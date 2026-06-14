const MODULE_CLASSES = {
    'Hypervisors': ['pxmx', 'kvm', 'vmware', 'utm'],
    'Firewalls': ['opnsense', 'pfsense', 'juniper', 'fortigate'],
    'IPAM': ['netbox', 'phpipam'],
    'Security/NAC': ['cppm', 'ise'],
    'Simulation': ['cs']
};

const PROVISIONABLE_MODULES = {
    'ldap': { name: 'LDAP Server', repo: 'https://github.com/lbockenstedt/ldap' },
    'netbox': { name: 'NetBox IPAM', repo: 'https://github.com/lbockenstedt/netbox' },
    'unbound': { name: 'Unbound DNS', repo: 'https://github.com/lbockenstedt/unbound' },
    'kea': { name: 'Kea DHCP', repo: 'https://github.com/lbockenstedt/kea' },
    'zabbix': { name: 'Zabbix Monitoring', repo: 'https://github.com/lbockenstedt/zabbix' },
    'graylog': { name: 'Graylog Log Management', repo: 'https://github.com/lbockenstedt/graylog' },
    'iperf': { name: 'iPerf Speed Test', repo: 'https://github.com/lbockenstedt/iperf' },
    'bugfix': { name: 'Bugfix Agent', repo: 'https://github.com/lbockenstedt/bugfix' },
    'pihole': { name: 'Pi-hole DNS Filter', repo: 'https://github.com/lbockenstedt/pihole' },
    'consolepi': { name: 'ConsolePi', repo: 'https://github.com/lbockenstedt/consolepi' },
};

const PRODUCT_MAP = {
    'pxmx': 'pxmx',
    'opn': 'opnsense',
    'opnsense': 'opnsense',
    'cs': 'cs',
    'cppm': 'cppm'
};

const LOG_NAMES = {
    'hub': 'Lab Manager Logs',
    'opn': 'Firewall Logs',
    'pxmx': 'Hypervisor Logs',
    'cppm': 'Security/NAC Logs',
    'cs': 'Client Simulator Logs'
};

const VIEWS = {
    dashboard: {
        name: 'Dashboard',
        subMenus: ['Overview', 'Notifications'],
        icon: '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6a8 8 0 018 8 8 8 0 018-8m-12 8a8 8 0 01-8-8 8 8 0 018-8m0 16v2m0-6V4m-2 8h4m-2 4h4m-4-8a4 4 0 01-4-4V4a4 4 0 014 0v4a4 4 0 014 0v4a4 4 0 01-4 0z"></path></svg>',
        render: () => `
            <div class="space-y-6">
                <h2 class="text-2xl font-bold mb-6 text-[#263040]">Welcome to Lab Manager</h2>
                <div class="hpe-card rounded-lg p-12 text-center">
                    <p class="text-slate-500">Select a module from the sidebar to begin management.</p>
                </div>
            </div>
        `
    },
    pxmx: {
        name: 'Proxmox',
        className: 'Virtual Machines',
        subMenus: ['VM Management', 'Cluster Status', 'Storage', 'config'],
        icon: '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path></svg>',
        render: (subMenu) => {
            if (subMenu === 'config') {
                return `
                    <div class="space-y-6">
                        <h2 class="text-2xl font-bold mb-6 text-[#263040]">Proxmox Configuration</h2>
                        <div class="hpe-card rounded-lg p-6 space-y-6">
                            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                                <div class="space-y-2">
                                    <label class="text-xs text-slate-500 uppercase font-bold">Default Node</label>
                                    <input type="text" id="pxmx-default-node" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm text-slate-800 outline-none focus:ring-2 focus:ring-green-500">
                                </div>
                                <div class="space-y-2">
                                    <label class="text-xs text-slate-500 uppercase font-bold">Cluster ID</label>
                                    <input type="text" id="pxmx-cluster-id" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm text-slate-800 outline-none focus:ring-2 focus:ring-green-500">
                                </div>
                            </div>
                            <div class="pt-6 border-t border-slate-200 flex justify-end">
                                <button onclick="saveProxmoxConfig()" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm">
                                    Save Configuration
                                </button>
                            </div>
                        </div>
                    </div>
                `;
            }
            return `
                <div class="space-y-6">
                    <h2 class="text-2xl font-bold mb-6 text-[#263040]">Proxmox Cluster Management</h2>
                    <div class="hpe-card rounded-lg p-6 shadow-sm">
                        <div class="flex gap-4 mb-8">
                            <input id="vm-id-input" type="text" placeholder="Enter VM ID (e.g. vm-101)"
                                   class="flex-1 bg-white border border-slate-300 rounded-md px-4 py-2 text-sm focus:ring-2 focus:ring-green-500 outline-none transition-all text-slate-800 placeholder-slate-400">
                            <button onclick="lookupVMDetails()"
                                    class="bg-[#01A982] hover:bg-[#008c6a] text-white px-6 py-2 rounded-md text-sm font-medium transition-all">
                                Stitched View
                            </button>
                        </div>

                        <div id="vm-details" class="hidden space-y-6">
                            <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                                <div class="p-4 rounded-md bg-slate-50 border border-slate-200">
                                    <label class="text-xs text-slate-500 uppercase font-bold">Identity</label>
                                    <div class="flex justify-between items-center mt-1">
                                        <div id="res-vm-id" class="text-lg font-medium text-slate-800">-</div>
                                        <div id="res-ip" class="text-sm font-mono text-blue-600">-</div>
                                    </div>
                                </div>
                                <div class="p-4 rounded-md bg-slate-50 border border-slate-200">
                                    <label class="text-xs text-slate-500 uppercase font-bold">Resources (Proxmox)</label>
                                    <div id="res-resources" class="text-sm text-slate-600 mt-1">CPU: - | RAM: - | Disk: -</div>
                                </div>
                                <div class="p-4 rounded-md bg-slate-50 border border-slate-200">
                                    <label class="text-xs text-slate-500 uppercase font-bold">Security (CPPM)</label>
                                    <div id="res-security" class="text-sm text-slate-600 mt-1">Policy: - | Posture: -</div>
                                </div>
                            </div>

                            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                                <div>
                                    <h3 class="text-sm font-semibold text-slate-500 mb-3 uppercase tracking-wider">Firewall Rules</h3>
                                    <div class="overflow-hidden rounded-md border border-slate-200 bg-white">
                                        <table class="w-full text-left text-sm">
                                            <thead class="bg-slate-100 text-slate-600 uppercase text-xs">
                                                <tr id="firewall-headers">
                                                    <th class="px-4 py-3">Source</th>
                                                    <th class="px-4 py-3">Destination</th>
                                                    <th class="px-4 py-3">Protocol</th>
                                                    <th class="px-4 py-3">Action</th>
                                                    <th class="px-4 py-3">Description</th>
                                                </tr>
                                            </thead>
                                            <tbody id="firewall-table-body" class="divide-y divide-slate-200">
                                                <!-- Rows injected here -->
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                                <div>
                                    <h3 class="text-sm font-semibold text-slate-500 mb-3 uppercase tracking-wider">DHCP Lease</h3>
                                    <div id="res-dhcp" class="p-4 rounded-md bg-slate-50 border border-slate-200 text-sm text-slate-600 space-y-2">
                                        <div><span class="font-bold">Hostname:</span> <span id="dhcp-host">-</span></div>
                                        <div><span class="font-bold">MAC:</span> <span id="dhcp-mac">-</span></div>
                                        <div><span class="font-bold">Expires:</span> <span id="dhcp-end">-</span></div>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div id="vm-inventory" class="space-y-4">
                            <h3 class="text-sm font-semibold text-slate-500 uppercase tracking-wider">Cluster Inventory</h3>
                            <div id="vm-list" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                                <div class="animate-pulse flex space-x-4 p-3 bg-slate-50 rounded-md">
                                    <div class="flex-1 space-y-3 py-1">
                                        <div class="h-2 bg-slate-200 rounded w-1/4"></div>
                                        <div class="h-2 bg-slate-200 rounded w-1/2"></div>
                                    </div>
                                </div>
                            </div>

                        <div id="vm-empty-state" class="hidden py-12 text-center text-slate-400">
                            <svg class="w-12 h-12 mx-auto mb-3 opacity-20" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
                            <p>No VMs found in the cluster.</p>
                        </div>
                    </div>
                </div>
            `;
        }
    },
    opnsense: {
        name: 'Firewall',
        className: 'Firewall',
        subMenus: ['Firewall Rules', 'Interfaces', 'DHCP Leases', 'NAT Policies', 'DNS Records', 'config'],
        icon: '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>',
        render: async (subMenu) => {
            if (subMenu === 'config') {
                const firewalls = await loadFirewalls();
                return `
                    <div class="space-y-6">
                        <div class="flex justify-between items-center mb-6">
                            <h2 class="text-2xl font-bold text-[#263040]">Firewall Configuration</h2>
                            <button onclick="showAddFirewallModal()" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-4 py-2 rounded-md text-sm font-bold transition-all shadow-sm flex items-center gap-2">
                                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"></path></svg>
                                Add Firewall
                            </button>
                        </div>
                        <div class="grid grid-cols-1 gap-4">
                            ${firewalls.map(fw => `
                                <div class="hpe-card rounded-lg p-4 border border-slate-200 bg-white flex justify-between items-center hover:border-green-500 transition-all group">
                                    <div class="flex items-center gap-4">
                                        <div class="w-10 h-10 rounded-full bg-slate-100 flex items-center justify-center text-slate-500">
                                            <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m0 0l-4 4m4-4V4a2 2 0 00-2-2H4a2 2 0 00-2 2v16a2 2 0 002 2h14a2 2 0 002-2v-4"></path></svg>
                                        </div>
                                        <div>
                                            <div class="font-bold text-slate-800">${fw.name}</div>
                                            <div class="text-xs text-slate-500 font-mono">${fw.model} | ${fw.host}:${fw.port}</div>
                                        </div>
                                    </div>
                                    <div class="flex items-center gap-2">
                                        <button onclick="editFirewall('${fw.id}')" class="p-2 text-slate-400 hover:text-green-600 transition-colors">
                                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9"></path></svg>
                                        </button>
                                        <button onclick="deleteFirewall('${fw.id}')" class="p-2 text-slate-400 hover:text-red-600 transition-colors">
                                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>
                                        </button>
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                `;
            }

            const firewalls = await loadFirewalls();
            if (firewalls.length === 0) {
                return `<div class="py-12 text-center text-slate-400 italic">No firewalls configured. Please add one in the configuration tab.</div>`;
            }

            // Set active firewall if none selected
            if (!activeFirewallId) {
                activeFirewallId = firewalls[0].id;
            }

            const activeFw = firewalls.find(f => f.id === activeFirewallId) || firewalls[0];

            return `
                <div class="space-y-6">
                    <div class="flex justify-between items-center mb-6">
                        <div class="flex items-center gap-4">
                            <h2 class="text-2xl font-bold text-[#263040]">Firewall Management: ${subMenu}</h2>
                            <div class="relative inline-block">
                                <select onchange="setActiveFirewall(this.value)" class="bg-white border border-slate-300 rounded-md px-3 py-1 text-xs font-medium text-slate-700 outline-none focus:ring-2 focus:ring-green-500 cursor-pointer">
                                    ${firewalls.map(fw => `<option value="${fw.id}" ${fw.id === activeFirewallId ? 'selected' : ''}>${fw.name}</option>`).join('')}
                                </select>
                                <div class="absolute right-2 top-1.5 pointer-events-none">
                                    <svg class="w-4 h-4 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path></svg>
                                </div>
                            </div>
                        </div>
                        <button onclick="refreshOpnsenseCache()" class="bg-white border border-slate-300 hover:bg-slate-50 text-slate-600 px-4 py-2 rounded-md text-sm font-medium transition-all flex items-center gap-2 shadow-sm">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 00-15.357-2m15.357 2H15"></path></svg>
                            Refresh Cache
                        </button>
                    </div>
                    <div class="hpe-card rounded-lg p-6 shadow-sm">
                        <div id="opn-table-container" class="space-y-4">
                            <div class="py-12 text-center text-slate-400 italic">Loading firewall data...</div>
                        </div>
                    </div>
                </div>
            `;
        }
    },
    cs: {
        name: 'Client Sim',
        className: 'Simulation Control',
        subMenus: ['Simulation Clients', 'VM Server', 'Simulation Control', 'Telemetry', 'Configuration'],
        icon: '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 6h7v8l7-7z"></path></svg>',
        render: (subMenu) => {
            if (subMenu === 'Configuration') {
                return `
                    <div class="space-y-6">
                        <h2 class="text-2xl font-bold mb-6 text-[#263040]">Simulation Configuration</h2>
                        <div class="hpe-card rounded-lg p-6 space-y-6 shadow-sm">
                            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                                <div class="space-y-2">
                                    <label class="text-xs text-slate-500 uppercase font-bold">Aruba Central Host</label>
                                    <input type="text" id="cs-aruba-host" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                                </div>
                                <div class="space-y-2">
                                    <label class="text-xs text-slate-500 uppercase font-bold">API Key</label>
                                    <input type="password" id="cs-aruba-key" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                                </div>
                            </div>
                            <div class="pt-6 border-t border-slate-200 flex justify-end">
                                <button onclick="saveCSConfig()" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm">
                                    Save Configuration
                                </button>
                            </div>
                        </div>
                    </div>
                `;
            }
            if (subMenu === 'VM Server') {
                return `
                    <div class="space-y-6">
                        <div class="flex justify-between items-center mb-6">
                            <h2 class="text-2xl font-bold text-[#263040]">VM Server Status</h2>
                            <button onclick="refreshVMServerStatus()" class="bg-white border border-slate-300 hover:bg-slate-50 text-slate-600 px-4 py-2 rounded-md text-sm font-medium transition-all flex items-center gap-2 shadow-sm">
                                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 00-15.357-2m15.357 2H15"></path></svg>
                                Refresh Status
                            </button>
                        </div>
                        <div id="vm-server-status-container" class="grid grid-cols-1 md:grid-cols-3 gap-6">
                            <div class="py-12 text-center text-slate-400 italic col-span-3">Loading server status...</div>
                        </div>
                    </div>
                `;
            }
            if (subMenu === 'Simulation Control') {
                return `
                    <div class="space-y-6">
                        <div class="flex justify-between items-center mb-6">
                            <h2 class="text-2xl font-bold text-[#263040]">Simulation Control</h2>
                            <div class="flex gap-3">
                                <button onclick="startSimulation()" class="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-md text-sm font-bold transition-all shadow-sm flex items-center gap-2">
                                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.007l-4.5 4.5a1 1 0 01-1.414 0l-4.5-4.5a1 1 0 011.414-1.414l3.5 3.5v-7.5a1 1 0 012 0v7.5l3.5-3.5a1 1 0 011.414 1.414z"></path></svg>
                                    Start Simulation
                                </button>
                                <button onclick="stopSimulation()" class="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-md text-sm font-bold transition-all shadow-sm flex items-center gap-2">
                                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 9v6m4-6v6m-8 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2z"></path></svg>
                                    Stop Simulation
                                </button>
                            </div>
                        </div>
                        <div class="hpe-card rounded-lg p-6 shadow-sm">
                            <div id="sim-status-container" class="flex flex-col items-center justify-center py-12 text-slate-400 italic">
                                <p>No active simulation. Start a profile to see system state.</p>
                            </div>
                        </div>
                    </div>
                `;
            }
            if (subMenu === 'Simulation Clients') {
                return `
                    <div class="space-y-6">
                        <div class="flex justify-between items-center mb-6">
                            <h2 class="text-2xl font-bold text-[#263040]">Simulation Clients</h2>
                            <button onclick="refreshSimClients()" class="bg-white border border-slate-300 hover:bg-slate-50 text-slate-600 px-4 py-2 rounded-md text-sm font-medium transition-all flex items-center gap-2 shadow-sm">
                                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 00-15.357-2m15.357 2H15"></path></svg>
                                Refresh Clients
                            </button>
                        </div>
                        <div class="hpe-card rounded-lg overflow-hidden shadow-sm border border-slate-200">
                            <table class="w-full text-left text-sm">
                                <thead class="bg-slate-100 text-slate-600 uppercase text-xs">
                                    <tr>
                                        <th class="px-4 py-3 font-bold">Client ID</th>
                                        <th class="px-4 py-3 font-bold">IP Address</th>
                                        <th class="px-4 py-3 font-bold">Status</th>
                                        <th class="px-4 py-3 font-bold text-right">Actions</th>
                                    </tr>
                                </thead>
                                <tbody id="sim-clients-body" class="divide-y divide-slate-200">
                                    <tr><td colspan="4" class="px-4 py-8 text-center text-slate-400 italic">Loading simulation clients...</td></tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                `;
            }
            return `
                <div class="space-y-6">
                    <h2 class="text-2xl font-bold mb-6 text-[#263040]">Simulation Telemetry</h2>
                    <div class="hpe-card rounded-lg p-6 shadow-sm">
                        <div id="sim-telemetry-container" class="space-y-4">
                            <p class="text-center text-slate-400 italic">Start simulation to view correlated telemetry.</p>
                        </div>
                    </div>
                </div>
            `;
        }
    },
    cppm: {
        name: 'Security/NAC',
        className: 'Security/NAC',
        subMenus: ['Access Tracker', 'Devices', 'Roles', 'Configuration'],
        icon: '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg>',
        render: (subMenu) => {
            if (subMenu === 'Configuration') {
                return `
                    <div class="space-y-6">
                        <div class="flex justify-between items-center mb-6">
                            <h2 class="text-2xl font-bold text-[#263040]">CPPM Configuration</h2>
                        </div>
                        <div class="hpe-card rounded-lg p-6 space-y-6 shadow-sm">
                            <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                                <div class="space-y-2">
                                    <label class="text-xs text-slate-500 uppercase font-bold">CPPM Host</label>
                                    <input type="text" id="cppm-host" placeholder="cppm.example.local" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                                </div>
                                <div class="space-y-2">
                                    <label class="text-xs text-slate-500 uppercase font-bold">Username</label>
                                    <input type="text" id="cppm-user" placeholder="admin" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                                </div>
                                <div class="space-y-2">
                                    <label class="text-xs text-slate-500 uppercase font-bold">Password</label>
                                    <input type="password" id="cppm-pass" placeholder="••••••••" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                                </div>
                            </div>
                            <div class="pt-6 border-t border-slate-200 flex justify-end">
                                <button onclick="saveCPPMConfig()" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm">
                                    Save Configuration
                                </button>
                            </div>
                        </div>
                    </div>
                `;
            }
            return `
                <div class="space-y-6">
                    <div class="flex justify-between items-center mb-6">
                        <h2 class="text-2xl font-bold text-[#263040]">Security/NAC: ${subMenu}</h2>
                        <button onclick="setSubView('Configuration')" class="p-2 rounded-md hover:bg-slate-100 text-slate-400 hover:text-slate-600 transition-all" title="Configuration">
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.754 2.924-1.754 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.754.426 1.754 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.754-2.924 1.754-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.754-.426-1.754-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.999.53 2.122.5C10.05 5.047 10.325 4.317 10.325 4.317z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path></svg>
                        </button>
                    </div>
                    <div class="hpe-card rounded-lg p-12 text-center">
                        <div class="flex flex-col items-center gap-4">
                            <div class="w-16 h-16 bg-slate-100 rounded-full flex items-center justify-center text-slate-400">
                                <svg class="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg>
                            </div>
                            <p class="text-slate-500">The ${subMenu} view is currently under development.</p>
                            <div class="text-xs text-slate-400 italic">Implementation of CPPM API integration pending.</div>
                        </div>
                    </div>
                </div>
            `;
        }
    },
    ldap: {
        name: 'LDAP',
        className: 'Directory Services',
        subMenus: ['OUs', 'Users', 'Groups'],
        icon: '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v12a2 2 0 002 2z"></path></svg>',
        render: async (subMenu) => {
            return `
                <div class="space-y-6">
                    <div class="flex justify-between items-center mb-6">
                        <h2 class="text-2xl font-bold text-[#263040]">LDAP Management: ${subMenu}</h2>
                        <button onclick="showLDAPModal('${subMenu}')" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-4 py-2 rounded-md text-sm font-bold transition-all shadow-sm flex items-center gap-2">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"></path></svg>
                            Add ${subMenu === 'OUs' ? 'OU' : (subMenu === 'Users' ? 'User' : 'Group')}
                        </button>
                    </div>
                    <div class="hpe-card rounded-lg overflow-hidden shadow-sm border border-slate-200">
                        <div class="overflow-x-auto">
                            <table class="w-full text-left text-sm">
                                <thead id="ldap-table-head" class="bg-slate-100 text-slate-600 uppercase text-xs">
                                    <!-- Headers injected here -->
                                </thead>
                                <tbody id="ldap-table-body" class="divide-y divide-slate-200">
                                    <tr><td colspan="100%" class="px-4 py-8 text-center text-slate-400 italic">Loading ${subMenu} data...</td></tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            `;
        }
    },
    setup: {
        name: 'Setup',
        subMenus: ['General', 'Tenant Config', 'User Access', 'Spoke Approvals', 'LDAP Config', 'Generic Nodes'],
        icon: '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110-4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m-2 8h4m-2 4h4m-4-8a4 4 0 01-4-4V4a4 4 0 014 0v4a4 4 0 014 0v4a4 4 0 01-4 0z"></path></svg>',

        render: (subMenu) => {
            if (subMenu === 'LDAP Config') {
                return `
                    <div class="space-y-6">
                        <h2 class="text-2xl font-bold mb-6 text-[#263040]">LDAP Server Configuration</h2>
                        <div class="hpe-card rounded-lg p-6 space-y-6 shadow-sm">
                            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                                <div class="space-y-2">
                                    <label class="text-xs text-slate-500 uppercase font-bold flex items-center gap-1">LDAP Server URL <span onclick="showHelp('ldap-config')" class="cursor-pointer inline-block text-slate-400 hover:text-green-500 transition-colors" title="Help">ⓘ</span></label>
                                    <input type="text" id="ldap-server-url" placeholder="ldap://localhost:389" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm text-slate-800 outline-none focus:ring-2 focus:ring-green-500">
                                </div>
                                <div class="space-y-2">
                                    <label class la-text-xs text-slate-500 uppercase font-bold flex items-center gap-1">Base DN <span onclick="showHelp('ldap-config')" class="cursor-pointer inline-block text-slate-400 hover:text-green-500 transition-colors" title="Help">ⓘ</span></label>
                                    <input type="text" id="ldap-base-dn" placeholder="dc=example,dc=org" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm text-slate-800 outline-none focus:ring-2 focus:ring-green-500">
                                </div>
                                <div class="space-y-2">
                                    <label class="text-xs text-slate-500 uppercase font-bold flex items-center gap-1">Admin DN <span onclick="showHelp('ldap-config')" class="cursor-pointer inline-block text-slate-400 hover:text-green-500 transition-colors" title="Help">ⓘ</span></label>
                                    <input type="text" id="ldap-admin-dn" placeholder="cn=admin,dc=example,dc=org" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm text-slate-800 outline-none focus:ring-2 focus:ring-green-500">
                                </div>
                                <div class="space-y-2">
                                    <label class="text-xs text-slate-500 uppercase font-bold flex items-center gap-1">Admin Password <span onclick="showHelp('ldap-config')" class="cursor-pointer inline-block text-slate-400 hover:text-green-500 transition-colors" title="Help">ⓘ</span></label>
                                    <input type="password" id="ldap-admin-pw" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm text-slate-800 outline-none focus:ring-2 focus:ring-green-500">
                                </div>
                            </div>
                            <div class="pt-6 border-t border-slate-200 flex justify-end">
                                <button onclick="saveLDAPConfig()" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm">
                                    Save LDAP Configuration
                                </button>
                            </div>
                        </div>
                    </div>
                `;
            }
            if (subMenu === 'Generic Nodes') {
                return `
                    <div class="space-y-6">
                        <div class="flex justify-between items-center mb-6">
                            <h2 class="text-2xl font-bold text-[#263040]">Generic Agent Nodes</h2>
                            <button onclick="showProvisionModal()" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-4 py-2 rounded-md text-sm font-bold transition-all shadow-sm flex items-center gap-2">
                                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"></path></svg>
                                Provision Module
                            </button>
                        </div>
                        <div class="hpe-card rounded-lg overflow-hidden shadow-sm border border-slate-200">
                            <div class="overflow-x-auto">
                                <table class="w-full text-left text-sm">
                                    <thead class="bg-slate-100 text-slate-600 uppercase text-xs">
                                        <tr>
                                            <th class="px-4 py-3 font-bold">Agent ID</th>
                                            <th class="px-4 py-3 font-bold">Status</th>
                                            <th class="px-4 py-3 font-bold">Connected</th>
                                            <th class="px-4 py-3 font-bold text-right">Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody id="generic-agents-body" class="divide-y divide-slate-200">
                                        <tr><td colspan="4" class="px-4 py-8 text-center text-slate-400 italic">Loading generic agents...</td></tr>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                `;
            }
            if (subMenu === 'User Access') {
                return `
                    <div class="space-y-6">
                        <div class="flex justify-between items-center mb-6">
                            <h2 class="text-2xl font-bold text-[#263040]">User Access Control</h2>
                            <button onclick="showAddUserModal()" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-4 py-2 rounded-md text-sm font-bold transition-all shadow-sm flex items-center gap-2">
                                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"></path></svg>
                                Add User
                            </button>
                        </div>
                        <div class="hpe-card rounded-lg overflow-hidden shadow-sm border border-slate-200">
                            <div class="overflow-x-auto">
                                <table class="w-full text-left text-sm">
                                    <thead class="bg-slate-100 text-slate-600 uppercase text-xs">
                                        <tr>
                                            <th class="px-4 py-3 font-bold">User ID</th>
                                            <th class="px-4 py-3 font-bold">System Admin</th>
                                            <th class="px-4 py-3 font-bold">Manage Proxmox</th>
                                            <th class="px-4 py-3 font-bold">View Proxmox</th>
                                            <th class="px-4 py-3 font-bold">Edit Firewall</th>
                                            <th class="px-4 py-3 font-bold">Manage DNS</th>
                                            <th class="px-4 py-3 font-bold">Manage CPPM</th>
                                            <th class="px-4 py-3 font-bold">View CPPM</th>
                                            <th class="px-4 py-3 font-bold text-right">Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody id="user-permissions-body" class="divide-y divide-slate-200">
                                        <!-- User rows injected here -->
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                `;
            }
            if (subMenu === 'Spoke Approvals') {
                return `
                    <div class="space-y-6">
                        <h2 class="text-2xl font-bold mb-6 text-[#263040]">Spoke Approvals</h2>
                        <div class="hpe-card rounded-lg p-6 shadow-sm">
                            <div id="pending-spokes-list" class="space-y-3">
                                <div class="py-12 text-center text-slate-400 italic">Loading pending spokes...</div>
                            </div>
                        </div>
                    </div>
                `;
            }
            if (subMenu === 'Tenant Config') {
                return `
                    <div class="space-y-6">
                        <h2 class="text-2xl font-bold mb-6 text-[#263040]">Tenant Configuration</h2>
                        <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
                            <div class="lg:col-span-1 space-y-4">
                                <div class="hpe-card rounded-lg p-4 shadow-sm">
                                    <h3 class="text-sm font-semibold text-slate-500 uppercase tracking-wider mb-4">Tenants</h3>
                                    <div id="tenant-list" class="space-y-2">
                                        <div class="py-4 text-center text-slate-400 italic text-xs">Loading tenants...</div>
                                    </div>
                                    <div class="pt-4 mt-4 border-t border-slate-200 flex gap-2">
                                        <input type="text" id="new-tenant-id" placeholder="Tenant ID" class="flex-1 bg-white border border-slate-300 rounded-md px-3 py-1.5 text-xs outline-none focus:ring-1 focus:ring-green-500">
                                        <button onclick="addTenant()" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-3 py-1.5 rounded text-xs font-bold transition-all">Add</button>
                                    </div>
                                </div>
                            </div>
                            <div class="lg:col-span-2">
                                <div id="tenant-editor" class="hpe-card rounded-lg p-6 shadow-sm hidden space-y-6">
                                    <div class="flex justify-between items-center mb-6">
                                        <h3 class="text-lg font-semibold text-[#263040]">Edit Tenant: <span id="edit-tenant-id" class="font-mono text-green-600"></span></h3>
                                        <button onclick="closeTenantEditor()" class="text-slate-400 hover:text-slate-600 text-xs">Close</button>
                                    </div>
                                    <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                                        <div class="space-y-2">
                                            <label class="text-xs text-slate-500 uppercase font-bold">Display Name</label>
                                            <input type="text" id="tenant-name" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm text-slate-800 outline-none focus:ring-2 focus:ring-green-500">
                                        </div>
                                        <div class="space-y-2">
                                            <label class="text-xs text-slate-500 uppercase font-bold">Active Tenant</label>
                                            <div class="flex items-center gap-3 py-2">
                                                <input type="checkbox" id="tenant-active" onchange="setTenant(document.getElementById('edit-tenant-id').textContent)" class="w-4 h-4 text-green-600 border-slate-300 rounded focus:ring-green-500">
                                                <span class="text-sm text-slate-600">Set as active hub tenant</span>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="pt-6 border-t border-slate-200">
                                        <h4 class="text-xs font-bold text-slate-500 uppercase tracking-wider mb-4">Quotas (Maximum Resources)</h4>
                                        <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                                            <div class="space-y-2">
                                                <label class="text-slate-400 flex items-center gap-1">VMs <span onclick="showHelp('tenant-quotas')" class="cursor-pointer inline-block text-slate-400 hover:text-green-500 transition-colors" title="Help">ⓘ</span></label>
                                                <input type="number" id="quota-vm" class="w-full bg-white border border-slate-300 rounded-md px-3 py-1 text-sm outline-none focus:ring-1 focus:ring-green-500">
                                            </div>
                                            <div class="space-y-2">
                                                <label class="text-xs text-slate-500 uppercase font-bold flex items-center gap-1">CPPM Policies <span onclick="showHelp('tenant-quotas')" class="cursor-pointer inline-block text-slate-400 hover:text-green-500 transition-colors" title="Help">ⓘ</span></label>
                                                <input type="number" id="quota-cppm" class="w-full bg-white border border-slate-300 rounded-md px-3 py-1 text-sm outline-none focus:ring-1 focus:ring-green-500">
                                            </div>
                                            <div class="space-y-2">
                                                <label class="text-xs text-slate-500 uppercase font-bold flex items-center gap-1">Firewall Rules <span onclick="showHelp('tenant-quotas')" class="cursor-pointer inline-block text-slate-400 hover:text-green-500 transition-colors" title="Help">ⓘ</span></label>
                                                <input type="number" id="quota-opn" class="w-full bg-white border border-slate-300 rounded-md px-3 py-1 text-sm outline-none focus:ring-1 focus:ring-green-500">
                                            </div>
                                        </div>
                                    </div>
                                    <div class="pt-6 border-t border-slate-200 flex justify-end">
                                        <button onclick="saveTenantConfig()" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm">
                                            Save Tenant Settings
                                        </button>
                                    </div>
                                </div>
                                <div id="tenant-empty-state" class="hpe-card rounded-lg p-12 text-center text-slate-400 italic shadow-sm">
                                    Select a tenant from the list to configure its settings.
                                </div>
                            </div>
                        </div>
                    </div>
                `;
            }
            return `
                <div class="space-y-6">
                    <h2 class="text-2xl font-bold mb-6 text-[#263040]">System Setup</h2>
                    <div class="hpe-card rounded-lg p-6 space-y-6">
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                            <div class="space-y-2">
                                <label class="text-xs text-slate-500 uppercase font-bold">Active Tenant</label>
                                <select id="tenant-selector" onchange="setTenant(this.value)" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm text-slate-800 outline-none focus:ring-2 focus:ring-green-500">
                                    <!-- Options injected dynamically -->
                                </select>
                            </div>
                            <div class="space-y-2">
                                <label class="text-xs text-slate-500 uppercase font-bold">Authentication Mode</label>
                                <select id="auth-mode" onchange="updateGlobalConfig('auth_mode', this.value)" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm text-slate-800 outline-none focus:ring-2 focus:ring-green-500">
                                    <option value="local">Local Login</option>
                                    <option value="ldap">LDAP Integration</option>
                                </select>
                            </div>
                        </div>
                        <div class="pt-6 border-t border-slate-200">
                            <h3 class="text-sm font-semibold text-slate-500 uppercase tracking-wider mb-4">Maintenance</h3>
                            <div class="flex flex-col gap-4 p-4 rounded-md bg-slate-50 border border-slate-200">
                                <div class="flex items-center justify-between">
                                    <div class="flex flex-col gap-2">
                                        <div class="text-sm text-slate-600 font-medium">Automated System Updates</div>
                                        <div class="flex items-center gap-4">
                                            <label class="flex items-center gap-2 cursor-pointer group">
                                                <input type="checkbox" id="auto-update-chk" onchange="updateAutoUpdate(this.checked)" class="w-4 h-4 text-green-600 border-slate-300 rounded focus:ring-green-500">
                                                <span class="text-xs font-medium text-slate-500 group-hover:text-slate-700 transition-colors">Enable Auto-Update</span>
                                            </label>
                                            <span class="text-slate-300">|</span>
                                            <div class="flex items-center gap-2">
                                                <span class="text-xs text-slate-500">Interval:</span>
                                                <input type="number" id="auto-update-int" onchange="updateAutoUpdateInterval(this.value)"
                                                       class="w-12 bg-white border border-slate-300 rounded px-2 py-0.5 text-xs text-slate-800 outline-none focus:ring-1 focus:ring-green-500">
                                                <span class="text-xs text-slate-500">hours</span>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="text-right">
                                        <span id="last-update-ts" class="text-slate-400">Last check: Never</span>
                                    </div>
                                </div>
                                <div class="pt-3 border-t border-slate-200 flex justify-between items-center">
                                    <div class="text-xs text-slate-400 italic">Manually synchronize from GitHub repository.</div>
                                    <button onclick="triggerUpdate()" id="update-btn" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-4 py-2 rounded-md text-xs font-bold transition-all shadow-sm">
                                        Update System Now
                                    </button>
                                </div>
                            </div>
                            <div class="pt-6 border-t border-slate-200">
                                <div class="flex justify-between items-center mb-4">
                                    <h3 class="text-sm font-semibold text-slate-500 uppercase tracking-wider">Advanced Settings</h3>
                                    <button onclick="toggleAdvancedSettings()" class="text l-slate-300 rounded-md px-3 py-1.5 text-xs outline-none focus:ring-1 focus:ring-green-500">
                                        Toggle Repository Sources
                                    </button>
                                </div>
                                <div id="setup-advanced-section" class="hidden space-y-6">
                                    <div class="flex justify-between items-center mb-4">
                                        <h3 class="textL-slate-300 rounded-md px-3 py-1.5 text-xs outline-none focus:ring-1 focus:ring-green-500">Repository Sources</h3>
                                        <div class="flex gap-2">
                                            <button onclick="scanGitHubRepos()" class="text l-slate-300 rounded-md px-3 py-1.5 text-xs outline-none focus:ring-1 focus:ring-green-500">
                                                <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path></svg>
                                                Scan GitHub
                                            </button>
                                            <div class="flex items-center gap-2 bg-slate-100 px-2 py-1 rounded border border-slate-200">
                                                <label class="text-xs text-slate-500 uppercase font-bold"">Global Branch</label>
                                                <select id="global-branch" class="bg-white border border-slate-300 rounded px-1 py-0.5 text-xs outline-none focus:ring-1 focus:ring-green-500">
                                                    <option value="main">main</option>
                                                    <option value="develop">develop</option>
                                                    <option value="master">master</option>
                                                </select>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                                        <div class="space-y-2">
                                            <labelL-slate-300 rounded-md px-3 py-1.5 text-xs outline-none focus:ring-1 focus:ring-green-500">Hub Repository</label>
                                            <input type="text" id="update-source-hub" class="w-full bg-white border border-slate-300 rounded-md px-3 py-1.5 text-xs outline-none focus:ring-1 focus:ring-green-500">
                                        </div>
                                        <div class="space-y-2">
                                            <label class="text-xs text-slate-500 uppercase font-bold">Proxmox Agent</label>
                                            <input type="text" id="update-source-pxmx" class="w-full bg-white border border-slate-300 rounded-md px-3 py-1.5 text-xs outline-none focus:ring-1 focus:ring-green-500">
                                        </div>
                                        <div class="space-y-2">
                                            <label class="text-xs text-slate-500 uppercase font-bold">OPNsense Spoke</label>
                                            <input type="text" id="update-source-opn" class="w-full bg-white border border-slate-300 rounded-md px-3 py-1.5 text-xs outline-none focus:ring-1 focus:ring-green-500">
                                        </div>
                                        <div class="space-y-2">
                                            <label class="text-xs text-slate-500 uppercase font-bold">Client Sim</label>
                                            <input type="text" id="update-source-cs" class="w-full bg-white border border-slate-300 rounded-md px-3 py-1.5 text-xs outline-none focus:ring-1 focus:ring-green-500">
                                        </div>
                                        <div class="space-y-2">
                                            <label class="text-xs text-slate-500 uppercase font-bold">CPPM Spoke</label>
                                            <input type="text" id="update-source-cppm" class="w-full bg-white border border-slate-300 rounded-md px-3 py-1.5 text-xs outline-none focus:ring-1 focus:ring-green-500">
                                        </div>
                                        <div class="space-y-2">
                                            <label class="text-xs text-slate-500 uppercase font-bold">Netbox Spoke</label>
                                            <input type="text" id="update-source-netbox" class="w-full bg-white border border-slate-300 rounded-md px-3 py-1.5 text-xs outline-none focus:ring-1 focus:ring-green-500">
                                        </div>
                                        <div class="space-y-2">
                                            <labelL-slate-300 rounded-md px-3 py-1.5 text-xs outline-none focus:ring-1 focus:ring-green-500">LDAP Spoke</label>
                                            <input type="text" id="update-source-ldap" class="w-full bg-white border border-slate-300 rounded-md px-3 py-1.5 text-xs outline-none focus:ring-1 focus:ring-green-500">
                                        </div>
                                    </div>
                                    <div class="pt-4 flex justify-end">
                                        <button onclick="saveUpdateSources()" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-4 py-2 rounded-md text-xs font-bold transition-all shadow-sm">
                                            Save Repository Sources
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                `;
        }

    },
    settings: {
        name: 'System',
        subMenus: ['General', 'Network', 'Auth', 'Logs', 'Diagnostics'],
        icon: '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-1.59 4.04-1.59 5.583 0a1.724 1.724 0 001.28 2.915c-1.344 1.35-3.77 1.35-5.114 0a1.724 1.724 0 00-1.28-2.915zM12 18a6 6 0 100-12 6 6 0 000 12z"></path></svg>',
        render: (subMenu) => {
            if (subMenu.startsWith('logs-')) {
                const module = subMenu.replace('logs-', '');
                const logTitle = LOG_NAMES[module] || `${module.toUpperCase()} Logs`;
                return `
                    <div class="space-y-6">
                        <h2 class="text-2xl font-bold mb-6 text-[#263040]">${logTitle}</h2>
                        <div class="hpe-card rounded-lg overflow-hidden shadow-sm border border-slate-200">
                            <div class="bg-slate-100 px-4 py-2 border-b border-slate-200 flex justify-between items-center">
                                <span class="text-xs font-bold text-slate-500 uppercase tracking-widest">${logTitle}</span>
                                <div class="flex gap-2">
                                    <button onclick="copyLogs()" class="text-[10px] bg-white border border-slate-300 px-2 py-1 rounded hover:bg-slate-50 transition-colors font-medium flex items-center gap-1">
                                        <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 012-2h2a2 2 0 012 2M8 5V3m4 2V3"></path></svg>
                                        Copy All
                                    </button>
                                    <button onclick="loadModuleLogs('${module}')" class="text-[10px] bg-white border border-slate-300 px-2 py-1 rounded hover:bg-slate-50 transition-colors font-medium">Refresh</button>
                                </div>
                            </div>
                            <div id="system-logs-container" class="h-[600px] overflow-y-auto bg-white font-mono">
                                <!-- Logs injected here -->
                            </div>
                        </div>
                    </div>
                `;
            }
            if (subMenu === 'Logs') {
                return `
                    <div class="space-y-6">
                        <h2 class="text-2xl font-bold mb-6 text-[#263040]">System Logs</h2>
                        <p class="text-sm text-slate-500 mb-4">Select a module from the list to view its specific output.</p>
                        <div class="grid grid-cols-1 gap-4">
                            ${['hub', 'pxmx', 'opn', 'cppm', 'cs'].map(mod => `
                                <div onclick="setSubView('logs-${mod}')" class="p-4 rounded-md bg-white border border-slate-200 hover:border-green-500 cursor-pointer transition-all flex justify-between items-center group">
                                    <span class="text-sm font-medium text-slate-700 group-hover:text-green-600">${LOG_NAMES[mod] || mod.toUpperCase() + ' Logs'}</span>
                                    <svg class="w-4 h-4 text-slate-400 group-hover:text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path></svg>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                `;
            }
            if (subMenu === 'Diagnostics') {
                return `
                    <div class="space-y-6">
                        <h2 class="text-2xl font-bold mb-6 text-[#263040]">Spoke Diagnostics</h2>
                        <div class="hpe-card rounded-lg p-6 shadow-sm">
                            <div id="diag-container" class="space-y-4">
                                <div class="py-12 text-center text-slate-400 italic">Loading diagnostics...</div>
                            </div>
                        </div>
                        <div class="pt-4 flex justify-end gap-3">
                            <button onclick="triggerUpdate(event)" id="diag-update-btn" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-4 py-2 rounded-md text-sm font-bold transition-all shadow-sm flex items-center gap-2">
                                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16V4m0 0a2 2 0 012-2h6a2 2 0 012 2m-6 0v12m0-12l-4 4m4-4l4 4"></path></svg>
                                Update from GitHub
                            </button>
                            <button onclick="refreshOpnsenseCache()" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-md text-sm font-bold transition-all shadow-sm">
                                Refresh OPNsense Cache
                            </button>
                            <button onclick="loadDiagnostics()" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-4 py-2 rounded-md text-sm font-bold transition-all shadow-sm">
                                Refresh Diagnostics
                            </button>
                        </div>

                        <div class="mt-8 space-y-4">
                            <h3 class="text-sm font-semibold text-slate-500 uppercase tracking-wider">API Explorer (Debug Tool)</h3>
                            <div class="hpe-card rounded-lg p-6 shadow-sm space-y-4">
                                <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                                    <div class="space-y-2">
                                        <label class="text-xs text-slate-500 uppercase font-bold">Target Spoke</label>
                                        <select id="probe-spoke-selector" onchange="updateQuickPaths()" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                                            <option value="">Select Spoke...</option>
                                        </select>
                                    </div>
                                    <div class="space-y-2 md:col-span-2">
                                        <label class="text-xs text-slate-500 uppercase font-bold">API Path</label>
                                        <div class="flex gap-2">
                                            <input type="text" id="probe-path" placeholder="/api/..." class="flex-1 bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500 font-mono">
                                            <button onclick="executeProbe()" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-6 py-2 rounded-md text-sm font-bold transition-all">Probe</button>
                                        </div>
                                    </div>
                                </div>
                                <div class="flex flex-wrap gap-2">
                                    <label class="text-[10px] text-slate-400 uppercase font-bold w-full">Quick Paths:</label>
                                    <div id="probe-quick-paths" class="flex flex-wrap gap-2"></div>
                                </div>
                                <div class="space-y-2">
                                    <label class="text-xs text-slate-500 uppercase font-bold">Response</label>
                                    <pre id="probe-response" class="w-full h-64 overflow-auto p-4 bg-slate-900 text-green-400 text-xs font-mono rounded-md border border-slate-800 whitespace-pre-wrap">No data probed yet...</pre>
                                </div>
                            </div>
                        </div>
                    </div>
                `;
            }
            return `
                <div class="space-y-6">
                    <h2 class="text-2xl font-bold mb-6 text-[#263040]">System Performance</h2>
                    <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                        <div class="hpe-card rounded-lg p-6 shadow-sm">
                            <label class="text-xs text-slate-500 uppercase font-bold">CPU Usage</label>
                            <div id="sys-cpu" class="text-4xl font-bold mt-2 text-slate-800">0%</div>
                        </div>
                        <div class="hpe-card rounded-lg p-6 shadow-sm">
                            <label class="text-xs text-slate-500 uppercase font-bold">Memory Usage</label>
                            <div id="sys-mem" class="text-4xl font-bold mt-2 text-slate-800">0%</div>
                        </div>
                        <div class="hpe-card rounded-lg p-6 shadow-sm">
                            <label class="text-xs text-slate-500 uppercase font-bold">Disk Usage</label>
                            <div id="sys-disk" class="text-4xl font-bold mt-2 text-slate-800">0%</div>
                        </div>
                    </div>
                    <div class="grid grid-cols-2 md:grid-cols-4 gap-6">
                        <div class="hpe-card rounded-lg p-4 shadow-sm">
                            <label class="text-[10px] text-slate-500 uppercase font-bold">Throughput</label>
                            <div id="sys-throughput" class="text-2xl font-bold mt-1 text-[#01A982]">0.0 MB/s</div>
                        </div>
                        <div class="hpe-card rounded-lg p-4 shadow-sm">
                            <label class="text-[10px] text-slate-500 uppercase font-bold">Packets/s</label>
                            <div id="sys-mps" class="text-2xl font-bold mt-1 text-[#01A982]">0.0 msg/s</div>
                        </div>
                        <div class="hpe-card rounded-lg p-4 shadow-sm">
                            <label class="text-[10px] text-slate-500 uppercase font-bold">Mailbox Queue</label>
                            <div id="sys-queue" class="text-2xl font-bold mt-1 text-slate-800">0</div>
                        </div>
                        <div class="hpe-card rounded-lg p-4 shadow-sm">
                            <label class="text-[10px] text-slate-500 uppercase font-bold">Backlog</label>
                            <div id="sys-backlog" class="text-2xl font-bold mt-1 text-slate-800">0</div>
                        </div>
                    </div>

                    <h2 class="text-2xl font-bold mb-6 text-[#263040] pt-6">System Configuration</h2>
                    <div class="hpe-card rounded-lg p-6 space-y-4">
                        <div class="flex justify-between p-4 rounded-md bg-slate-50 border border-slate-200">
                            <span class="text-slate-500">Hub Version</span>
                            <span class="text-blue-600 font-mono font-bold">0.08</span>
                        </div>
                        <div class="flex justify-between p-4 rounded-md bg-slate-50 border border-slate-200">
                            <span class="text-slate-500">API Status</span>
                            <span class="text-green-600 font-bold">Active</span>
                        </div>
                        <div class="flex justify-between p-4 rounded-md bg-slate-50 border border-slate-200">
                            <span class="text-slate-500">Deployment Mode</span>
                            <span class="text-slate-700">LXC Native</span>
                        </div>
                        <div class="flex justify-between p-4 rounded-md bg-slate-50 border border-slate-200">
                            <span class="text-slate-500">UI Theme</span>
                            <div class="flex items-center gap-2">
                                <span class="text-xs font-medium text-slate-400 uppercase">Theme:</span>
                                <select id="theme-selector" onchange="setTheme(this.value)"
                                       class="bg-white border border-slate-300 rounded px-2 py-0.5 text-xs text-slate-800 outline-none focus:ring-1 focus:ring-green-500 cursor-pointer">
                                    <option value="default">Default</option>
                                    <option value="cicada">Cicada</option>
                                    <option value="lcars">Star Trek (LCARS)</option>
                                    <option value="sw">Star Wars (Imperial)</option>
                                </select>
                            </div>
                        </div>
                    </div>
                    </div>
                </div>
            `;
        }
    }
};

let currentView = 'dashboard';
let activeFirewallId = null;
let showHiddenOnlyFirewallRules = false;

async function loadFirewalls() {
    try {
        const response = await fetch('/setup/firewalls');
        if (!response.ok) throw new Error('Failed to fetch firewalls');
        const data = await response.json();
        return data.firewalls || [];
    } catch (err) {
        console.error('Error loading firewalls:', err);
        return [];
    }
}
let currentTenant = 'default';
let currentProduct = null;
let logRefreshInterval = null;

async function setTenant(tenant) {
    currentTenant = tenant;
    localStorage.setItem('lm_tenant', tenant);

    try {
        const response = await fetch('/setup/tenant', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ tenant_id: tenant, config: { active: true } })
        });
        if (response.ok) {
            console.log(`Switched to tenant: ${tenant}`);
            // Refresh current view to load tenant-specific data
            setView(currentView);
        }
    } catch (err) {
        console.error('Failed to set tenant', err);
    }
}

async function loadTenants() {
    const selector = document.getElementById('tenant-selector');
    if (!selector) return;

    try {
        const response = await fetch('/setup/tenants');
        if (!response.ok) throw new Error('Failed to fetch tenants');
        const data = await response.json();
        const tenants = data.tenants || [];

        selector.innerHTML = tenants.map(t => `
            <option value="${t.id}" ${t.id === currentTenant ? 'selected' : ''}>${t.name}</option>
        `).join('');
    } catch (err) {
        console.error('Error loading tenants:', err);
        selector.innerHTML = `<option value="default">Default Tenant (Error Loading)</option>`;
    }
}

async function updateGlobalConfig(key, value) {
    try {
        await fetch('/setup/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ config: { [key]: value } })
        });
    } catch (err) {
        console.error('Failed to update config', err);
    }
}

async function updateAutoUpdate(enabled) {
    await updateGlobalConfig('autoupdate', enabled);
}

async function updateAutoUpdateInterval(hours) {
    await updateGlobalConfig('update_interval', parseInt(hours) || 1);
}

async function triggerUpdate(event) {
    const btn = event ? event.currentTarget : document.getElementById('update-btn');
    if (!btn) return;

    const originalText = btn.textContent;
    btn.disabled = true;
    btn.textContent = 'Updating...';

    try {
        // Append ?force=true to ensure we pull even if version is the same
        const response = await fetch('/setup/update?force=true', { method: 'POST' });
        const data = await response.json();
        if (response.ok) {
            alert(data.message || 'Update triggered successfully!');
        } else {
            alert('Update failed: ' + (data.detail || 'Unknown error'));
        }
    } catch (err) {
        alert('Error triggering update: ' + err.message);
    } finally {
        btn.disabled = false;
        btn.textContent = originalText;
    }
}

async function scanGitHubRepos() {
    try {
        const response = await fetch('/setup/github-repos');
        if (!response.ok) throw new Error('Failed to fetch repos');
        const data = await response.json();
        const repos = data.repos;

        if (repos.length === 0) {
            alert('No repositories found for lbockenstedt');
            return;
        }

        let repoList = repos.map((r, i) => `${i + 1}: ${r.name} (${r.url})`).join('\\n');
        const choice = prompt(`Found ${repos.length} repositories. Enter the number of the repo to use as the Hub source, or 0 to cancel:\\n\\n${repoList}`);

        if (choice && choice !== '0') {
            const idx = parseInt(choice) - 1;
            if (idx >= 0 && idx < repos.length) {
                document.getElementById('update-source-hub').value = repos[idx].url;
                alert(`Set Hub source to ${repos[idx].name}`);
            } else {
                alert('Invalid selection');
            }
        }
    } catch (err) {
        alert('Error scanning GitHub: ' + err.message);
    }
}

async function saveUpdateSources() {
    const sources = {
        hub: document.getElementById('update-source-hub').value,
        pxmx: document.getElementById('update-source-pxmx').value,
        opn: document.getElementById('update-source-opn').value,
        cs: document.getElementById('update-source-cs').value,
        cppm: document.getElementById('update-source-cppm').value,
        netbox: document.getElementById('update-source-netbox').value,
        ldap: document.getElementById('update-source-ldap').value,
    };
    const globalBranch = document.getElementById('global-branch').value;

    try {
        const response = await fetch('/setup/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ config: { update_sources: sources, global_branch: globalBranch } })
        });
        if (response.ok) {
            alert('Update sources and global branch saved successfully!');
        } else {
            alert('Failed to save update sources.');
        }
    } catch (err) {
        alert('Error saving update sources: ' + err.message);
    }
}

function toggleAdvancedSettings() {
    const section = document.getElementById('setup-advanced-section');
    if (section) {
        section.classList.toggle('hidden');
    }
}


async function loadSetupConfig() {
    try {
        const response = await fetch('/setup/config');
        if (!response.ok) return;
        const data = await response.json();
        const config = data.global_config || {};

        const chk = document.getElementById('auto-update-chk');
        const int = document.getElementById('auto-update-int');

        if (chk) chk.checked = config.autoupdate !== false; // Default to true
        if (int) int.value = config.update_interval || 1;

        const tsEl = document.getElementById('last-update-ts');
        if (tsEl && config.last_update_ts) {
            const date = new Date(config.last_update_ts * 1000);
            tsEl.textContent = `Last check: ${date.toLocaleString()}`;
        }

        // Load update sources
        const sources = config.update_sources || {};
        const globalBranch = config.global_branch || 'main';
        if (document.getElementById('global-branch')) {
            document.getElementById('global-branch').value = globalBranch;
        }
        const sourceFields = {
            'hub': 'update-source-hub',
            'pxmx': 'update-source-pxmx',
            'opn': 'update-source-opn',
            'cs': 'update-source-cs',
            'cppm': 'update-source-cppm',
            'netbox': 'update-source-netbox',
            'ldap': 'update-source-ldap'
        };
        for (const [key, id] of Object.entries(sourceFields)) {
            const el = document.getElementById(id);
            if (el) el.value = sources[key] || '';
        }

        // Load module-specific configs if we are in a module subview
        if ((currentView === 'setup' && currentSubView === 'Proxmox') || (currentView === 'pxmx' && currentSubView === 'Configuration')) {
            loadProxmoxConfig(config.pxmx || {});
        } else if ((currentView === 'setup' && currentSubView === 'OPNsense') || (currentView === 'opnsense' && currentSubView === 'Configuration')) {
            loadOpnsenseConfig(config.opn || {});
        } else if ((currentView === 'setup' && currentSubView === 'Client Sim') || (currentView === 'cs' && currentSubView === 'Configuration')) {
            loadCSConfig(config.cs || {});
        } else if ((currentView === 'setup' && currentSubView === 'CPPM') || (currentView === 'cppm' && currentSubView === 'Configuration')) {
            loadCPPMConfig(config.cppm || {});
        } else if (currentView === 'setup' && currentSubView === 'LDAP Config') {
            loadLDAPConfig(config.ldap || {});
        }
    } catch (err) {
        console.error('Failed to load setup config', err);
    }
}

function loadLDAPConfig(config) {
    const urlEl = document.getElementById('ldap-server-url');
    const baseEl = document.getElementById('ldap-base-dn');
    const adminEl = document.getElementById('ldap-admin-dn');
    const passEl = document.getElementById('ldap-admin-pw');
    if (urlEl) urlEl.value = config.server_url || 'ldap://localhost:389';
    if (baseEl) baseEl.value = config.base_dn || 'dc=example,dc=org';
    if (adminEl) adminEl.value = config.admin_dn || 'cn=admin,dc=example,dc=org';
    if (passEl) passEl.value = config.admin_pw || 'admin';
}

async function saveLDAPConfig() {
    const config = {
        server_url: document.getElementById('ldap-server-url').value,
        base_dn: document.getElementById('ldap-base-dn').value,
        admin_dn: document.getElementById('ldap-admin-dn').value,
        admin_pw: document.getElementById('ldap-admin-pw').value,
    };
    try {
        const response = await fetch('/setup/ldap-config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ config: config })
        });
        if (response.ok) {
            alert('LDAP configuration saved successfully!');
        } else {
            alert('Failed to save LDAP configuration.');
        }
    } catch (err) {
        alert('Error saving LDAP configuration: ' + err.message);
    }
}
function loadProxmoxConfig(config) {
    const nodeEl = document.getElementById('pxmx-default-node');
    const clusterEl = document.getElementById('pxmx-cluster-id');
    if (nodeEl) nodeEl.value = config.default_node || '';
    if (clusterEl) clusterEl.value = config.cluster_id || '';
}

function loadOpnsenseConfig(config) {
    const hostEl = document.getElementById('opn-host');
    const portEl = document.getElementById('opn-port');
    const keyEl = document.getElementById('opn-api-key');
    const secretEl = document.getElementById('opn-api-secret');
    if (hostEl) hostEl.value = config.opn_host || '';
    if (portEl) portEl.value = config.opn_port || '8443';
    if (keyEl) keyEl.value = config.api_key || '';
    if (secretEl) secretEl.value = config.api_secret || '';
}

function loadCSConfig(config) {
    const hostEl = document.getElementById('cs-aruba-host');
    const keyEl = document.getElementById('cs-aruba-key');
    if (hostEl) hostEl.value = config.aruba_host || '';
    if (keyEl) keyEl.value = config.aruba_api_key || '';
}

function loadCPPMConfig(config) {
    const hostEl = document.getElementById('cppm-host');
    const userEl = document.getElementById('cppm-user');
    const passEl = document.getElementById('cppm-pass');
    if (hostEl) hostEl.value = config.host || '';
    if (userEl) userEl.value = config.user || '';
    if (passEl) passEl.value = config.password || '';
}

async function saveProxmoxConfig() {
    const config = {
        default_node: document.getElementById('pxmx-default-node').value,
        cluster_id: document.getElementById('pxmx-cluster-id').value,
    };
    try {
        const response = await fetch('/setup/pxmx-config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ config: config })
        });
        if (response.ok) {
            alert('Proxmox configuration saved successfully!');
        } else {
            alert('Failed to save Proxmox configuration.');
        }
    } catch (err) {
        alert('Error saving Proxmox configuration: ' + err.message);
    }
}

async function saveOpnsenseConfig() {
    const config = {
        opn_host: document.getElementById('opn-host').value,
        opn_port: document.getElementById('opn-port').value,
        api_key: document.getElementById('opn-api-key').value,
        api_secret: document.getElementById('opn-api-secret').value,
    };
    try {
        const response = await fetch('/setup/opn-config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ config: config })
        });
        if (response.ok) {
            alert('Firewall configuration saved successfully!');
        } else {
            alert('Failed to save firewall configuration.');
        }
    } catch (err) {
        alert('Error saving firewall configuration: ' + err.message);
    }
}

async function saveCSConfig() {
    const config = {
        aruba_host: document.getElementById('cs-aruba-host').value,
        aruba_api_key: document.getElementById('cs-aruba-key').value,
    };
    try {
        const response = await fetch('/setup/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ config: { cs: config } })
        });
        if (response.ok) {
            alert('Client Sim configuration saved successfully!');
        } else {
            alert('Failed to save Client Sim configuration.');
        }
    } catch (err) {
        alert('Error saving Client Sim configuration: ' + err.message);
    }
}

async function saveCPPMConfig() {
    const config = {
        host: document.getElementById('cppm-host').value,
        user: document.getElementById('cppm-user').value,
        password: document.getElementById('cppm-pass').value,
    };
    try {
        const response = await fetch('/setup/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ config: { cppm: config } })
        });
        if (response.ok) {
            alert('CPPM configuration saved successfully!');
        } else {
            alert('Failed to save CPPM configuration.');
        }
    } catch (err) {
        alert('Error saving CPPM configuration: ' + err.message);
    }
}

async function loadTenantConfig() {
    const listEl = document.getElementById('tenant-list');
    if (!listEl) return;

    try {
        const response = await fetch('/setup/tenants');
        if (!response.ok) throw new Error('Failed to fetch tenants');
        const data = await response.json();
        const tenants = data.tenants || [];

        listEl.innerHTML = tenants.map(t => `
            <div onclick="editTenant('${t.id}')" class="flex items-center justify-between p-2 rounded-md cursor-pointer transition-all group ${t.id === currentTenant ? 'bg-green-50 border-l-4 border-green-500' : 'bg-white border border-slate-200 hover:bg-slate-50'}">
                <div class="flex items-center gap-2">
                    <span class="text-xs font-medium text-slate-700 group-hover:text-green-600">${t.name}</span>
                </div>
                <span class="text-[10px] font-mono text-slate-400">${t.id}</span>
            </div>
        `).join('');
    } catch (err) {
        console.error('Error loading tenant config:', err);
        listEl.innerHTML = `<div class="py-4 text-center text-red-500 text-xs">Error loading tenants: ${err.message}</div>`;
    }
}

async function editTenant(tenantId) {
    const editor = document.getElementById('tenant-editor');
    const emptyState = document.getElementById('tenant-empty-state');
    if (!editor) return;

    try {
        const response = await fetch(`/setup/tenants/${tenantId}`);
        if (!response.ok) throw new Error('Failed to fetch tenant details');
        const data = await response.json();
        const config = data.config || {};

        document.getElementById('edit-tenant-id').textContent = tenantId;
        document.getElementById('tenant-name').value = config.name || tenantId;
        document.getElementById('tenant-active').checked = (currentTenant === tenantId);

        const quotas = config.quotas || {};
        document.getElementById('quota-vm').value = quotas.vm || 0;
        document.getElementById('quota-cppm').value = quotas.cppm || 0;
        document.getElementById('quota-opn').value = quotas.opn || 0;

        editor.classList.remove('hidden');
        emptyState.classList.add('hidden');
    } catch (err) {
        alert('Error loading tenant: ' + err.message);
    }
}

function closeTenantEditor() {
    document.getElementById('tenant-editor').classList.add('hidden');
    document.getElementById('tenant-empty-state').classList.remove('hidden');
}

async function saveTenantConfig() {
    const tenantId = document.getElementById('edit-tenant-id').textContent;
    const config = {
        name: document.getElementById('tenant-name').value,
        quotas: {
            vm: parseInt(document.getElementById('quota-vm').value) || 0,
            cppm: parseInt(document.getElementById('quota-cppm').value) || 0,
            opn: parseInt(document.getElementById('quota-opn').value) || 0,
        }
    };

    try {
        const response = await fetch('/setup/tenant', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ tenant_id: tenantId, config: config })
        });
        if (response.ok) {
            alert('Tenant configuration saved successfully!');
            await loadTenantConfig();
        } else {
            alert('Failed to save tenant configuration.');
        }
    } catch (err) {
        alert('Error saving tenant: ' + err.message);
    }
}

async function addTenant() {
    const tenantId = document.getElementById('new-tenant-id').value.trim();
    if (!tenantId) {
        alert('Please enter a Tenant ID');
        return;
    }

    try {
        const response = await fetch('/setup/tenants', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ tenant_id: tenantId })
        });
        if (response.ok) {
            document.getElementById('new-tenant-id').value = '';
            await loadTenantConfig();
        } else {
            alert('Failed to create tenant.');
        }
    } catch (err) {
        alert('Error creating tenant: ' + err.message);
    }
}

function renderTopNav() {
    const topNav = document.getElementById('top-nav');
    if (!topNav) return;

    const view = VIEWS[currentView] || VIEWS[currentProduct];
    if (!view) return;

    let topNavHtml = '';

    // 1. Render Product Tabs if we are in a multi-product class
    const isClass = Object.keys(MODULE_CLASSES).includes(currentView);
    if (isClass && MODULE_CLASSES[currentView] &&
        Array.from(window.activeProducts || []).filter(p => MODULE_CLASSES[currentView].includes(p)).length > 1) {

        const products = Array.from(window.activeProducts || []).filter(p => MODULE_CLASSES[currentView].includes(p));
        topNavHtml += `<div class="flex gap-2 mr-4 border-r border-slate-300 pr-4">`;
        topNavHtml += products.map(p => `
            <div onclick="switchProduct('${p}')" class="px-3 py-1 text-xs font-bold rounded cursor-pointer transition-all ${p === currentProduct ? 'bg-green-600 text-white' : 'bg-slate-200 text-slate-600 hover:bg-slate-300'}">
                ${VIEWS[p].name}
            </div>
        `).join('');
        topNavHtml += `</div>`;
    }

    // 2. Render Sub-menus
    topNavHtml += view.subMenus.map((menu, i) => {
        return `
            <div onclick="setSubView('${menu}')" class="sub-nav-item ${menu === 'config' ? 'ml-auto' : ''} ${menu === currentSubView ? 'active' : ''} px-2 py-1 text-xs uppercase tracking-widest cursor-pointer">
                ${menu}
            </div>
        `;
    }).join('');

    topNav.innerHTML = topNavHtml;
}

function renderSpokeIndicators() {
    const bannerEl = document.getElementById('spoke-indicators-banner');
    if (!bannerEl || !window.spokeHealth) return;

    bannerEl.innerHTML = Object.entries(window.spokeHealth).map(([id, health]) => {
        let color = 'bg-red-500';
        if (health.online) {
            color = health.error ? 'bg-yellow-500' : 'bg-green-500';
        }
        return `
            <div class="flex items-center gap-1.5 group relative">
                <div class="w-2 h-2 rounded-full ${color} shadow-sm transition-all group-hover:scale-125"></div>
                <span class="text-[10px] font-mono text-slate-400 group-hover:text-slate-600 transition-colors">${id}</span>
                <div class="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 hidden group-hover:block bg-slate-800 text-white text-[10px] px-2 py-1 rounded shadow-lg whitespace-nowrap z-50">
                    ${id}: ${health.online ? (health.error ? 'Online (Error)' : 'Online') : 'Offline'}
                </div>
            </div>
        `;
    }).join('');
}

async function setView(viewId) {
    const isClass = Object.keys(MODULE_CLASSES).includes(viewId);


    if (isClass) {
        // Find active products for this class
        const activeProducts = [];
        // We need to get the approved/connected spokes again
        // In a real app, we'd cache this, but for now we can call the API or use a global
        // Since updateStatus is called every 10s, let's use a global cache for active products
        const products = Array.from(window.activeProducts || []).filter(p =>
            MODULE_CLASSES[viewId].includes(p)
        );

        if (products.length === 0) {
            alert('No active products available for this category.');
            return;
        }

        if (products.length === 1) {
            currentView = products[0];
            currentProduct = products[0];
        } else {
            currentView = viewId;
            currentProduct = products[0];
        }
    } else {
        currentView = viewId;
        currentProduct = viewId;
    }

    currentSubView = 'General'; // Default sub-view

    const view = VIEWS[currentView] || VIEWS[currentProduct];
    if (view && view.subMenus && !view.subMenus.includes('General')) {
        currentSubView = view.subMenus[0];
    }

    document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
    const navItem = document.getElementById(`nav-${isClass ? viewId : currentView}`);
    if (navItem) navItem.classList.add('active');

    const topNav = document.getElementById('top-nav');
    if (view) {
        renderTopNav();
    }

    const viewport = document.getElementById('viewport');
    if (viewport && view) {
        viewport.innerHTML = await view.render(currentSubView);
        if (viewId === 'setup') {

            loadSetupConfig();
            loadTenants();
            if (currentSubView === 'Spoke Approvals') loadPendingSpokes();
            if (currentSubView === 'Tenant Config') loadTenantConfig();
            if (currentSubView === 'Generic Nodes') loadGenericAgents();
        }
        if (currentView === 'pxmx') {
            loadVMInventory();
        }
        if (currentView === 'opnsense') {
            loadOpnsenseManagement();
        }
    }

    if (currentView === 'dashboard' || currentView === 'settings') updateStatus();
}

function switchProduct(productId) {
    currentProduct = productId;
    currentView = productId; // Treat as the product view
    setView(currentView);
}

async function setSubView(subMenu) {
    currentSubView = subMenu;
    const view = VIEWS[currentView];
    if (view) {

        // Update sub-nav active state
        renderTopNav();

        // Re-render content
        const viewport = document.getElementById('viewport');
        if (viewport) {
            viewport.innerHTML = await view.render(currentSubView);
            if (currentView === 'setup') {

                loadSetupConfig();
                loadTenants();
                if (currentSubView === 'Spoke Approvals') {
                    loadPendingSpokes();
                }
                if (currentSubView === 'Tenant Config') {
                    loadTenantConfig();
                }
                if (currentSubView === 'User Access') {
                    loadUsers();
                }
                if (currentSubView === 'Generic Nodes') {
                    loadGenericAgents();
                }
            }
            if (currentView === 'ldap') {
                loadLDAPData(currentSubView);
            }
            if ((currentView === 'pxmx' && currentSubView === 'config') ||
                (currentView === 'opnsense' && currentSubView === 'config')) {
                loadSetupConfig();
            }
            if (currentView === 'settings' && currentSubView.startsWith('logs-')) {
                const module = currentSubView.replace('logs-', '');
                loadModuleLogs(module);
            }
            if (currentView === 'settings' && currentSubView === 'General') updateStatus();
            if (currentView === 'settings' && currentSubView === 'Diagnostics') loadDiagnostics();
            if (currentView === 'opnsense' && currentSubView !== 'config') {
                loadOpnsenseManagement();
            }
        }
    }
}

async function updateStatus() {
    const statusEl = document.getElementById('connection-status');
    const spokeList = document.getElementById('spoke-list');
    const spokeCount = document.getElementById('spoke-count');
    const mainNav = document.getElementById('main-nav');

    if (!statusEl) {
        // Connection status pill removed from UI, but we still need to process status updates
    }


    try {
        // Fetch both connection status and approval status
        const [statusRes, approvalsRes, diagRes] = await Promise.all([
            fetch('/status'),
            fetch('/setup/pending_spokes'),
            fetch('/setup/diagnostics')
        ]);

        if (!statusRes.ok || !approvalsRes.ok || !diagRes.ok) throw new Error('API Error');

        const statusData = await statusRes.json();
        const approvalsData = await approvalsRes.json();
        const diagData = await diagRes.json();

        // Update system metrics if elements exist
        if (statusData.metrics) {
            const m = statusData.metrics;
            const cpuEl = document.getElementById('sys-cpu');
            const memEl = document.getElementById('sys-mem');
            const diskEl = document.getElementById('sys-disk');
            const mpsEl = document.getElementById('sys-mps');
            const qEl = document.getElementById('sys-queue');
            const bEl = document.getElementById('sys-backlog');
            const tEl = document.getElementById('sys-throughput');
            if (cpuEl) cpuEl.textContent = `${m.cpu_util}%`;
            if (memEl) memEl.textContent = `${m.mem_util}%`;
            if (diskEl) diskEl.textContent = `${m.disk_util}%`;
            if (mpsEl) mpsEl.textContent = `${m.mps.toFixed(1)} msg/s`;
            if (qEl) qEl.textContent = m.queue_size;
            if (bEl) bEl.textContent = m.backlog;
            if (tEl) tEl.textContent = `${m.throughput.toFixed(2)} MB/s`;

            const versionEl = document.getElementById('footer-sys-version');
            if (versionEl && m.version) {
                versionEl.textContent = `v${m.version}`;
            }
        }

        if (statusEl) {
            statusEl.innerHTML = `
                <div class="w-1.5 h-1.5 rounded-full bg-green-500"></div>
                <span class="text-green-600">Hub Online</span>
            `;
        }

        const connections = statusData.active_connections || [];

        // Store health for the top nav indicators
        window.spokeHealth = {};
        (diagData.spokes || []).forEach(s => {
            window.spokeHealth[s.spoke_id] = {
                online: s.authenticated,
                error: !!s.last_error
            };
        });
        renderSpokeIndicators();


        // Count approved spokes for the dashboard metric
        const allSpokes = approvalsData.spokes || [];
        const approvedSpokes = allSpokes.filter(s => s.approved);

        if (spokeCount) spokeCount.textContent = approvedSpokes.length;

        const activeProducts = new Set();

        // 1. Add products that are currently online
        connections.forEach(id => {
            for (const [key, product] of Object.entries(PRODUCT_MAP)) {
                if (id.includes(key)) activeProducts.add(product);
            }
        });

        // 2. Add products that are known and approved (even if offline)
        const allSpokesList = approvalsData.spokes || [];
        allSpokesList.forEach(spoke => {
            if (spoke.approved) {
                for (const [key, product] of Object.entries(PRODUCT_MAP)) {
                    if (spoke.spoke_id.includes(key)) activeProducts.add(product);
                }
            }
        });

        window.activeProducts = activeProducts;

        // Determine which classes are active
        const activeClasses = [];
        for (const [className, products] of Object.entries(MODULE_CLASSES)) {
            if (products.some(p => activeProducts.has(p))) {
                activeClasses.push(className);
            }
        }

        const staticNavs = ['dashboard', 'settings', 'setup'];
        const dynamicHtml = activeClasses.map(className => {
            const isActive = currentView === className ? 'active' : '';
            // Use an icon from the first active product in the class
            const firstProduct = MODULE_CLASSES[className].find(p => activeProducts.has(p));
            let icon = VIEWS[firstProduct]?.icon || '';

            // Specialize icon for Security/NAC
            if (className === 'Security/NAC') {
                icon = '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg>';
            }

            return `
                <div onclick="setView('${className}')" id="nav-${className}" class="nav-item ${isActive} p-3 rounded-r-lg flex items-center gap-3 text-sm font-medium">
                    ${icon}
                    ${className}
                </div>
            `;
        }).join('');

        const dashboardNav = document.getElementById('nav-dashboard').outerHTML;
        const setupNav = document.getElementById('nav-setup').outerHTML;
        const settingsNav = document.getElementById('nav-settings').outerHTML;

        mainNav.innerHTML = `
            ${dashboardNav}
            ${dynamicHtml}
            <div class="pt-4 mt-4 border-t border-slate-200"></div>
            ${setupNav}
            ${settingsNav}
        `;

        if (spokeList) {
            if (approvedSpokes.length === 0) {
                spokeList.innerHTML = `<p class="text-xs text-slate-400 italic">No approved spokes configured.</p>`;
            } else {
                spokeList.innerHTML = approvedSpokes.map(spoke => {
                    const id = spoke.spoke_id;
                    const isOnline = connections.includes(id);
                    return `
                        <div class="flex items-center justify-between p-3 rounded-lg bg-slate-50 border border-slate-200 hover:border-green-500 transition-all group">
                            <div class="flex items-center gap-3">
                                <div class="w-2 h-2 rounded-full ${isOnline ? 'bg-green-500 shadow-[0_0_8px_rgba(34,197,94,0.6)]' : 'bg-slate-400'}"></div>
                                <span class="text-sm font-medium text-slate-700 group-hover:text-green-600 transition-colors">${id}</span>
                            </div>
                            <span class="text-[10px] uppercase tracking-widest ${isOnline ? 'text-green-600 font-bold' : 'text-slate-400 font-bold'}">${isOnline ? 'Online' : 'Offline'}</span>
                        </div>
                    `;
                }).join('');
            }
        }
    } catch (err) {
        statusEl.innerHTML = `
            <div class="w-1.5 h-1.5 rounded-full bg-red-500"></div>
            <span class="text-red-600">Hub Offline</span>
        `;
        if (spokeList) spokeList.innerHTML = `<p class="text-xs text-red-500 italic">Error connecting to Hub API.</p>`;
    }
}

async function handleSearch(query) {
    const resultsEl = document.getElementById('search-results');
    if (!query) {
        resultsEl.classList.add('hidden');
        return;
    }

    try {
        const response = await fetch('/status');
        const data = await response.json();
        const connections = data.active_connections || [];

        const filtered = connections.filter(id => id.toLowerCase().includes(query.toLowerCase()));

        if (filtered.length === 0) {
            resultsEl.innerHTML = `<div class="p-3 text-xs text-slate-500 italic">No matches found</div>`;
        } else {
            resultsEl.innerHTML = filtered.map(id => `
                <div onclick="setView('dashboard')" class="p-2 text-xs text-slate-700 hover:bg-slate-100 rounded cursor-pointer transition-colors">
                    ${id}
                </div>
            `).join('');
        }
        resultsEl.classList.remove('hidden');
    } catch (err) {
        resultsEl.innerHTML = `<div class="p-3 text-xs text-red-400">Search failed</div>`;
        resultsEl.classList.remove('hidden');
    }
}

async function loadLDAPData(subMenu) {
    const headEl = document.getElementById('ldap-table-head');
    const bodyEl = document.getElementById('ldap-table-body');
    if (!headEl || !bodyEl) return;

    try {
        let endpoint = '';
        let headers = [];
        if (subMenu === 'OUs') {
            endpoint = '/api/ldap/ous';
            headers = ['Name', 'DN', 'Actions'];
        } else if (subMenu === 'Users') {
            endpoint = '/api/ldap/users';
            headers = ['Username', 'First Name', 'Last Name', 'Email', 'DN', 'Actions'];
        } else if (subMenu === 'Groups') {
            endpoint = '/api/ldap/groups';
            headers = ['Name', 'DN', 'Actions'];
        }

        headEl.innerHTML = `<tr>${headers.map(h => `<th class="px-4 py-3 font-bold">${h}</th>`).join('')}</tr>`;
        bodyEl.innerHTML = `<tr><td colspan="100%" class="px-4 py-8 text-center text-slate-400 italic">Fetching ${subMenu}...</td></tr>`;

        const response = await fetch(endpoint);
        if (!response.ok) throw new Error(`Failed to fetch ${subMenu}`);
        const data = await response.json();
        const items = data.data || [];

        if (items.length === 0) {
            bodyEl.innerHTML = `<tr><td colspan="100%" class="px-4 py-8 text-center text-slate-400 italic">No ${subMenu.toLowerCase()} found.</td></tr>`;
            return;
        }

        bodyEl.innerHTML = items.map(item => {
            let row = '';
            if (subMenu === 'OUs') {
                row = `<td class="px-4 py-3 text-slate-700">${item.name}</td><td class="px-4 py-3 font-mono text-xs text-slate-500">${item.dn}</td>`;
            } else if (subMenu === 'Users') {
                row = `<td class="px-4 py-3 text-slate-700 font-medium">${item.username}</td><td class="px-4 py-3 text-slate-600">${item.first_name}</td><td class="px-4 py-3 text-slate-600">${item.last_name}</td><td class="px-4 py-3 text-slate-600">${item.email}</td><td class="px-4 py-3 font-mono text-xs text-slate-500">${item.dn}</td>`;
            } else if (subMenu === 'Groups') {
                row = `<td class="px-4 py-3 text-slate-700">${item.name}</td><td class="px-4 py-3 font-mono text-xs text-slate-500">${item.dn}</td>`;
            }

            row += `<td class="px-4 py-3 text-right">
                <button onclick="deleteLDAPEntity('${item.dn}')" class="p-1 text-slate-400 hover:text-red-600 transition-colors">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>
                </button>
            </td>`;
            return `<tr class="hover:bg-slate-50 transition-colors">${row}</tr>`;
        }).join('');

    } catch (err) {
        bodyEl.innerHTML = `<tr><td colspan="100%" class="px-4 py-8 text-center text-red-500">${err.message}</td></tr>`;
    }
}

function showLDAPModal(subMenu) {
    const modal = document.createElement('div');
    modal.className = 'fixed inset-0 bg-slate-900/50 backdrop-blur-sm flex items-center justify-center z-50';

    let fields = '';
    if (subMenu === 'OUs') {
        fields = `
            <div class="space-y-2">
                <label class="text-xs text-slate-500 uppercase font-bold">OU Name</label>
                <input type="text" id="ldap-ou-name" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
            </div>
            <div class="space-y-2">
                <label class="text-xs text-slate-500 uppercase font-bold">Parent DN</label>
                <input type="text" id="ldap-ou-parent" placeholder="dc=example,dc=org" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
            </div>
        `;
    } else if (subMenu === 'Users') {
        fields = `
            <div class="grid grid-cols-2 gap-4">
                <div class="space-y-2">
                    <label class="text-xs text-slate-500 uppercase font-bold">Username</label>
                    <input type="text" id="ldap-user-username" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                </div>
                <div class="space-y-2">
                    <label class="text-xs text-slate-500 uppercase font-bold">First Name</label>
                    <input type="text" id="ldap-user-first" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                </div>
                <div class="space-y-2">
                    <label class="text-xs text-slate-500 uppercase font-bold">Last Name</label>
                    <input type="text" id="ldap-user-last" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                </div>
                <div class="space-y-2">
                    <label class="text-xs text-slate-500 uppercase font-bold">Email</label>
                    <input type="text" id="ldap-user-email" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                </div>
            </div>
            <div class="space-y-2">
                <label class="text-xs text-slate-500 uppercase font-bold">OU DN</label>
                <input type="text" id="ldap-user-ou" placeholder="ou=Users,dc=example,dc=org" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
            </div>
        `;
    } else if (subMenu === 'Groups') {
        fields = `
            <div class="space-y-2">
                <label class="text-xs text-slate-500 uppercase font-bold">Group Name</label>
                <input type="text" id="ldap-group-name" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
            </div>
            <div class="space-y-2">
                <label class="text-xs text-slate-500 uppercase font-bold">OU DN</label>
                <input type="text" id="ldap-group-ou" placeholder="ou=Groups,dc=example,dc=org" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
            </div>
        `;
    }

    modal.innerHTML = `
        <div class="bg-white rounded-lg shadow-2xl w-full max-w-md overflow-hidden border border-slate-200">
            <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center">
                <h3 class="text-lg font-bold text-slate-800">Add ${subMenu === 'OUs' ? 'OU' : (subMenu === 'Users' ? 'User' : 'Group')}</h3>
                <button onclick="this.closest('.fixed').remove()" class="text-slate-400 hover:text-slate-600">
                    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                </button>
            </div>
            <div class="p-6 space-y-4">
                ${fields}
            </div>
            <div class="px-6 py-4 bg-slate-50 border-t border-slate-200 flex justify-end gap-3">
                <button onclick="this.closest('.fixed').remove()" class="px-4 py-2 text-sm font-medium text-slate-600 hover:text-slate-800">Cancel</button>
                <button onclick="saveLDAPEntity('${subMenu}')" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-6 py-2 rounded-md text-sm font-bold transition-all">Save Entity</button>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
}

async function saveLDAPEntity(subMenu) {
    const body = {};
    if (subMenu === 'OUs') {
        body.name = document.getElementById('ldap-ou-name').value;
        body.parent_dn = document.getElementById('ldap-ou-parent').value;
    } else if (subMenu === 'Users') {
        body.username = document.getElementById('ldap-user-username').value;
        body.first_name = document.getElementById('ldap-user-first').value;
        body.last_name = document.getElementById('ldap-user-last').value;
        body.email = document.getElementById('ldap-user-email').value;
        body.ou_dn = document.getElementById('ldap-user-ou').value;
    } else if (subMenu === 'Groups') {
        body.name = document.getElementById('ldap-group-name').value;
        body.ou_dn = document.getElementById('ldap-group-ou').value;
    }

    try {
        const endpoint = subMenu === 'OUs' ? '/api/ldap/ous' : (subMenu === 'Users' ? '/api/ldap/users' : '/api/ldap/groups');
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        if (response.ok) {
            alert('Entity created successfully!');
            document.querySelector('.fixed').remove();
            loadLDAPData(subMenu);
        } else {
            const err = await response.json();
            alert('Error: ' + (err.message || 'Failed to create entity'));
        }
    } catch (e) {
        alert('Request failed: ' + e.message);
    }
}

async function deleteLDAPEntity(dn) {
    if (!confirm(`Are you sure you want to delete ${dn}?`)) return;
    try {
        const response = await fetch('/api/ldap/delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ dn: dn })
        });
        if (response.ok) {
            alert('Entity deleted successfully!');
            loadLDAPData(currentSubView);
        } else {
            const err = await response.json();
            alert('Error: ' + (err.message || 'Failed to delete entity'));
        }
    } catch (e) {
        alert('Request failed: ' + e.message);
    }
}

async function loadVMInventory() {
    const listEl = document.getElementById('vm-list');
    const inventoryEl = document.getElementById('vm-inventory');
    const emptyStateEl = document.getElementById('vm-empty-state');
    if (!listEl) return;


    try {
        const response = await fetch('/status');
        if (!response.ok) throw new Error('Failed to fetch status');
        const data = await response.json();
        const resources = data.state?.resources || {};
        const vms = Object.entries(resources);

        if (vms.length === 0) {
            if (inventoryEl) inventoryEl.classList.add('hidden');
            if (emptyStateEl) emptyStateEl.classList.remove('hidden');
            return;
        }

        if (emptyStateEl) emptyStateEl.classList.add('hidden');
        if (inventoryEl) inventoryEl.classList.remove('hidden');

        listEl.innerHTML = vms.map(([id, info]) => {
            const ip = info.metadata?.ip || 'No IP';
            const name = info.metadata?.name || id;
            return `
                <div onclick="selectVM('${id}')" class="p-3 rounded-md bg-white border border-slate-200 hover:border-green-500 cursor-pointer transition-all group">
                    <div class="flex justify-between items-start">
                        <span class="text-sm font-bold text-slate-800 group-hover:text-green-600 transition-colors">${name}</span>
                        <span class="text-[10px] font-mono text-slate-400">${id}</span>
                    </div>
                    <div class="text-xs text-slate-500 mt-1 font-mono">${ip}</div>
                </div>
            `;
        }).join('');
    } catch (err) {
        console.error('Error loading VM inventory:', err);
        listEl.innerHTML = `<div class="col-span-full text-center text-red-500 text-xs py-4">Error loading inventory: ${err.message}</div>`;
    }
}

function selectVM(vmId) {
    const input = document.getElementById('vm-id-input');
    if (input) {
        input.value = vmId;
        lookupVMDetails();
    }
}

async function lookupVMDetails() {
    const vmId = document.getElementById('vm-id-input').value.trim();
    if (!vmId) return;

    const details = document.getElementById('vm-details');
    const emptyState = document.getElementById('vm-empty-state');
    const tableBody = document.getElementById('firewall-table-body');
    const idEl = document.getElementById('res-vm-id');
    const ipEl = document.getElementById('res-ip');
    const resResources = document.getElementById('res-resources');
    const resSecurity = document.getElementById('res-security');
    const dhcpHost = document.getElementById('dhcp-host');
    const dhcpMac = document.getElementById('dhcp-mac');
    const dhcpEnd = document.getElementById('dhcp-end');

    emptyState.classList.add('hidden');
    details.classList.remove('hidden');
    tableBody.innerHTML = `<tr><td colspan="4" class="px-4 py-8 text-center text-slate-400 animate-pulse">Stitching VM data...</td></tr>`;

    try {
        const response = await fetch(`/vm/${vmId}/details`);
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to fetch VM details');
        }
        const data = await response.json();

        idEl.textContent = vmId;
        ipEl.textContent = data.ip || 'Unknown';

        // 1. Update Resources (Proxmox)
        const res = data.proxmox || {};
        resResources.textContent = `CPU: ${res.cpu || '-'}% | RAM: ${res.ram || '-'}MB | Disk: ${res.disk || '-'}%`;

        // 2. Update Security (CPPM)
        const sec = data.cppm || {};
        resSecurity.textContent = `Policy: ${sec.policy || '-'} | Posture: ${sec.posture || '-'}`;

        // 3. Update DHCP (OPNsense)
        const dhcp = data.dhcp || {};
        dhcpHost.textContent = dhcp.hostname || '-';
        dhcpMac.textContent = dhcp.mac || '-';
        dhcpEnd.textContent = dhcp.lease_end || '-';

        // 4. Update Firewall Rules (OPNsense)
        const rules = (data.opnsense && data.opnsense.rules) || [];
        if (rules.length === 0) {
            tableBody.innerHTML = `<tr><td colspan="5" class="px-4 py-4 text-center text-slate-400 italic">No rules found for this VM.</td></tr>`;
        } else {
            tableBody.innerHTML = rules.map(rule => `
                <tr class="hover:bg-slate-50 transition-colors">
                    <td class="px-4 py-3 font-mono text-xs text-slate-600">${rule.source || 'any'}</td>
                    <td class="px-4 py-3 text-slate-600">${rule.destination || '-'}</td>
                    <td class="px-4 py-3 text-slate-600">${rule.protocol || 'TCP'}</td>
                    <td class="px-4 py-3">
                        <span class="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase ${rule.action === 'pass' ? 'bg-green-100 text-green-600' : 'bg-red-100 text-red-600'}">
                            ${rule.action}
                        </span>
                    </td>
                    <td class="px-4 py-3 text-slate-600 text-xs">${rule.description || '-'}</td>
                </tr>
            `).join('');
        }
    } catch (err) {
        tableBody.innerHTML = `<tr><td colspan="5" class="px-4 py-8 text-center text-red-500 font-medium">${err.message}</td></tr>`;
    }
}

async function loadUsers() {
    const bodyEl = document.getElementById('user-permissions-body');
    if (!bodyEl) return;

    try {
        const response = await fetch('/setup/users');
        if (!response.ok) throw new Error('Failed to fetch users');
        const data = await response.json();
        const users = data.users || {};

        if (Object.keys(users).length === 0) {
            bodyEl.innerHTML = `<tr class="text-center py-8 text-slate-400 italic"><td colspan="8">No users configured.</td></tr>`;
            return;
        }

        bodyEl.innerHTML = Object.entries(users).map(([userId, user]) => {
            const perms = user.permissions || {};
            const check = (key) => perms[key] ?
                `<svg class="w-4 h-4 text-green-500" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"></path></svg>` :
                `<div class="w-4 h-4 rounded-full border-2 border-slate-200"></div>`;

            return `
                <tr class="hover:bg-slate-50 transition-colors">
                    <td class="px-4 py-3 font-mono text-xs font-medium text-slate-700">${userId}</td>
                    <td class="px-4 py-3 text-center">${check('view')}</td>
                    <td class="px-4 py-3 text-center">${check('edit')}</td>
                    <td class="px-4 py-3 text-center">${check('pxmx')}</td>
                    <td class="px-4 py-3 text-center">${check('firewall')}</td>
                    <td class="px-4 py-3 text-center">${check('dns')}</td>
                    <td class="px-4 py-3 text-center">${check('dhcp')}</td>
                    <td class="px-4 py-3 text-center">${check('security')}</td>
                    <td class="px-4 py-3 text-center bg-slate-50 font-bold">${check('admin')}</td>
                    <td class="px-4 py-3 text-right">
                        <button onclick="editUser('${userId}')" class="text-blue-400 hover:text-blue-600 text-xs font-bold mr-3">Edit</button>
                        <button onclick="deleteUser('${userId}')" class="text-red-400 hover:text-red-600 text-xs font-bold">Delete</button>
                    </td>
                </tr>
            `;
        }).join('');
    } catch (err) {
        console.error('Error loading users:', err);
        bodyEl.innerHTML = `<tr class="text-center py-8 text-red-500 text-xs">Error loading users: ${err.message}</tr>`;
    }
}

async function deleteUser(userId) {
    if (!confirm(`Are you sure you want to delete user ${userId}?`)) return;
    try {
        const response = await fetch(`/setup/users/${userId}`, { method: 'DELETE' });
        if (response.ok) {
            alert('User deleted');
            await loadUsers();
        } else {
            alert('Failed to delete user');
        }
    } catch (err) {
        alert('Error deleting user: ' + err.message);
    }
}

async function editUser(userId) {
    try {
        // 1. Fetch user and tenants
        const [userResp, tenantResp] = await Promise.all([
            fetch('/setup/users'),
            fetch('/setup/tenants')
        ]);
        if (!userResp.ok || !tenantResp.ok) throw new Error('Failed to load user or tenant data');

        const userData = await userResp.json();
        const tenantData = await tenantResp.json();

        const users = userData.users || {};
        const user = users[userId];
        if (!user) throw new Error('User not found');

        const tenants = tenantData.tenants || [];
        const userTenants = user.tenants || [];

        // Create Modal
        const modal = document.createElement('div');
        modal.id = 'edit-user-modal';
        modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm';

        // Permissions HTML (Reuse pattern from add user)
        const perms = user.permissions || {};
        const permFields = [
            {id: 'admin', label: 'System Admin'},
            {id: 'view', label: 'View'},
            {id: 'edit', label: 'Edit'},
            {id: 'pxmx', label: 'Hypervisor'},
            {id: 'firewall', label: 'Firewall'},
            {id: 'dns', label: 'DNS'},
            {id: 'dhcp', label: 'DHCP'},
            {id: 'security', label: 'Security/NAC'},
        ];

        const permHtml = permFields.map(p => `
            <div class="space-y-2">
                <label class="text-xs text-slate-500 uppercase font-bold">${p.label}</label>
                <div class="flex items-center gap-2 py-2">
                    <input type="checkbox" id="edit-perm-${p.id}" ${perms[p.id] ? 'checked' : ''} class="w-4 h-4 text-green-600 border-slate-300 rounded focus:ring-green-500">
                </div>
            </div>
        `).join('');

        // Tenants HTML
        const tenantHtml = tenants.map(t => `
            <div class="flex items-center gap-3 p-2 hover:bg-slate-100 rounded-md transition-colors cursor-pointer">
                <input type="checkbox" id="edit-tenant-${t.id}" ${userTenants.includes(t.id) ? 'checked' : ''} value="${t.id}" class="w-4 h-4 text-green-600 border-slate-300 rounded focus:ring-green-500">
                <label for="edit-tenant-${t.id}" class="text-sm text-slate-700 cursor-pointer flex-1">${t.name}</label>
            </div>
        `).join('');

        modal.innerHTML = `
            <div class="bg-white rounded-xl shadow-2xl w-full max-w-2xl overflow-hidden">
                <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50">
                    <h3 class="text-lg font-bold text-[#263040]">Edit User: ${userId}</h3>
                    <button onclick="closeEditUserModal()" class="text-slate-400 hover:text-slate-600 transition-colors">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                    </button>
                </div>
                <div class="p-6 grid grid-cols-1 md:grid-cols-2 gap-8">
                    <div class="space-y-6">
                        <div>
                            <h4 class="text-xs font-bold text-slate-400 uppercase mb-4">Permissions</h4>
                            <div class="grid grid-cols-2 gap-4">
                                ${permHtml}
                            </div>
                        </div>
                    </div>
                    <div class="space-y-6">
                        <div>
                            <h4 class="text-xs font-bold text-slate-400 uppercase mb-4">Tenant Associations</h4>
                            <div class="border border-slate-200 rounded-lg overflow-hidden bg-slate-50 max-h-64 overflow-y-auto p-2 space-y-1">
                                ${tenantHtml || '<div class="text-xs text-slate-400 italic p-2">No tenants available.</div>'}
                            </div>
                        </div>
                    </div>
                </div>
                <div class="px-6 py-4 bg-slate-50 border-t border-slate-200 flex justify-end gap-3">
                    <button onclick="closeEditUserModal()" class="px-4 py-2 text-sm font-medium text-slate-600 hover:text-slate-800 transition-colors">Cancel</button>
                    <button onclick="saveUserEdits('${userId}')" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm">Save Changes</button>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
    } catch (err) {
        alert('Error opening edit modal: ' + err.message);
    }
}

function closeEditUserModal() {
    const modal = document.getElementById('edit-user-modal');
    if (modal) modal.remove();
}

async function saveUserEdits(userId) {
    try {
        // 1. Collect permissions
        const permissions = {
            admin: document.getElementById('edit-perm-admin').checked,
            view: document.getElementById('edit-perm-view').checked,
            edit: document.getElementById('edit-perm-edit').checked,
            pxmx: document.getElementById('edit-perm-pxmx').checked,
            firewall: document.getElementById('edit-perm-firewall').checked,
            dns: document.getElementById('edit-perm-dns').checked,
            dhcp: document.getElementById('edit-perm-dhcp').checked,
            security: document.getElementById('edit-perm-security').checked,
        };

        // 2. Collect tenants
        const tenantCheckboxes = document.querySelectorAll('input[id^="edit-tenant-"]');
        const selectedTenants = Array.from(tenantCheckboxes)
            .filter(cb => cb.checked)
            .map(cb => cb.value);

        // 3. Update basic user info (permissions)
        const updateResp = await fetch('/setup/users', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ user_id: userId, permissions: permissions })
        });
        if (!updateResp.ok) throw new Error('Failed to update user permissions');

        // 4. Handle tenant associations
        // We need current tenant list to find what to remove
        const userResp = await fetch('/setup/users');
        const userData = await userResp.json();
        const currentTenants = userData.users[userId].tenants || [];

        const tenantsToAssign = selectedTenants.filter(t => !currentTenants.includes(t));
        const tenantsToRemove = currentTenants.filter(t => !selectedTenants.includes(t));

        const requests = [];

        for (const tId of tenantsToAssign) {
            requests.push(fetch('/setup/users/assign-tenant', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ user_id: userId, tenant_id: tId })
            }));
        }

        for (const tId of tenantsToRemove) {
            requests.push(fetch('/setup/users/remove-tenant', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ user_id: userId, tenant_id: tId })
            }));
        }

        await Promise.all(requests);

        alert('User updated successfully');
        closeEditUserModal();
        await loadUsers();
    } catch (err) {
        alert('Error saving user edits: ' + err.message);
    }
}

function showAddUserModal() {
    const modal = document.createElement('div');
    modal.id = 'add-user-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm';
    modal.innerHTML = `
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-md overflow-hidden">
            <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50">
                <h3 class="text-lg font-bold text-[#263040]">Add New User</h3>
                <button onclick="closeAddUserModal()" class="text-slate-400 hover:text-slate-600 transition-colors">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                </button>
            </div>
            <div class="p-6 space-y-4">
                <div class="space-y-2">
                    <label class="text-xs text-slate-500 uppercase font-bold">User ID</label>
                    <input type="text" id="new-user-id" placeholder="e.g. admin-user" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                </div>
                <div class="grid grid-cols-2 gap-4">
                    <div class="space-y-2">
                        <label class="text-xs text-slate-500 uppercase font-bold">System Admin</label>
                        <div class="flex items-center gap-2 py-2">
                            <input type="checkbox" id="perm-admin" class="w-4 h-4 text-green-600 border-slate-300 rounded focus:ring-green-500">
                        </div>
                    </div>
                    <div class="space-y-2">
                        <label class="text-xs text-slate-500 uppercase font-bold">View</label>
                        <div class="flex items-center gap-2 py-2">
                            <input type="checkbox" id="perm-view" class="w-4 h-4 text-green-600 border-slate-300 rounded focus:ring-green-500">
                        </div>
                    </div>
                    <div class="space-y-2">
                        <label class="text-xs text-slate-500 uppercase font-bold">Edit</label>
                        <div class="flex items-center gap-2 py-2">
                            <input type="checkbox" id="perm-edit" class="w-4 h-4 text-green-600 border-slate-300 rounded focus:ring-green-500">
                        </div>
                    </div>
                    <div class="space-y-2">
                        <label class="text-xs text-slate-500 uppercase font-bold">Hypervisor</label>
                        <div class="flex items-center gap-2 py-2">
                            <input type="checkbox" id="perm-pxmx" class="w-4 h-4 text-green-600 border-slate-300 rounded focus:ring-green-500">
                        </div>
                    </div>
                    <div class="space-y-2">
                        <label class="text-xs text-slate-500 uppercase font-bold">Firewall</label>
                        <div class="flex items-center gap-2 py-2">
                            <input type="checkbox" id="perm-firewall" class="w-4 h-4 text-green-600 border-slate-300 rounded focus:ring-green-500">
                        </div>
                    </div>
                    <div class="space-y-2">
                        <label class="text-xs text-slate-500 uppercase font-bold">DNS</label>
                        <div class="flex items-center gap-2 py-2">
                            <input type="checkbox" id="perm-dns" class="w-4 h-4 text-green-600 border-slate-300 rounded focus:ring-green-500">
                        </div>
                    </div>
                    <div class="space-y-2">
                        <label class="text-xs text-slate-500 uppercase font-bold">DHCP</label>
                        <div class="flex items-center gap-2 py-2">
                            <input type="checkbox" id="perm-dhcp" class="w-4 h-4 text-green-600 border-slate-300 rounded focus:ring-green-500">
                        </div>
                    </div>
                    <div class="space-y-2">
                        <label class="text-xs text-slate-500 uppercase font-bold">Security/NAC</label>
                        <div class="flex items-center gap-2 py-2">
                            <input type="checkbox" id="perm-security" class="w-4 h-4 text-green-600 border-slate-300 rounded focus:ring-green-500">
                        </div>
                    </div>
                </div>
            </div>
            <div class="px-6 py-4 bg-slate-50 border-t border-slate-200 flex justify-end gap-3">
                <button onclick="closeAddUserModal()" class="px-4 py-2 text-sm font-medium text-slate-600 hover:text-slate-800 transition-colors">Cancel</button>
                <button onclick="saveUser()" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm">Create User</button>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
}

function closeAddUserModal() {
    const modal = document.getElementById('add-user-modal');
    if (modal) modal.remove();
}

async function saveUser() {
    const userId = document.getElementById('new-user-id').value.trim();
    if (!userId) {
        alert('Please enter a User ID');
        return;
    }

    const permissions = {
        admin: document.getElementById('perm-admin').checked,
        view: document.getElementById('perm-view').checked,
        edit: document.getElementById('perm-edit').checked,
        pxmx: document.getElementById('perm-pxmx').checked,
        firewall: document.getElementById('perm-firewall').checked,
        dns: document.getElementById('perm-dns').checked,
        dhcp: document.getElementById('perm-dhcp').checked,
        security: document.getElementById('perm-security').checked,
    };

    try {
        const response = await fetch('/setup/users', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ user_id: userId, permissions: permissions })
        });
        if (response.ok) {
            alert('User created successfully');
            closeAddUserModal();
            await loadUsers();
        } else {
            alert('Failed to create user');
        }
    } catch (err) {
        alert('Error creating user: ' + err.message);
    }
}

async function loadOpnsenseManagement() {
    const container = document.getElementById('opn-table-container');
    if (!container) return;

    const subMenu = currentSubView;
    if (subMenu === 'Configuration') return;

    container.innerHTML = `<div class="py-12 text-center text-slate-400 animate-pulse">Fetching ${subMenu} data...</div>`;

    try {
        let endpoint = '';
        const fwId = activeFirewallId;
        if (subMenu === 'Firewall Rules') endpoint = `/api/firewall/${fwId}/rules`;
        else if (subMenu === 'DHCP Leases') endpoint = `/api/firewall/${fwId}/dhcp`;
        else if (subMenu === 'Interfaces') endpoint = `/api/firewall/${fwId}/interfaces`;
        else if (subMenu === 'NAT Policies') endpoint = `/api/firewall/${fwId}/nat`;
        else if (subMenu === 'DNS Records') endpoint = `/api/firewall/${fwId}/dns`;
        else {
            console.log(`[OPNsense] No endpoint defined for subMenu: ${subMenu}`);
            return;
        }

        console.log(`[OPNsense-Debug] Fetching ${subMenu} from ${endpoint}...`);
        const response = await fetch(endpoint);
        console.log(`[OPNsense-Debug] Response status: ${response.status} ${response.statusText}`);
        if (!response.ok) {
            let errorMessage = `Failed to fetch ${subMenu}: ${response.status} ${response.statusText}`;
            try {
                const errorData = await response.json();
                if (errorData.detail) errorMessage = errorData.detail;
                else if (errorData.message) errorMessage = errorData.message;
            } catch (e) {
                // fallback to default
            }
            throw new Error(errorMessage);
        }

        const data = await response.json();
        console.log(`[OPNsense-Debug] Received raw data for ${subMenu}:`, data);
        console.log(`[OPNsense-Debug] Data keys:`, Object.keys(data));

        // Robust item extraction
        let items = [];
        if (Array.isArray(data)) {
            console.log(`[OPNsense-Debug] Data is an array, using as items.`);
            items = data;
        } else if (data && typeof data === 'object') {
            if (Array.isArray(data.data)) {
                console.log(`[OPNsense-Debug] Found items in data.data`);
                items = data.data;
            } else if (Array.isArray(data.payload?.data)) {
                console.log(`[OPNsense-Debug] Found items in data.payload.data`);
                items = data.payload.data;
            } else if (data.rows && Array.isArray(data.rows)) {
                console.log(`[OPNsense-Debug] Found items in data.rows`);
                items = data.rows;
            } else {
                console.log(`[OPNsense-Debug] No known item arrays found in data object. Keys were:`, Object.keys(data));
            }
        } else {
            console.log(`[OPNsense-Debug] Data is neither array nor object:`, typeof data);
        }
        console.log(`[OPNsense-Debug] Processed items for ${subMenu} (count: ${items.length}):`, items);

        let finalItems = items;

        if (!finalItems || finalItems.length === 0) {
            container.innerHTML = `<div class="py-12 text-center text-slate-400 italic">No ${subMenu} found.</div>`;
            return;
        }

        // Generic Table Renderer
        const firstItem = finalItems[0] || {};
        let keys = Object.keys(firstItem).filter(k => !k.toLowerCase().includes('hit'));

        if (subMenu === 'Firewall Rules') {
            // Use specialized columns for firewall rules to hide ID and ensure Source is present
            keys = ['source', 'destination', 'protocol', 'action', 'description'].filter(k => k in firstItem || true);
        }

        const hiddenRules = JSON.parse(localStorage.getItem('lm_hidden_firewall_rules') || '[]');
        let filteredItems = finalItems;
        if (subMenu === 'Firewall Rules') {
            filteredItems = finalItems.filter(item => {
                const id = item.id || JSON.stringify(item);
                const isHidden = hiddenRules.includes(id);
                return showHiddenOnlyFirewallRules ? isHidden : !isHidden;
            });
        }

        const headers = keys.map(k => `<th class="px-4 py-3">${k.toUpperCase().replace('_', ' ')}</th>`).join('');
        const rows = filteredItems.map(item => {
            const ruleId = item.id || JSON.stringify(item);
            return `
                <tr class="hover:bg-slate-50 transition-colors">
                    ${keys.map(k => {
                        const val = item[k] !== undefined ? item[k] : '-';
                        if (k === 'action' && typeof val === 'string') {
                            const color = val === 'pass' ? 'bg-green-100 text-green-600' : 'bg-red-100 text-red-600';
                            return `<td class="px-4 py-3"><span class="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase ${color}">${val}</span></td>`;
                        }
                        return `<td class="px-4 py-3 text-slate-600 font-mono text-xs">${val}</td>`;
                    }).join('')}
                    <td class="px-4 py-3 text-center">
                        <label class="flex items-center justify-center cursor-pointer">
                            <input type="checkbox"
                                   data-rule-id="${ruleId.replace(/"/g, '&quot;')}"
                                   onchange="toggleFirewallRuleVisibility(this.dataset.ruleId, this.checked)"
                                   ${hiddenRules.includes(ruleId) ? 'checked' : ''}
                                   class="w-4 h-4 text-green-600 border-slate-300 rounded focus:ring-green-500">
                        </label>
                    </td>
                </tr>
            `;
        }).join('');

        let footerHtml = '';
        if (subMenu === 'Firewall Rules' && hiddenRules.length > 0) {
            footerHtml = `
                <div class="pt-4 flex justify-between items-center">
                    <div class="flex items-center gap-4">
                        <span class="text-xs text-slate-400">${hiddenRules.length} rules hidden</span>
                        <button onclick="toggleHiddenFirewallRules()" class="text-xs font-medium text-blue-600 hover:text-blue-800 transition-colors">
                            ${showHiddenOnlyFirewallRules ? 'Show All' : 'View Hidden'}
                        </button>
                    </div>
                    <button onclick="unhideAllFirewallRules()" class="text-xs font-medium text-blue-600 hover:text-blue-800 transition-colors">
                        Unhide All Rules
                    </button>
                </div>
            `;
        }

        container.innerHTML = `
            <div class="space-y-4">
                <div class="overflow-hidden rounded-md border border-slate-200 bg-white">
                    <table class="w-full text-left text-sm">
                        <thead class="bg-slate-100 text-slate-600 uppercase text-xs">
                            <tr>${headers}<th class="px-4 py-3 text-center">Hide</th></tr>
                        </thead>
                        <tbody class="divide-y divide-slate-200">
                            ${rows}
                        </tbody>
                    </table>
                </div>
                ${footerHtml}
            </div>
        `;
    } catch (err) {
        console.error(`[OPNsense] Error in loadOpnsenseManagement:`, err);
        container.innerHTML = `<div class="py-12 text-center text-red-500 font-medium">Error loading ${subMenu}: ${err.message}</div>`;
    }
}


function setTheme(theme) {
    document.body.classList.remove('lcars-theme', 'sw-theme', 'cicada-theme', 'gl-theme');
    if (theme === 'lcars') {
        document.body.classList.add('lcars-theme');
    } else if (theme === 'sw') {
        document.body.classList.add('sw-theme');
    } else if (theme === 'cicada') {
        document.body.classList.add('cicada-theme');
    } else if (theme === 'gl') {
        document.body.classList.add('gl-theme');
    }
    localStorage.setItem('lm_theme', theme);
}

async function refreshOpnsenseCache() {
    try {
        const fwId = activeFirewallId;
        if (!fwId) {
            alert('No active firewall selected to refresh.');
            return;
        }
        const response = await fetch(`/api/firewall/${fwId}/refresh`);
        if (!response.ok) throw new Error('Failed to refresh firewall cache');
        const data = await response.json();
        alert(data.message || 'Firewall cache refreshed successfully!');
        console.log('Firewall cache refresh result:', data);

        // If we are currently viewing OPNsense management, reload the data
        if (currentView === 'opnsense' && currentSubView !== 'Configuration') {
            loadOpnsenseManagement();
        }
    } catch (err) {
        alert('Error refreshing firewall cache: ' + err.message);
        console.error('Error refreshing firewall cache:', err);
    }
}

function toggleFirewallRuleVisibility(ruleId, isHidden) {
    let hiddenRules = JSON.parse(localStorage.getItem('lm_hidden_firewall_rules') || '[]');
    if (isHidden) {
        if (!hiddenRules.includes(ruleId)) {
            hiddenRules.push(ruleId);
        }
    } else {
        hiddenRules = hiddenRules.filter(id => id !== ruleId);
    }
    localStorage.setItem('lm_hidden_firewall_rules', JSON.stringify(hiddenRules));
    loadOpnsenseManagement();
}

function toggleHiddenFirewallRules() {
    showHiddenOnlyFirewallRules = !showHiddenOnlyFirewallRules;
    loadOpnsenseManagement();
}

function unhideAllFirewallRules() {
    localStorage.removeItem('lm_hidden_firewall_rules');
    loadOpnsenseManagement();
}

async function loadDiagnostics() {
    const container = document.getElementById('diag-container');
    const spokeSelector = document.getElementById('probe-spoke-selector');
    if (!container) return;

    container.innerHTML = `<div class="py-12 text-center text-slate-400 animate-pulse">Fetching spoke telemetry...</div>`;

    try {
        const response = await fetch('/setup/diagnostics');
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        const data = await response.json();
        const spokes = data.spokes || [];

        if (spokeSelector) {
            spokeSelector.innerHTML = '<option value="">Select Spoke...</option>' +
                spokes.map(s => `<option value="${s.spoke_id}">${s.spoke_id}</option>`).join('');
        }

        if (spokes.length === 0) {
            container.innerHTML = `<div class="py-12 text-center text-slate-400 italic">No spoke telemetry available.</div>`;
            return;
        }

        container.innerHTML = `
            <div class="overflow-hidden rounded-md border border-slate-200 bg-white">
                <table class="w-full text-left text-sm">
                    <thead class="bg-slate-100 text-slate-600 uppercase text-xs">
                        <tr>
                            <th class="px-4 py-3 font-bold">Spoke ID</th>
                            <th class="px-4 py-3 font-bold">Auth</th>
                            <th class="px-4 py-3 font-bold">Approved</th>
                            <th class="px-4 py-3 font-bold">State</th>
                            <th class="px-4 py-3 font-bold">Last Status</th>
                            <th class="px-4 py-3 font-bold">Error</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-slate-200">
                        ${spokes.map(s => `
                            <tr class="hover:bg-slate-50 transition-colors">
                                <td class="px-4 py-3 font-mono text-xs text-slate-700">${s.spoke_id}</td>
                                <td class="px-4 py-3">
                                    <span class="text-[10px] px-2 py-0.5 rounded-full font-bold uppercase ${s.authenticated ? 'bg-green-100 text-green-600' : 'bg-red-100 text-red-600'}">
                                        ${s.authenticated ? 'Yes' : 'No'}
                                    </span>
                                </td>
                                <td class="px-4 py-3">
                                    <span class="text-[10px] px-2 py-0.5 rounded-full font-bold uppercase ${s.approved ? 'bg-green-100 text-green-600' : 'bg-yellow-100 text-yellow-600'}">
                                        ${s.approved ? 'Yes' : 'Pending'}
                                    </span>
                                </td>
                                <td class="px-4 py-3 text-slate-600 font-mono text-xs">${s.connection_state}</td>
                                <td class="px-4 py-3 text-slate-600 text-xs">${s.last_status || '-'}</td>
                                <td class="px-4 py-3 text-red-500 text-xs">${s.last_error || '-'}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        `;
    } catch (err) {
        container.innerHTML = `<div class="py-12 text-center text-red-500 font-medium">Error loading diagnostics: ${err.message}</div>`;
    }
}

async function updateAppearance() {
    const config = {
        primary_color: document.getElementById('app-primary-color').value,
        navy_color: document.getElementById('app-navy-color').value,
        logo_url: document.getElementById('app-logo-url').value,
        logo_url_right: document.getElementById('app-logo-url-right').value,
        show_logo_left: document.getElementById('app-show-logo-left').checked,
        show_logo_right: document.getElementById('app-show-logo-right').checked,
    };

    document.getElementById('app-primary-hex').value = config.primary_color;
    document.getElementById('app-navy-hex').value = config.navy_color;

    try {
        const response = await fetch('/setup/appearance', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ config })
        });
        if (response.ok) {
            applyAppearance(config);
        }
    } catch (err) {
        console.error('Failed to update appearance', err);
    }
}

function renderLogo(config, side) {
    return; // Disabled logo rendering
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
    renderLogo(config, 'right');
}

async function loadModuleLogs(module, isRefresh = false) {
    const container = document.getElementById('system-logs-container');
    if (!container) return;

    if (!isRefresh) {
        container.innerHTML = `<div class="py-12 text-center text-slate-400 animate-pulse">Fetching ${module} logs...</div>`;
    }

    try {
        const endpoint = module === 'hub' ? '/setup/logs' : `/setup/logs/${module}`;
        const response = await fetch(endpoint);
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        const data = await response.json();
        const logs = data.logs || [];

        if (logs.length === 0) {
            container.innerHTML = `<div class="py-12 text-center text-slate-400 italic">No logs available for ${module}.</div>`;
            return;
        }

        container.innerHTML = logs.map(log => `
            <div class="px-4 py-1 border-b border-slate-100 text-xs font-mono text-slate-600 hover:bg-slate-50">
                ${log}
            </div>
        `).join('');

        container.scrollTop = container.scrollHeight;
    } catch (err) {
        console.error(`Error loading ${module} logs:`, err);
        if (!isRefresh) {
            container.innerHTML = `<div class="py-12 text-center text-red-500 font-medium">Error loading ${module} logs: ${err.message}</div>`;
        }
    }
}

async function copyLogs() {
    const container = document.getElementById('system-logs-container');
    if (!container) return;

    const text = container.innerText;
    try {
        await navigator.clipboard.writeText(text);
        alert('Logs copied to clipboard!');
    } catch (err) {
        alert('Failed to copy logs: ' + err.message);
    }
}

async function loadSystemLogs() {
    await loadModuleLogs('hub');
}

async function loadAppearance() {
    try {
        const response = await fetch('/setup/appearance');
        if (!response.ok) return;
        const data = await response.json();
        const config = data.config;

        if (document.getElementById('app-primary-color')) {
            document.getElementById('app-primary-color').value = config.primary_color;
            document.getElementById('app-primary-hex').value = config.primary_color;
            document.getElementById('app-navy-color').value = config.navy_color;
            document.getElementById('app-navy-hex').value = config.navy_color;
            document.getElementById('app-logo-url').value = config.logo_url;
            document.getElementById('app-logo-url-right').value = config.logo_url_right || config.logo_url;
            document.getElementById('app-show-logo-left').checked = false; // Forced to false
            document.getElementById('app-show-logo-right').checked = false; // Forced to false
        }
        applyAppearance(config);
    } catch (err) {
        console.error('Failed to load appearance', err);
    }
}

async function loadPendingSpokes() {
    console.log('Loading spoke statuses...');
    const listEl = document.getElementById('pending-spokes-list');
    if (!listEl) {
        console.error('Could not find pending-spokes-list element');
        return;
    }

    try {
        const response = await fetch('/setup/pending_spokes');
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        const data = await response.json();
        const spokes = data.spokes || [];

        console.log(`Found ${spokes.length} known spokes:`, spokes);

        if (spokes.length === 0) {
            listEl.innerHTML = `<div class="py-12 text-center text-slate-400 italic">No spokes have attempted to connect yet.</div>`;
            return;
        }

        listEl.innerHTML = `
            <div class="overflow-hidden rounded-md border border-slate-200 bg-white">
                <table class="w-full text-left text-sm">
                    <thead class="bg-slate-100 text-slate-600 uppercase text-xs">
                        <tr>
                            <th class="px-4 py-3 font-bold">Spoke Name / ID</th>
                            <th class="px-4 py-3 font-bold">Status</th>
                            <th class="px-4 py-3 font-bold text-right">Actions</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-slate-200">
                        ${spokes.map(spoke => {
                            const sid = spoke.spoke_id;
                            const name = spoke.display_name || sid;
                            const isApproved = spoke.approved;
                            return `
                                <tr class="hover:bg-slate-50 transition-colors">
                                    <td class="px-4 py-3">
                                        <div class="flex items-center gap-3">
                                            <div class="w-2 h-2 rounded-full ${isApproved ? 'bg-green-500 shadow-[0_0_8px_rgba(34,197,94,0.6)]' : 'bg-yellow-500 shadow-[0_0_8px_rgba(234,179,8,0.6)]'}"></div>
                                            <div class="flex flex-col">
                                                <span class="font-medium text-slate-700">${name}</span>
                                                <span class="text-[10px] font-mono text-slate-400">${sid}</span>
                                            </div>
                                        </div>
                                    </td>
                                    <td class="px-4 py-3">
                                        <span class="text-[10px] px-2 py-0.5 rounded-full font-bold uppercase ${isApproved ? 'bg-green-100 text-green-600' : 'bg-yellow-100 text-yellow-600'}">
                                            ${isApproved ? 'Approved' : 'Pending'}
                                        </span>
                                    </td>
                                    <td class="px-4 py-3 text-right flex justify-end gap-2">
                                        <button onclick="openSpokeMetadataModal('${sid}', '${name}')" class="text-slate-400 hover:text-slate-600 p-1 transition-colors" title="Edit Spoke Metadata">
                                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9"></path></svg>
                                        </button>
                                        ${!isApproved ? `
                                            <button onclick="approveSpoke('${sid}')" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-1 rounded text-xs font-bold transition-colors">
                                                Approve
                                            </button>
                                        ` : `
                                            <button onclick="unapproveSpoke('${sid}')" class="bg-red-50 hover:bg-red-100 text-red-600 border border-red-200 px-4 py-1 rounded text-xs font-bold transition-colors">
                                                Un-approve
                                            </button>
                                        `}
                                    </td>
                                </tr>
                            `;
                        }).join('')}
                    </tbody>
                </table>
            </div>
        `;
    } catch (err) {
        console.error('Error in loadPendingSpokes:', err);
        listEl.innerHTML = `<div class="py-12 text-center text-red-500 font-medium">Error loading spoke statuses: ${err.message}</div>`;
    }
}

async function openSpokeMetadataModal(spokeId, currentName) {
    const modal = document.createElement('div');
    modal.id = 'spoke-metadata-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm';

    let description = '';
    try {
        const res = await fetch(`/setup/spoke-metadata/${spokeId}`);
        if (res.ok) {
            const data = await res.json();
            description = data.metadata.description || '';
            currentName = data.metadata.display_name || currentName;
        }
    } catch (e) {
        console.error('Error fetching spoke metadata:', e);
    }

    modal.innerHTML = `
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-md overflow-hidden">
            <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50">
                <h3 class="text-lg font-bold text-[#263040]">Spoke Metadata</h3>
                <button onclick="this.closest('#spoke-metadata-modal').remove()" class="text-slate-400 hover:text-slate-600 transition-colors">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                </button>
            </div>
            <div class="p-6 space-y-4">
                <div class="text-xs text-slate-400 font-mono mb-4">ID: ${spokeId}</div>
                <div class="space-y-2">
                    <label class="text-xs text-slate-500 uppercase font-bold">Display Name</label>
                    <input type="text" id="meta-display-name" value="${currentName}" placeholder="e.g. Core Firewall" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                </div>
                <div class="space-y-2">
                    <label class="text-xs text-slate-500 uppercase font-bold">Description</label>
                    <textarea id="meta-description" rows="3" placeholder="Describe the purpose of this spoke..." class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">${description}</textarea>
                </div>
                <div class="space-y-2">
                    <label class="text-xs text-slate-500 uppercase font-bold">System Hostname (Optional)</label>
                    <input type="text" id="meta-hostname" placeholder="e.g. opnsense-core" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                </div>
                <div class="pt-4 flex justify-end gap-3">
                    <button onclick="this.closest('#spoke-metadata-modal').remove()" class="px-4 py-2 text-sm font-medium text-slate-600 hover:text-slate-800">Cancel</button>
                    <button onclick="saveSpokeMetadata('${spokeId}')" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm">
                        Save Changes
                    </button>
                </div>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
}

async function saveSpokeMetadata(spokeId) {
    const displayName = document.getElementById('meta-display-name').value;
    const description = document.getElementById('meta-description').value;
    const hostname = document.getElementById('meta-hostname').value;

    try {
        const response = await fetch('/setup/spoke-metadata', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                spoke_id: spokeId,
                metadata: {
                    display_name: displayName,
                    description: description
                }
            })
        });
        if (!response.ok) throw new Error('Failed to save metadata');

        // If hostname was provided, we also call the existing renameSpoke endpoint for the system update
        if (hostname) {
            await fetch('/setup/spoke-name', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    spoke_id: spokeId,
                    display_name: displayName,
                    hostname: hostname
                })
            });
        }

        alert('Spoke metadata updated successfully.');
        document.getElementById('spoke-metadata-modal').remove();
        await loadPendingSpokes();
        updateStatus();
    } catch (err) {
        alert('Error updating metadata: ' + err.message);
    }
}

async function approveSpoke(spokeId) {
    try {
        const response = await fetch('/setup/approve_spoke', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ spoke_id: spokeId, action: 'approve' })
        });
        if (!response.ok) throw new Error('Approval failed');

        await loadPendingSpokes();
        updateStatus();
    } catch (err) {
        alert('Error approving spoke: ' + err.message);
    }
}

async function unapproveSpoke(spokeId) {
    try {
        const response = await fetch('/setup/approve_spoke', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ spoke_id: spokeId, action: 'unapprove' })
        });
        if (!response.ok) throw new Error('Un-approval failed');

        await loadPendingSpokes();
        updateStatus();
    } catch (err) {
        alert('Error un-approving spoke: ' + err.message);
    }
}

async function executeProbe() {
    const spokeId = document.getElementById('probe-spoke-selector').value;
    const path = document.getElementById('probe-path').value;
    const responseEl = document.getElementById('probe-response');

    if (!spokeId || !path) {
        alert('Please select a spoke and enter a path');
        return;
    }

    responseEl.textContent = 'Probing...';
    try {
        const res = await fetch(`/setup/api-probe?spoke_id=${spokeId}&path=${encodeURIComponent(path)}`);
        const data = await res.json();
        responseEl.textContent = JSON.stringify(data, null, 2);
    } catch (err) {
        responseEl.textContent = `Error: ${err.message}`;
    }
}

function updateQuickPaths() {
    const spokeId = document.getElementById('probe-spoke-selector').value;
    const container = document.getElementById('probe-quick-paths');
    if (!container) return;

    const paths = {
        'opn': ['/api/unbound/overrides', '/api/unbound/dns', '/api/firewall/rules', '/api/interfaces'],
        'pxmx': ['/api/vms', '/api/nodes', '/api/storage'],
        'cppm': ['/api/policies', '/api/endpoints', '/api/health'],
        'cs': ['/api/simulations', '/api/profiles'],
        'default': ['/api/health', '/api/status']
    };

    let type = 'default';
    if (spokeId.includes('opn')) type = 'opn';
    else if (spokeId.includes('pxmx')) type = 'pxmx';
    else if (spokeId.includes('cppm')) type = 'cppm';
    else if (spokeId.includes('cs')) type = 'cs';

    const selectedPaths = paths[type];
    container.innerHTML = selectedPaths.map(p => `
        <button onclick="setProbePath('${p}')" class="text-[10px] bg-slate-100 border border-slate-200 px-2 py-1 rounded hover:bg-slate-200 transition-colors text-slate-600 font-medium">
            ${p}
        </button>
    `).join('');
}

function setProbePath(path) {
    document.getElementById('probe-path').value = path;
    executeProbe();
}

async function setActiveFirewall(id) {
    activeFirewallId = id;
    console.log(`Active firewall switched to: ${id}`);
    setView(currentView);
}

async function loadApprovedSpokes() {
    try {
        const response = await fetch('/setup/pending_spokes');
        if (!response.ok) throw new Error('Failed to fetch spokes');
        const data = await response.json();
        return (data.spokes || []).filter(s => s.approved);
    } catch (err) {
        console.error('Error loading approved spokes:', err);
        return [];
    }
}

function showAddFirewallModal() {
    const modal = document.createElement('div');
    modal.id = 'firewall-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm';
    modal.innerHTML = `
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-md overflow-hidden">
            <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50">
                <h3 class="text-lg font-bold text-[#263040]" id="fw-modal-title">Add New Firewall</h3>
                <button onclick="closeFirewallModal()" class="text-slate-400 hover:text-slate-600 transition-colors">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                </button>
            </div>
            <div class="p-6 space-y-4">
                <div class="space-y-2">
                    <label class="text-xs text-slate-500 uppercase font-bold">Firewall Name</label>
                    <input type="text" id="fw-name" placeholder="e.g. Core Firewall" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                </div>
                <div class="grid grid-cols-2 gap-4">
                    <div class="space-y-2">
                        <label class="text-xs text-slate-500 uppercase font-bold">Model</label>
                        <select id="fw-model" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                            <option value="opnsense">OPNsense</option>
                            <option value="juniper">Juniper</option>
                            <option value="fortigate">Fortigate</option>
                            <option value="pfsense">pfSense</option>
                        </select>
                    </div>
                    <div class="space-y-2">
                        <label class="text-xs text-slate-500 uppercase font-bold">Associated Spoke</label>
                        <select id="fw-spoke" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                            <option value="">Loading spokes...</option>
                        </select>
                    </div>
                </div>
                <div class="grid grid-cols-2 gap-4">
                    <div class="space-y-2">
                        <label class="text-xs text-slate-500 uppercase font-bold flex items-center gap-1">Host/IP <span onclick="showHelp('firewall-config')" class="cursor-pointer inline-block text-slate-400 hover:text-green-500 transition-colors" title="Help">ⓘ</span></label>
                        <input type="text" id="fw-host" placeholder="172.16.1.1" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                    </div>
                    <div class="space-y-2">
                        <label class="text-xs text-slate-500 uppercase font-bold flex items-center gap-1">Port <span onclick="showHelp('firewall-config')" class="cursor-pointer inline-block text-slate-400 hover:text-green-500 transition-colors" title="Help">ⓘ</span></label>
                        <input type="text" id="fw-port" placeholder="8443" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                    </div>
                </div>
                <div class="space-y-2">
                    <label class="text-xs text-slate-500 uppercase font-bold flex items-center gap-1">API Key <span onclick="showHelp('firewall-config')" class="cursor-pointer inline-block text-slate-400 hover:text-green-500 transition-colors" title="Help">ⓘ</span></label>
                    <input type="text" id="fw-api-key" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                </div>
                <div class="space-y-2">
                    <label class="text-xs text-slate-500 uppercase font-bold flex items-center gap-1">API Secret <span onclick="showHelp('firewall-config')" class="cursor-pointer inline-block text-slate-400 hover:text-green-500 transition-colors" title="Help">ⓘ</span></label>
                    <input type="password" id="fw-api-secret" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                </div>
            </div>
            <div class="px-6 py-4 bg-slate-50 border-t border-slate-200 flex justify-end gap-3">
                <button onclick="closeFirewallModal()" class="px-4 py-2 text-sm font-medium text-slate-600 hover:text-slate-800 transition-colors">Cancel</button>
                <button onclick="saveFirewall()" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm">Save Firewall</button>
            </div>
        </div>
    `;
    document.body.appendChild(modal);

    // Populate spoke selector
    loadApprovedSpokes().then(spokes => {
        const selector = document.getElementById('fw-spoke');
        if (selector) {
            selector.innerHTML = spokes.length > 0
                ? spokes.map(s => `<option value="${s.spoke_id}">${s.spoke_id}</option>`).join('')
                : '<option value="">No approved spokes found</option>';
        }
    });
}

async function editFirewall(id) {
    const firewalls = await loadFirewalls();
    const fw = firewalls.find(f => f.id === id);
    if (!fw) return;

    showAddFirewallModal();
    document.getElementById('fw-modal-title').textContent = 'Edit Firewall';
    document.getElementById('fw-name').value = fw.name;
    document.getElementById('fw-model').value = fw.model;
    document.getElementById('fw-host').value = fw.host;
    document.getElementById('fw-port').value = fw.port;
    document.getElementById('fw-api-key').value = fw.api_key;
    document.getElementById('fw-api-secret').value = fw.api_secret;

    // Wait for the spoke selector to be populated and then set value
    setTimeout(() => {
        const selector = document.getElementById('fw-spoke');
        if (selector) selector.value = fw.spoke_id || '';
    }, 100);

    document.getElementById('firewall-modal').dataset.firewallId = id;
}

async function deleteFirewall(id) {
    if (!confirm('Are you sure you want to delete this firewall?')) return;
    try {
        const response = await fetch(`/setup/firewalls/${id}`, { method: 'DELETE' });
        if (response.ok) {
            alert('Firewall deleted successfully');
            setView(currentView);
        } else {
            alert('Failed to delete firewall');
        }
    } catch (err) {
        alert('Error deleting firewall: ' + err.message);
    }
}

async function saveFirewall() {
    const modal = document.getElementById('firewall-modal');
    const id = modal.dataset.firewallId;
    const config = {
        name: document.getElementById('fw-name').value,
        model: document.getElementById('fw-model').value,
        spoke_id: document.getElementById('fw-spoke').value,
        host: document.getElementById('fw-host').value,
        port: parseInt(document.getElementById('fw-port').value) || 8443,
        api_key: document.getElementById('fw-api-key').value,
        api_secret: document.getElementById('fw-api-secret').value,
    };

    try {
        const method = id ? 'PUT' : 'POST';
        const url = id ? `/setup/firewalls/${id}` : '/setup/firewalls';
        const payload = id ? { config: config } : { firewall: config };
        const response = await fetch(url, {
            method: method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        if (response.ok) {
            alert(`Firewall ${id ? 'updated' : 'added'} successfully!`);
            closeFirewallModal();
            setView(currentView);
        } else {
            alert('Failed to save firewall configuration');
        }
    } catch (err) {
        alert('Error saving firewall: ' + err.message);
    }
}

function closeFirewallModal() {
    const modal = document.getElementById('firewall-modal');
    if (modal) modal.remove();
}


async function loadGenericAgents() {
    const bodyEl = document.getElementById('generic-agents-body');
    if (!bodyEl) return;

    try {
        const response = await fetch('/setup/diagnostics');
        if (!response.ok) throw new Error('Failed to fetch diagnostics');
        const data = await response.json();
        const spokes = data.spokes || [];

        // Filter for agents (this is a simple heuristic, might need a better way if roles aren't clearly defined)
        const agents = spokes.filter(s => s.spoke_id.includes('generic'));

        if (agents.length === 0) {
            bodyEl.innerHTML = `<tr><td colspan="4" class="px-4 py-8 text-center text-slate-400 italic">No generic agents found.</td></tr>`;
            return;
        }

        bodyEl.innerHTML = agents.map(agent => `
            <tr class="hover:bg-slate-50 transition-colors">
                <td class="px-4 py-3 font-mono text-xs text-slate-700">${agent.spoke_id}</td>
                <td class="px-4 py-3">
                    <span class="px-2 py-0.5 rounded-full text-[10px] font-bold ${agent.authenticated ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}">
                        ${agent.authenticated ? 'Online' : 'Offline'}
                    </span>
                </td>
                <td class="px-4 py-3 text-xs text-slate-500">${agent.last_error ? 'Error' : 'OK'}</td>
                <td class="px-4 py-3 text-right">
                    <button onclick="showProvisionModal('${agent.spoke_id}')" class="text-xs font-bold text-[#01A982] hover:text-[#008c6a] transition-colors">Provision</button>
                </td>
            </tr>
        `).join('');
    } catch (err) {
        console.error('Error loading generic agents:', err);
        bodyEl.innerHTML = `<tr><td colspan="4" class="px-4 py-8 text-center text-red-500 italic">Error loading agents: ${err.message}</td></tr>`;
    }
}

function showProvisionModal(agentId = '') {
    const modal = document.createElement('div');
    modal.id = 'provision-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50 backdrop-blur-sm p-4';
    modal.innerHTML = `
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-md overflow-hidden border border-slate-200 animate-in fade-in zoom-in duration-200">
            <div class="px-6 py-4 bg-slate-50 border-b border-slate-200 flex justify-between items-center">
                <h3 class="text-lg font-bold text-slate-800">Provision Module</h3>
                <button onclick="closeProvisionModal()" class="text-slate-400 hover:text-slate-600 transition-colors">
                    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                </button>
            </div>
            <div class="p-6 space-y-4">
                <div class="space-y-2">
                    <label class="text-xs text-slate-500 uppercase font-bold">Target Agent ID</label>
                    <input type="text" id="prov-agent-id" value="${agentId}" placeholder="e.g. generic-agent-1" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                </div>
                <div class="space-y-2">
                    <label class="text-xs text-slate-500 uppercase font-bold">Module to Install</label>
                    <select id="prov-module-id" onchange="updateProvisionRepo(this.value)" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                        <option value="">-- Select a Module --</option>
                        ${Object.entries(PROVISIONABLE_MODULES).map(([id, info]) => `
                            <option value="${id}">${info.name}</option>
                        `).join('')}
                        <option value="custom">Custom Repository...</option>
                    </select>
                </div>
                <div class="space-y-2">
                    <label class="text-xs text-slate-500 uppercase font-bold">Repository URL</label>
                    <input type="text" id="prov-repo-url" placeholder="https://github.com/..." class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                </div>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4 p-3 bg-slate-50 rounded-lg border border-slate-200">
                    <div class="space-y-2">
                        <label class="text-xs text-slate-400 uppercase font-bold">Custom Spoke ID</label>
                        <input type="text" id="prov-spoke-id" placeholder="e.g. ldap-prod-1" class="w-full bg-white border border-slate-300 rounded-md px-3 py-1.5 text-xs outline-none focus:ring-2 focus:ring-green-500">
                    </div>
                    <div class="space-y-2">
                        <label class="text-xs text-slate-400 uppercase font-bold">Display Name</label>
                        <input type="text" id="prov-display-name" placeholder="e.g. Main LDAP Server" class="w-full bg-white border border-slate-300 rounded-md px-3 py-1.5 text-xs outline-none focus:ring-2 focus:ring-green-500">
                    </div>
                </div>
            </div>
            <div class="px-6 py-4 bg-slate-50 border-t border-slate-200 flex justify-end gap-3">
                <button onclick="closeProvisionModal()" class="px-4 py-2 text-sm font-medium text-slate-600 hover:text-slate-800 transition-colors">Cancel</button>
                <button onclick="provisionModule()" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm">Provision</button>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
}

function updateProvisionRepo(moduleId) {
    const repoInput = document.getElementById('prov-repo-url');
    if (moduleId === 'custom') {
        repoInput.disabled = false;
        repoInput.value = '';
        repoInput.placeholder = 'Enter custom repository URL...';
    } else if (PROVISIONABLE_MODULES[moduleId]) {
        repoInput.value = PROVISIONABLE_MODULES[moduleId].repo;
        repoInput.disabled = true;
        repoInput.placeholder = 'Automatic repo for ' + PROVISIONABLE_MODULES[moduleId].name;
    } else {
        repoInput.disabled = true;
        repoInput.value = '';
    }
}


function closeProvisionModal() {
    const modal = document.getElementById('provision-modal');
    if (modal) modal.remove();
}

async function provisionModule() {
    const agent_id = document.getElementById('prov-agent-id').value.trim();
    const module_id = document.getElementById('prov-module-id').value.trim();
    const repo_url = document.getElementById('prov-repo-url').value.trim();
    const spoke_id = document.getElementById('prov-spoke-id').value.trim();
    const display_name = document.getElementById('prov-display-name').value.trim();

    if (!agent_id || !module_id || !repo_url) {
        alert('Please fill in all required fields');
        return;
    }

    try {
        const response = await fetch('/api/generic/provision', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ agent_id, module_id, repo_url, spoke_id, display_name })
        });
        const data = await response.json();
        if (response.ok) {
            alert('Provisioning request sent successfully! The module will be installed in the background.');
            closeProvisionModal();
        } else {
            alert('Provisioning failed: ' + (data.detail || 'Unknown error'));
        }
    } catch (err) {
        alert('Error triggering provisioning: ' + err.message);
    }
}

async function showHelp(section) {
    try {
        const response = await fetch(`/setup/docs/${section}`);
        if (!response.ok) throw new Error('Help section not found');
        const data = await response.json();
        const content = data.content || 'No documentation available for this section.';

        const modal = document.createElement('div');
        modal.className = 'fixed inset-0 bg-slate-900/50 backdrop-blur-sm flex items-center justify-center z-[100] p-4 animate-in fade-in duration-200';
        modal.innerHTML = `
            <div class="bg-white rounded-xl shadow-2xl w-full max-w-2xl overflow-hidden border border-slate-200 flex flex-col max-h-[80vh]">
                <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50">
                    <h3 class="text-lg font-bold text-slate-800 flex items-center gap-2">
                        <svg class="w-5 h-5 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                        Help: ${section.replace(/-/g, ' ')}
                    </h3>
                    <button onclick="this.closest('.fixed').remove()" class="text-slate-400 hover:text-slate-600 transition-colors">
                        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                    </button>
                </div>
                <div class="p-6 overflow-y-auto prose prose-slate max-w-none">
                    <div class="text-sm text-slate-600 leading-relaxed whitespace-pre-wrap">${content}</div>
                </div>
                <div class="px-6 py-4 border-t border-slate-200 flex justify-end bg-slate-50">
                    <button onclick="this.closest('.fixed').remove()" class="bg-slate-200 hover:bg-slate-300 text-slate-700 px-4 py-2 rounded-md text-sm font-bold transition-all">Close</button>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
    } catch (err) {
        console.error('Error loading help:', err);
        alert('Could not load help documentation: ' + err.message);
    }
}

async function startSimulation() {
    try {
        const response = await fetch('/api/sim/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ profile: 'default' })
        });
        const data = await response.json();
        if (response.ok) {
            alert('Simulation started: ' + data.message);
            refreshSimStatus();
        } else {
            alert('Error starting simulation: ' + (data.detail || 'Unknown error'));
        }
    } catch (err) {
        alert('Request failed: ' + err.message);
    }
}

async function stopSimulation() {
    try {
        const response = await fetch('/api/sim/stop', { method: 'POST' });
        const data = await response.json();
        if (response.ok) {
            alert('Simulation stopped: ' + data.message);
            refreshSimStatus();
        } else {
            alert('Error stopping simulation: ' + (data.detail || 'Unknown error'));
        }
    } catch (err) {
        alert('Request failed: ' + err.message);
    }
}

async function refreshSimStatus() {
    const container = document.getElementById('sim-status-container');
    if (!container) return;

    try {
        const response = await fetch('/api/sim/status');
        if (!response.ok) throw new Error('Failed to fetch sim status');
        const data = await response.json();
        const status = data.data || {};
        const vms = status.vms || {};

        if (Object.keys(vms).length === 0) {
            container.innerHTML = '<p class="text-slate-400 italic">No active simulation VMs found.</p>';
            return;
        }

        container.innerHTML = `
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 w-full">
                ${Object.entries(vms).map(([vmId, info]) => `
                    <div class="p-4 rounded-md bg-slate-50 border border-slate-200 flex justify-between items-center group">
                        <div>
                            <div class="text-sm font-bold text-slate-800">${vmId}</div>
                            <div class="text-xs text-slate-500 font-mono">${info.ip || 'Unknown IP'}</div>
                        </div>
                        <div class="flex items-center gap-3">
                            <span class="text-[10px] px-2 py-0.5 rounded-full font-bold uppercase ${info.status === 'ONLINE' ? 'bg-green-100 text-green-600' : 'bg-red-100 text-red-600'}">
                                ${info.status}
                            </span>
                            <button onclick="refreshSimTelemetry('${vmId}')" class="p-1 text-blue-500 hover:text-blue-700 transition-colors" title="View Telemetry">
                                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H3m6 6v-6a2 2 0 00-2-2h-4m12 6v-6a2 2 0 00-2-2h-4M9 9V5a2 2 0 012-2h2a2 2 0 012 2v4"></path></svg>
                            </button>
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
    } catch (err) {
        container.innerHTML = `<div class="text-red-500 text-sm">Error loading status: ${err.message}</div>`;
    }
}

async function refreshSimTelemetry(vmId) {
    const container = document.getElementById('sim-telemetry-container');
    if (!container) return;

    try {
        const response = await fetch(`/api/sim/telemetry?vm_id=${vmId}`);
        if (!response.ok) throw new Error('Failed to fetch telemetry');
        const data = await response.json();
        const telemetry = data.data || {};

        container.innerHTML = `
            <div class="flex justify-between items-center mb-4">
                <h3 class="text-sm font-bold text-slate-700">Telemetry for ${vmId}</h3>
                <button onclick="setView('cs')" class="text-xs text-slate-400 hover:text-slate-600">Clear</button>
            </div>
            <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div class="p-4 rounded-md bg-slate-50 border border-slate-200">
                    <label class="text-[10px] text-slate-500 uppercase font-bold">Aruba Status</label>
                    <div class="text-lg font-bold text-slate-800">${telemetry.aruba_status || 'Unknown'}</div>
                </div>
                <div class="p-4 rounded-md bg-slate-50 border border-slate-200">
                    <label class="text-[10px] text-slate-500 uppercase font-bold">Signal Strength</label>
                    <div class="text-lg font-bold text-slate-800">${telemetry.signal_strength || 'N/A'}</div>
                </div>
                <div class="p-4 rounded-md bg-slate-50 border border-slate-200">
                    <label class="text-[10px] text-slate-500 uppercase font-bold">Last Seen</label>
                    <div class="text-lg font-bold text-slate-800">${telemetry.last_seen || 'Unknown'}</div>
                </div>
            </div>
        `;
    } catch (err) {
        container.innerHTML = `<div class="text-red-500 text-sm">Error loading telemetry: ${err.message}</div>`;
    }
}

async function refreshSimClients() {
    const bodyEl = document.getElementById('sim-clients-body');
    if (!bodyEl) return;

    try {
        const response = await fetch('/api/sim/status');
        if (!response.ok) throw new Error('Failed to fetch simulation status');
        const data = await response.json();
        const vms = data.data?.vms || {};

        if (Object.keys(vms).length === 0) {
            bodyEl.innerHTML = `<tr><td colspan="4" class="px-4 py-8 text-center text-slate-400 italic">No active simulation clients found.</td></tr>`;
            return;
        }

        bodyEl.innerHTML = Object.entries(vms).map(([vmId, info]) => `
            <tr class="hover:bg-slate-50 transition-colors">
                <td class="px-4 py-3 font-mono text-xs text-slate-700 font-medium">${vmId}</td>
                <td class="px-4 py-3 text-slate-600 font-mono text-xs">${info.ip || 'Unknown'}</td>
                <td class="px-4 py-3">
                    <span class="text-[10px] px-2 py-0.5 rounded-full font-bold uppercase ${info.status === 'ONLINE' ? 'bg-green-100 text-green-600' : 'bg-red-100 text-red-600'}">
                        ${info.status || 'UNKNOWN'}
                    </span>
                </td>
                <td class="px-4 py-3 text-right">
                    <button onclick="refreshSimTelemetry('${vmId}')" class="bg-blue-50 hover:bg-blue-100 text-blue-600 px-3 py-1 rounded text-xs font-bold transition-colors">
                        Telemetry
                    </button>
                </td>
            </tr>
        `).join('');
    } catch (err) {
        bodyEl.innerHTML = `<tr><td colspan="4" class="px-4 py-8 text-center text-red-500">${err.message}</td></tr>`;
    }
}

async function refreshVMServerStatus() {
    const container = document.getElementById('vm-server-status-container');
    if (!container) return;

    try {
        const response = await fetch('/setup/diagnostics');
        if (!response.ok) throw new Error('Failed to fetch diagnostics');
        const data = await response.json();
        const spokes = data.spokes || [];

        // Find the simulation spoke
        const csSpoke = spokes.find(s => s.spoke_id.includes('cs'));
        if (!csSpoke) {
            container.innerHTML = `<div class="py-12 text-center text-slate-400 italic col-span-3">Simulation server spoke not found or not connected.</div>`;
            return;
        }

        const statusColor = csSpoke.authenticated ? 'text-green-600' : 'text-red-600';
        const statusBg = csSpoke.authenticated ? 'bg-green-100' : 'bg-red-100';

        container.innerHTML = `
            <div class="hpe-card rounded-lg p-6 shadow-sm border border-slate-200 bg-white">
                <label class="text-[10px] text-slate-500 uppercase font-bold">Connection State</label>
                <div class="flex items-center gap-2 mt-2">
                    <div class="w-2 h-2 rounded-full ${csSpoke.authenticated ? 'bg-green-500' : 'bg-red-500'}"></div>
                    <div class="text-lg font-bold ${statusColor}">${csSpoke.connection_state || 'UNKNOWN'}</div>
                </div>
                <div class="mt-4 pt-4 border-t border-slate-100">
                    <div class="flex justify-between text-xs">
                        <span class="text-slate-500">Authenticated</span>
                        <span class="font-bold ${statusColor}">${csSpoke.authenticated ? 'YES' : 'NO'}</span>
                    </div>
                    <div class="flex justify-between text-xs mt-2">
                        <span class="text-slate-500">Approved</span>
                        <span class="font-bold ${csSpoke.approved ? 'text-green-600' : 'text-yellow-600'}">${csSpoke.approved ? 'YES' : 'PENDING'}</span>
                    </div>
                </div>
            </div>
            <div class="hpe-card rounded-lg p-6 shadow-sm border border-slate-200 bg-white">
                <label class="text-[10px] text-slate-500 uppercase font-bold">Server Health</label>
                <div class="mt-2">
                    ${csSpoke.last_error ?
                        `<div class="p-3 rounded-md bg-red-50 border border-red-100 text-red-600 text-xs font-mono">${csSpoke.last_error}</div>` :
                        `<div class="p-3 rounded-md bg-green-50 border border-green-100 text-green-600 text-xs font-medium">System Operational</div>`
                    }
                </div>
            </div>
            <div class="hpe-card rounded-lg p-6 shadow-sm border border-slate-200 bg-white">
                <label class="text-[10px] text-slate-500 uppercase font-bold">Identity</label>
                <div class="mt-2 space-y-1">
                    <div class="text-sm font-mono text-slate-800">${csSpoke.spoke_id}</div>
                    <div class="text-xs text-slate-400">Simulation Control Plane</div>
                </div>
            </div>
        `;
    } catch (err) {
        container.innerHTML = `<div class="py-12 text-center text-red-500 col-span-3">Error loading server status: ${err.message}</div>`;
    }
}
    console.log("Lab Manager UI: Initializing...");
    try {
        currentTenant = localStorage.getItem('lm_tenant') || 'default';
        setTenant(currentTenant);

        const savedTheme = localStorage.getItem('lm_theme') || 'default';
        setTheme(savedTheme);

        loadAppearance();
        setView('dashboard');
        setInterval(updateStatus, 10000);
        console.log("Lab Manager UI: Initialization complete.");
    } catch (err) {
        console.error("Lab Manager UI: Critical initialization error:", err);
        alert("UI Initialization failed: " + err.message);
    }
});
