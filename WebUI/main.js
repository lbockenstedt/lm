const VIEWS = {
    dashboard: {
        name: 'Dashboard',
        subMenus: ['Overview', 'Notifications'],
        icon: '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6a8 8 0 018 8 8 8 0 018-8m-12 8a8 8 0 01-8-8 8 8 0 018-8m0 16v2m0-6V4m-2 8h4m-2 4h4m-4-8a4 4 0 01-4-4V4a4 4 0 014 0v4a4 4 0 014 0v4a4 4 0 01-4 0z"></path></svg>',
        render: () => `
            <div class="space-y-6">
                <h2 class="text-2xl font-bold mb-6 text-[#263040]">Infrastructure Overview</h2>
                <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <div class="hpe-card rounded-lg p-6 shadow-sm">
                        <label class="text-xs text-slate-500 uppercase font-bold">Active Spokes</label>
                        <div id="spoke-count" class="text-4xl font-bold mt-2 text-[#01A982]">0</div>
                    </div>
                    <div class="hpe-card rounded-lg p-6 shadow-sm">
                        <label class="text-xs text-slate-500 uppercase font-bold">System Health</label>
                        <div id="health-status" class="text-4xl font-bold mt-2 text-green-600">Optimal</div>
                    </div>
                    <div class="hpe-card rounded-lg p-6 shadow-sm">
                        <label class="text-xs text-slate-500 uppercase font-bold">Network Latency</label>
                        <div class="text-4xl font-bold mt-2 text-slate-700">~1.2ms</div>
                    </div>
                </div>

                <div class="hpe-card rounded-lg p-6 shadow-sm">
                    <h3 class="text-lg font-semibold mb-4 text-[#263040]">Connected Spokes</h3>
                    <div id="spoke-list" class="space-y-3">
                        <div class="animate-pulse flex space-x-4 p-2">
                            <div class="rounded-full bg-slate-200 h-10 w-10"></div>
                            <div class="flex-1 space-y-6 py-1">
                                <div class="h-2 bg-slate-200 rounded"></div>
                                <div class="h-2 bg-slate-200 rounded w-5/6"></div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `
    },
    pxmx: {
        name: 'Proxmox',
        subMenus: ['VM Management', 'Cluster Status', 'Storage', 'Configuration'],
        icon: '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path></svg>',
        render: (subMenu) => {
            if (subMenu === 'Configuration') {
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
                                    <h3 class="text-sm font-semibold text-slate-500 mb-3 uppercase tracking-wider">Firewall Rules (OPNsense)</h3>
                                    <div class="overflow-hidden rounded-md border border-slate-200 bg-white">
                                        <table class="w-full text-left text-sm">
                                            <thead class="bg-slate-100 text-slate-600 uppercase text-xs">
                                                <tr id="firewall-headers">
                                                    <th class="px-4 py-3">Rule ID</th>
                                                    <th class="px-4 py-3">Action</th>
                                                    <th class="px-4 py-3">Protocol</th>
                                                    <th class="px-4 py-3">Destination</th>
                                                </tr>
                                            </thead>
                                            <tbody id="firewall-table-body" class="divide-y divide-slate-200">
                                                <!-- Rows injected here -->
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                                <div>
                                    <h3 class="text-sm font-semibold text-slate-500 mb-3 uppercase tracking-wider">DHCP Lease (OPNsense)</h3>
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
        name: 'OPNsense',
        subMenus: ['Firewall Rules', 'Configuration', 'Interfaces', 'DHCP Leases', 'NAT Policies', 'DNS Records'],
        icon: '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.C18.4 5.6 17.4 5.4 16.3 5.4a4.4 4.4 0 00-4.4 4.4c0 1.1.2 2.1.6 3.1"></path></svg>',
        render: (subMenu) => {
            if (subMenu === 'Configuration') {
                return `
                    <div class="space-y-6">
                        <h2 class="text-2xl font-bold mb-6 text-[#263040]">OPNsense Configuration</h2>
                        <div class="hpe-card rounded-lg p-6 space-y-6">
                            <div class="grid grid-cols-1 gap-6">
                                <div class="space-y-2">
                                    <label class="text-xs text-slate-500 uppercase font-bold">OPNsense Host / IP</label>
                                    <input type="text" id="opn-host" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm text-slate-800 outline-none focus:ring-2 focus:ring-green-500">
                                </div>
                                <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                                    <div class="space-y-2">
                                        <label class="text-xs text-slate-500 uppercase font-bold">API Key</label>
                                        <input type="text" id="opn-api-key" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm text-slate-800 outline-none focus:ring-2 focus:ring-green-500">
                                    </div>
                                    <div class="space-y-2">
                                        <label class="text-xs text-slate-500 uppercase font-bold">API Secret</label>
                                        <input type="password" id="opn-api-secret" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm text-slate-800 outline-none focus:ring-2 focus:ring-green-500">
                                    </div>
                                </div>
                            </div>
                            <div class="pt-6 border-t border-slate-200 flex justify-end">
                                <button onclick="saveOpnsenseConfig()" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm">
                                    Save Configuration
                                </button>
                            </div>
                        </div>
                    </div>
                `;
            }
            return `
                <div class="space-y-6">
                    <h2 class="text-2xl font-bold mb-6 text-[#263040]">OPNsense Management: ${subMenu}</h2>
                    <div class="hpe-card rounded-lg p-6 shadow-sm">
                        <div id="opn-table-container" class="space-y-4">
                            <div class="py-12 text-center text-slate-400 italic">Loading OPNsense data...</div>
                        </div>
                    </div>
                </div>
            `;
        }
    },
    cs: {
        name: 'Client Sim',
        subMenus: ['Traffic Gen', 'DNS Config', 'Schedules'],
        icon: '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>',
        render: () => `
            <div class="space-y-6">
                <h2 class="text-2xl font-bold mb-6 text-[#263040]">Client Simulator</h2>
                <div class="hpe-card rounded-lg p-6 text-center py-12">
                    <div class="text-slate-500">Traffic simulation controls coming soon...</div>
                </div>
            </div>
        `
    },
    setup: {
        name: 'Setup',
        subMenus: ['General', 'Tenant Config', 'User Access', 'Spoke Approvals'],
        icon: '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110-4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m-2 8h4m-2 4h4m-4-8a4 4 0 01-4-4V4a4 4 0 014 0v4a4 4 0 014 0v4a4 4 0 01-4 0z"></path></svg>',
        render: (subMenu) => {
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
                                        <span id="last-update-ts" class="text-[10px] text-slate-400 block">Last check: Never</span>
                                    </div>
                                </div>
                                <div class="pt-3 border-t border-slate-200 flex justify-between items-center">
                                    <div class="text-xs text-slate-400 italic">Manually synchronize from GitHub repository.</div>
                                    <button onclick="triggerUpdate()" id="update-btn" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-4 py-2 rounded-md text-xs font-bold transition-all shadow-sm">
                                        Update System Now
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
        subMenus: ['General', 'Network', 'Auth', 'Logs'],
        icon: '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-1.59 4.04-1.59 5.583 0a1.724 1.724 0 001.28 2.915c-1.344 1.35-3.77 1.35-5.114 0a1.724 1.724 0 00-1.28-2.915zM12 18a6 6 0 100-12 6 6 0 000 12z"></path></svg>',
        render: (subMenu) => {
            if (subMenu === 'Logs') {
                return `
                    <div class="space-y-6">
                        <h2 class="text-2xl font-bold mb-6 text-[#263040]">System Logs</h2>
                        <div class="hpe-card rounded-lg overflow-hidden shadow-sm border border-slate-200">
                            <div class="bg-slate-100 px-4 py-2 border-b border-slate-200 flex justify-between items-center">
                                <span class="text-xs font-bold text-slate-500 uppercase tracking-widest">Hub Console Output</span>
                                <button onclick="loadSystemLogs()" class="text-[10px] bg-white border border-slate-300 px-2 py-1 rounded hover:bg-slate-50 transition-colors font-medium">Refresh</button>
                            </div>
                            <div id="system-logs-container" class="h-[600px] overflow-y-auto bg-white font-mono">
                                <!-- Logs injected here -->
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
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                        <div class="hpe-card rounded-lg p-6 shadow-sm">
                            <label class="text-xs text-slate-500 uppercase font-bold">Throughput (MPS)</label>
                            <div id="sys-mps" class="text-4xl font-bold mt-2 text-[#01A982]">0.0 msg/s</div>
                        </div>
                        <div class="hpe-card rounded-lg p-6 shadow-sm">
                            <label class="text-xs text-slate-500 uppercase font-bold">Mailbox Backlog</label>
                            <div id="sys-queue" class="text-4xl font-bold mt-2 text-slate-800">0</div>
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
                                    <option value="default">HPE Default</option>
                                    <option value="lcars">Star Trek (LCARS)</option>
                                    <option value="sw">Star Wars (Imperial)</option>
                                </select>
                            </div>
                        </div>
                    </div>
                    <div class="mt-6 hpe-card rounded-lg p-6 space-y-6">
                        <h3 class="text-sm font-semibold text-slate-500 uppercase tracking-wider mb-4">Appearance Configuration</h3>
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                            <div class="space-y-4">
                                <div class="flex items-center justify-between gap-4">
                                    <label class="text-xs font-bold text-slate-500 uppercase">Primary Color</label>
                                    <div class="flex items-center gap-2">
                                        <input type="color" id="app-primary-color" oninput="updateAppearance()" class="w-6 h-6 border-none cursor-pointer bg-transparent">
                                        <input type="text" id="app-primary-hex" class="w-20 bg-white border border-slate-300 rounded px-2 py-0.5 text-xs font-mono text-slate-800 outline-none">
                                    </div>
                                </div>
                                <div class="flex items-center justify-between gap-4">
                                    <label class="text-xs font-bold text-slate-500 uppercase">Navy Color</label>
                                    <div class="flex items-center gap-2">
                                        <input type="color" id="app-navy-color" oninput="updateAppearance()" class="w-6 h-6 border-none cursor-pointer bg-transparent">
                                        <input type="text" id="app-navy-hex" class="w-20 bg-white border border-slate-300 rounded px-2 py-0.5 text-xs font-mono text-slate-800 outline-none">
                                    </div>
                                </div>
                                <div class="space-y-2">
                                    <label class="text-xs font-bold text-slate-500 uppercase block">Left Logo URL</label>
                                    <input type="text" id="app-logo-url" oninput="updateAppearance()"
                                           placeholder="Enter image URL or 'hpe-svg'"
                                           class="w-full bg-white border border-slate-300 rounded px-3 py-2 text-xs text-slate-800 outline-none focus:ring-1 focus:ring-green-500">
                                </div>
                                <div class="space-y-2">
                                    <label class="text-xs font-bold text-slate-500 uppercase block">Right Logo URL</label>
                                    <input type="text" id="app-logo-url-right" oninput="updateAppearance()"
                                           placeholder="Enter image URL or 'hpe-svg'"
                                           class="w-full bg-white border border-slate-300 rounded px-3 py-2 text-xs text-slate-800 outline-none focus:ring-1 focus:ring-green-500">
                                </div>
                            </div>
                            <div class="space-y-4">
                                <div class="flex items-center justify-between p-3 rounded-md bg-slate-50 border border-slate-200">
                                    <span class="text-xs font-medium text-slate-600">Show Logo (Left)</span>
                                    <input type="checkbox" id="app-show-logo-left" onchange="updateAppearance()" class="w-4 h-4 text-green-600 border-slate-300 rounded">
                                </div>
                                <div class="flex items-center justify-between p-3 rounded-md bg-slate-50 border border-slate-200">
                                    <span class="text-xs font-medium text-slate-600">Show Logo (Right)</span>
                                    <input type="checkbox" id="app-show-logo-right" onchange="updateAppearance()" class="w-4 h-4 text-green-600 border-slate-300 rounded">
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
let currentSubView = 'General';
let currentTenant = 'default';

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

        // Load module-specific configs if we are in a module subview
        if ((currentView === 'setup' && currentSubView === 'Proxmox') || (currentView === 'pxmx' && currentSubView === 'Configuration')) {
            loadProxmoxConfig(config.pxmx || {});
        } else if ((currentView === 'setup' && currentSubView === 'OPNsense') || (currentView === 'opnsense' && currentSubView === 'Configuration')) {
            loadOpnsenseConfig(config.opn || {});
        } else if ((currentView === 'setup' && currentSubView === 'Client Sim') || (currentView === 'cs' && currentSubView === 'Configuration')) {
            loadCSConfig(config.cs || {});
        } else if ((currentView === 'setup' && currentSubView === 'CPPM') || (currentView === 'cppm' && currentSubView === 'Configuration')) {
            loadCPPMConfig(config.cppm || {});
        }
    } catch (err) {
        console.error('Failed to load setup config', err);
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
    const keyEl = document.getElementById('opn-api-key');
    const secretEl = document.getElementById('opn-api-secret');
    if (hostEl) hostEl.value = config.opn_host || '';
    if (keyEl) keyEl.value = config.api_key || '';
    if (secretEl) secretEl.value = config.api_secret || '';
}

function loadCSConfig(config) {
    const profilesEl = document.getElementById('cs-profiles');
    if (profilesEl) {
        profilesEl.value = JSON.stringify(config.sim_profiles || {}, null, 2);
    }
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
            alert('OPNsense configuration saved successfully!');
        } else {
            alert('Failed to save OPNsense configuration.');
        }
    } catch (err) {
        alert('Error saving OPNsense configuration: ' + err.message);
    }
}

async function saveCSConfig() {
    const profilesRaw = document.getElementById('cs-profiles').value;
    let profiles = {};
    try {
        profiles = JSON.parse(profilesRaw);
    } catch (e) {
        alert('Invalid JSON in simulation profiles');
        return;
    }
    try {
        const response = await fetch('/setup/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ config: { cs: { sim_profiles: profiles } } })
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

function setView(viewId) {
    currentView = viewId;
    currentSubView = 'General'; // Default sub-view

    const view = VIEWS[viewId];
    if (view && view.subMenus && !view.subMenus.includes('General')) {
        currentSubView = view.subMenus[0];
    }

    document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
    const navItem = document.getElementById(`nav-${viewId}`);
    if (navItem) navItem.classList.add('active');

    const topNav = document.getElementById('top-nav');
    if (view) {
        topNav.innerHTML = view.subMenus.map((menu, i) => `
            <div onclick="setSubView('${menu}')" class="sub-nav-item ${menu === currentSubView ? 'active' : ''} px-2 py-1 text-xs uppercase tracking-widest cursor-pointer">
                ${menu}
            </div>
        `).join('');
    }

    const viewport = document.getElementById('viewport');
    if (viewport && view) {
        viewport.innerHTML = view.render(currentSubView);
        if (viewId === 'setup') {
            loadSetupConfig();
            loadTenants();
            if (currentSubView === 'Spoke Approvals') loadPendingSpokes();
        }
        if (viewId === 'pxmx') {
            loadVMInventory();
        }
        if (viewId === 'opnsense') {
            loadOpnsenseManagement();
        }
    }

    if (viewId === 'dashboard' || viewId === 'settings') updateStatus();
}

function setSubView(subMenu) {
    currentSubView = subMenu;
    const view = VIEWS[currentView];
    if (view) {
        // Update sub-nav active state
        const topNav = document.getElementById('top-nav');
        topNav.innerHTML = view.subMenus.map(menu => `
            <div onclick="setSubView('${menu}')" class="sub-nav-item ${menu === currentSubView ? 'active' : ''} px-2 py-1 text-xs uppercase tracking-widest cursor-pointer">
                ${menu}
            </div>
        `).join('');

        // Re-render content
        const viewport = document.getElementById('viewport');
        if (viewport) {
            viewport.innerHTML = view.render(currentSubView);
            if (currentView === 'setup') {
                loadSetupConfig();
                loadTenants();
                if (currentSubView === 'Spoke Approvals') {
                    loadPendingSpokes();
                }
            }
            if ((currentView === 'pxmx' && currentSubView === 'Configuration') ||
                (currentView === 'opnsense' && currentSubView === 'Configuration')) {
                loadSetupConfig();
            }
            if (currentView === 'settings' && currentSubView === 'Logs') loadSystemLogs();
            if (currentView === 'settings' && currentSubView === 'General') updateStatus();
            if (currentView === 'opnsense' && currentSubView !== 'Configuration') {
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

    if (!statusEl) return;

    try {
        // Fetch both connection status and approval status
        const [statusRes, approvalsRes] = await Promise.all([
            fetch('/status'),
            fetch('/setup/pending_spokes')
        ]);

        if (!statusRes.ok || !approvalsRes.ok) throw new Error('API Error');

        const statusData = await statusRes.json();
        const approvalsData = await approvalsRes.json();

        // Update system metrics if elements exist
        if (statusData.metrics) {
            const m = statusData.metrics;
            const cpuEl = document.getElementById('sys-cpu');
            const memEl = document.getElementById('sys-mem');
            const diskEl = document.getElementById('sys-disk');
            const mpsEl = document.getElementById('sys-mps');
            const qEl = document.getElementById('sys-queue');
            if (cpuEl) cpuEl.textContent = `${m.cpu_util}%`;
            if (memEl) memEl.textContent = `${m.mem_util}%`;
            if (diskEl) diskEl.textContent = `${m.disk_util}%`;
            if (mpsEl) mpsEl.textContent = `${m.mps.toFixed(1)} msg/s`;
            if (qEl) qEl.textContent = m.queue_size;
        }

        statusEl.innerHTML = `
            <div class="w-1.5 h-1.5 rounded-full bg-green-500"></div>
            <span class="text-green-600">Hub Online</span>
        `;

        const connections = statusData.active_connections || [];

        // Count approved spokes for the dashboard metric
        const allSpokes = approvalsData.spokes || [];
        const approvedSpokes = allSpokes.filter(s => s.approved);

        if (spokeCount) spokeCount.textContent = approvedSpokes.length;

        const moduleMap = {
            'pxmx': 'pxmx',
            'opn': 'opnsense',
            'cs': 'cs',
            'cppm': 'cppm'
        };

        const activeModules = new Set();

        // 1. Add modules that are currently online
        connections.forEach(id => {
            for (const [key, viewId] of Object.entries(moduleMap)) {
                if (id.includes(key)) activeModules.add(viewId);
            }
        });

        // 2. Add modules that are known and approved (even if offline)
        const allSpokesList = approvalsData.spokes || [];
        allSpokesList.forEach(spoke => {
            if (spoke.approved) {
                for (const [key, viewId] of Object.entries(moduleMap)) {
                    if (spoke.spoke_id.includes(key)) activeModules.add(viewId);
                }
            }
        });

        // Dynamic setup submenus based on approved modules
        const baseSetupMenus = ['General', 'Tenant Config', 'User Access', 'Spoke Approvals'];
        VIEWS.setup.subMenus = baseSetupMenus;

        const staticNavs = ['dashboard', 'settings', 'setup'];
        const dynamicHtml = Array.from(activeModules).map(viewId => {
            const view = VIEWS[viewId];
            const isActive = currentView === viewId ? 'active' : '';
            return `
                <div onclick="setView('${viewId}')" id="nav-${viewId}" class="nav-item ${isActive} p-3 rounded-r-lg flex items-center gap-3 text-sm font-medium">
                    ${view.icon}
                    ${view.name}
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
            tableBody.innerHTML = `<tr><td colspan="4" class="px-4 py-4 text-center text-slate-400 italic">No rules found for this VM.</td></tr>`;
        } else {
            tableBody.innerHTML = rules.map(rule => `
                <tr class="hover:bg-slate-50 transition-colors">
                    <td class="px-4 py-3 font-mono text-xs text-slate-400">${rule.id || 'N/A'}</td>
                    <td class="px-4 py-3">
                        <span class="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase ${rule.action === 'pass' ? 'bg-green-100 text-green-600' : 'bg-red-100 text-red-600'}">
                            ${rule.action}
                        </span>
                    </td>
                    <td class="px-4 py-3 text-slate-600">${rule.protocol || 'TCP'}</td>
                    <td class="px-4 py-3 text-slate-600">${rule.destination || '-'}</td>
                </tr>
            `).join('');
        }
    } catch (err) {
        tableBody.innerHTML = `<tr><td colspan="4" class="px-4 py-8 text-center text-red-500 font-medium">${err.message}</td></tr>`;
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
        if (subMenu === 'Firewall Rules') endpoint = '/opn/firewall/all';
        else if (subMenu === 'DHCP Leases') endpoint = '/opn/dhcp';
        else if (subMenu === 'Interfaces') endpoint = '/opn/interfaces'; // Mocked or generic
        else if (subMenu === 'NAT Policies') endpoint = '/opn/nat';
        else if (subMenu === 'DNS Records') endpoint = '/opn/dns';
        else return;

        const response = await fetch(endpoint);
        if (!response.ok) throw new Error(`Failed to fetch ${subMenu}`);
        const data = await response.json();
        const items = data.data || [];

        if (items.length === 0) {
            container.innerHTML = `<div class="py-12 text-center text-slate-400 italic">No ${subMenu} found.</div>`;
            return;
        }

        // Generic Table Renderer
        const keys = Object.keys(items[0]);
        const headers = keys.map(k => `<th class="px-4 py-3">${k.toUpperCase().replace('_', ' ')}</th>`).join('');
        const rows = items.map(item => `
            <tr class="hover:bg-slate-50 transition-colors">
                ${keys.map(k => `<td class="px-4 py-3 text-slate-600 font-mono text-xs">${item[k]}</td>`).join('')}
            </tr>
        `).join('');

        container.innerHTML = `
            <div class="overflow-hidden rounded-md border border-slate-200 bg-white">
                <table class="w-full text-left text-sm">
                    <thead class="bg-slate-100 text-slate-600 uppercase text-xs">
                        <tr>${headers}</tr>
                    </thead>
                    <tbody class="divide-y divide-slate-200">
                        ${rows}
                    </tbody>
                </table>
            </div>
        `;
    } catch (err) {
        container.innerHTML = `<div class="py-12 text-center text-red-500 font-medium">Error loading ${subMenu}: ${err.message}</div>`;
    }
}

function setTheme(theme) {
    document.body.classList.remove('lcars-theme', 'sw-theme');
    if (theme === 'lcars') {
        document.body.classList.add('lcars-theme');
    } else if (theme === 'sw') {
        document.body.classList.add('sw-theme');
    }
    localStorage.setItem('lm_theme', theme);
}

async function loadSystemLogs() {
    const logsContainer = document.getElementById('system-logs-container');
    if (!logsContainer) return;

    logsContainer.innerHTML = `<div class="py-12 text-center text-slate-400 animate-pulse">Fetching system logs...</div>`;

    try {
        const response = await fetch('/setup/logs');
        if (!response.ok) throw new Error('Failed to fetch logs');
        const data = await response.json();
        const logs = data.logs || [];

        if (logs.length === 0) {
            logsContainer.innerHTML = `<div class="py-12 text-center text-slate-400 italic">No system logs available.</div>`;
            return;
        }

        logsContainer.innerHTML = logs.map(log => `
            <div class="p-2 border-b border-slate-100 font-mono text-[11px] text-slate-600 hover:bg-slate-50 transition-colors">
                ${log}
            </div>
        `).join('');
    } catch (err) {
        logsContainer.innerHTML = `<div class="py-12 text-center text-red-500 font-medium">Error loading logs: ${err.message}</div>`;
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
    const container = document.getElementById(`logo-${side}`);
    if (!container) return;

    const showLogo = side === 'left' ? config.show_logo_left : config.show_logo_right;
    const logoUrl = side === 'left' ? config.logo_url : config.logo_url_right;

    if (!showLogo) {
        container.innerHTML = '';
        return;
    }

    let html = '';
    if (logoUrl === 'hpe-svg' || !logoUrl) {
        html = `<img src="assets/hpe-logo.svg" class="${side === 'left' ? 'h-10' : 'h-8'} w-auto" alt="HPE Logo">`;
    } else {
        html = `<img src="${logoUrl}" class="${side === 'left' ? 'h-12' : 'h-8'} w-auto" alt="Logo" onerror="this.style.display='none'">`;
    }

    container.innerHTML = html;
}

function applyAppearance(config) {
    document.documentElement.style.setProperty('--hpe-green', config.primary_color);
    document.documentElement.style.setProperty('--hpe-navy', config.navy_color);
    renderLogo(config, 'left');
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
            document.getElementById('app-show-logo-left').checked = config.show_logo_left;
            document.getElementById('app-show-logo-right').checked = config.show_logo_right;
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

        listEl.innerHTML = spokes.map(spoke => {
            const sid = spoke.spoke_id;
            const isApproved = spoke.approved;

            return `
                <div class="flex items-center justify-between p-4 rounded-lg bg-slate-50 border border-slate-200 hover:border-blue-500 transition-all">
                    <div class="flex items-center gap-3">
                        <div class="w-2 h-2 rounded-full ${isApproved ? 'bg-green-500 shadow-[0_0_8px_rgba(34,197,94,0.6)]' : 'bg-yellow-500 shadow-[0_0_8px_rgba(234,179,8,0.6)]'}"></div>
                        <span class="text-sm font-medium text-slate-700">${sid}</span>
                        <span class="text-[10px] px-2 py-0.5 rounded-full font-bold uppercase ${isApproved ? 'bg-green-100 text-green-600' : 'bg-yellow-100 text-yellow-600'}">
                            ${isApproved ? 'Approved' : 'Pending'}
                        </span
                    </div>
                    ${!isApproved ? `
                        <button onclick="approveSpoke('${sid}')" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-1 rounded text-xs font-bold transition-colors">
                            Approve
                        </button>
                    ` : `
                        <button onclick="unapproveSpoke('${sid}')" class="bg-red-50 hover:bg-red-100 text-red-600 border border-red-200 px-4 py-1 rounded text-xs font-bold transition-colors">
                            Un-approve
                        </button>
                    `}
                </div>
            `;
        }).join('');
    } catch (err) {
        console.error('Error in loadPendingSpokes:', err);
        listEl.innerHTML = `<div class="py-12 text-center text-red-500 font-medium">Error loading spoke statuses: ${err.message}</div>`;
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

document.addEventListener('DOMContentLoaded', () => {
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
