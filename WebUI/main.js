const MODULE_CLASSES = {
    'Virtual Machines': ['pxmx', 'kvm', 'vmware', 'utm'],
    'Firewall': ['opnsense', 'pfsense', 'juniper', 'fortigate'],
    'IPAM': ['netbox', 'phpipam'],
    'Security/NAC': ['cppm', 'ise']
};

const PRODUCT_MAP = {
    'pxmx': 'pxmx',
    'opn': 'opnsense',
    'opnsense': 'opnsense',
    'cs': 'cs',
    'cppm': 'cppm'
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
                                    <h3 class="text-sm font-semibold text-slate-500 mb-3 uppercase tracking-wider">Firewall Rules</h3>
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
        subMenus: ['Firewall Rules', 'Configuration', 'Interfaces', 'DHCP Leases', 'NAT Policies', 'DNS Records'],
        icon: '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>',
        render: (subMenu) => {
            if (subMenu === 'Configuration') {
                return `
                    <div class="space-y-6">
                        <h2 class="text-2xl font-bold mb-6 text-[#263040]">Firewall Configuration</h2>
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
                    <h2 class="text-2xl font-bold mb-6 text-[#263040]">Firewall Management: ${subMenu}</h2>
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
        className: 'Simulation',
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
                                                <label class="text-[10px] text-slate-400 uppercase font-bold">VMs</label>
                                                <input type="number" id="quota-vm" class="w-full bg-white border border-slate-300 rounded-md px-3 py-1 text-sm outline-none focus:ring-1 focus:ring-green-500">
                                            </div>
                                            <div class="space-y-2">
                                                <label class="text-[10px] text-slate-400 uppercase font-bold">CPPM Policies</label>
                                                <input type="number" id="quota-cppm" class="w-full bg-white border border-slate-300 rounded-md px-3 py-1 text-sm outline-none focus:ring-1 focus:ring-green-500">
                                            </div>
                                            <div class="space-y-2">
                                                <label class="text-[10px] text-slate-400 uppercase font-bold">Firewall Rules</label>
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
        subMenus: ['General', 'Network', 'Auth', 'Logs', 'Diagnostics'],
        icon: '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-1.59 4.04-1.59 5.583 0a1.724 1.724 0 001.28 2.915c-1.344 1.35-3.77 1.35-5.114 0a1.724 1.724 0 00-1.28-2.915zM12 18a6 6 0 100-12 6 6 0 000 12z"></path></svg>',
        render: (subMenu) => {
            if (subMenu.startsWith('logs-')) {
                const module = subMenu.replace('logs-', '');
                const logTitle = module === 'hub' ? 'Hub Console Output' : `${module.toUpperCase()} Logs`;
                return `
                    <div class="space-y-6">
                        <h2 class="text-2xl font-bold mb-6 text-[#263040]">${logTitle}</h2>
                        <div class="hpe-card rounded-lg overflow-hidden shadow-sm border border-slate-200">
                            <div class="bg-slate-100 px-4 py-2 border-b border-slate-200 flex justify-between items-center">
                                <span class="text-xs font-bold text-slate-500 uppercase tracking-widest">${logTitle}</span>
                                <button onclick="loadModuleLogs('${module}')" class="text-[10px] bg-white border border-slate-300 px-2 py-1 rounded hover:bg-slate-50 transition-colors font-medium">Refresh</button>
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
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                            ${['hub', 'pxmx', 'opn', 'cppm', 'cs'].map(mod => `
                                <div onclick="setSubView('logs-${mod}')" class="p-4 rounded-md bg-white border border-slate-200 hover:border-green-500 cursor-pointer transition-all flex justify-between items-center group">
                                    <span class="text-sm font-medium text-slate-700 group-hover:text-green-600">${mod.toUpperCase()} Logs</span>
                                    <svg class="w-4 h-4 text-slate-400 group-hover:text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path></svg>
                                </div>
                            `).join('')}
                        </div}
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
                        <div class="pt-4 flex justify-end">
                            <button onclick="loadDiagnostics()" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-4 py-2 rounded-md text-sm font-bold transition-all shadow-sm">
                                Refresh Diagnostics
                            </button>
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
let currentSubView = 'General';
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
            alert('Firewall configuration saved successfully!');
        } else {
            alert('Failed to save firewall configuration.');
        }
    } catch (err) {
        alert('Error saving firewall configuration: ' + err.message);
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
        if (menu === 'Logs') {
            return `
                <div class="relative group inline-flex items-center">
                    <div onclick="setSubView('Logs')" class="sub-nav-item ${currentSubView.startsWith('logs-') || currentSubView === 'Logs' ? 'active' : ''} px-2 py-1 text-xs uppercase tracking-widest cursor-pointer">
                        Logs ▾
                    </div>
                    <div class="absolute left-0 top-full hidden group-hover:block w-40 bg-white border border-slate-200 shadow-xl z-50 rounded-b-md">
                        <div onclick="setSubView('logs-hub')" class="px-4 py-2 text-xs hover:bg-slate-100 cursor-pointer ${currentSubView === 'logs-hub' ? 'text-green-600 font-bold' : ''}">Hub Logs</div>
                        <div onclick="setSubView('logs-pxmx')" class="px-4 py-2 text-xs hover:bg-slate-100 cursor-pointer ${currentSubView === 'logs-pxmx' ? 'text-green-600 font-bold' : ''}">Proxmox Logs</div>
                        <div onclick="setSubView('logs-opn')" class="px-4 py-2 text-xs hover:bg-slate-100 cursor-pointer ${currentSubView === 'logs-opn' ? 'text-green-600 font-bold' : ''}">OPNsense Logs</div>
                        <div onclick="setSubView('logs-cppm')" class="px-4 py-2 text-xs hover:bg-slate-100 cursor-pointer ${currentSubView === 'logs-cppm' ? 'text-green-600 font-bold' : ''}">CPPM Logs</div>
                        <div onclick="setSubView('logs-cs')" class="px-4 py-2 text-xs hover:bg-slate-100 cursor-pointer ${currentSubView === 'logs-cs' ? 'text-green-600 font-bold' : ''}">CS Logs</div>
                    </div>
                </div>
            `;
        }
        return `
            <div onclick="setSubView('${menu}')" class="sub-nav-item ${menu === currentSubView ? 'active' : ''} px-2 py-1 text-xs uppercase tracking-widest cursor-pointer">
                ${menu}
            </div>
        `;
    }).join('');

    topNav.innerHTML = topNavHtml;
}

function setView(viewId) {
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
        viewport.innerHTML = view.render(currentSubView);
        if (viewId === 'setup') {
            loadSetupConfig();
            loadTenants();
            if (currentSubView === 'Spoke Approvals') loadPendingSpokes();
            if (currentSubView === 'Tenant Config') loadTenantConfig();
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

function setSubView(subMenu) {
    currentSubView = subMenu;
    const view = VIEWS[currentView];
    if (view) {
        // Update sub-nav active state
        renderTopNav();

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
                if (currentSubView === 'Tenant Config') {
                    loadTenantConfig();
                }
                if (currentSubView === 'User Access') {
                    loadUsers();
                }
            }
            if ((currentView === 'pxmx' && currentSubView === 'Configuration') ||
                (currentView === 'opnsense' && currentSubView === 'Configuration')) {
                loadSetupConfig();
            }
            if (currentView === 'settings' && currentSubView.startsWith('logs-')) {
                const module = currentSubView.replace('logs-', '');
                loadModuleLogs(module);
            }
            if (currentView === 'settings' && currentSubView === 'General') updateStatus();
            if (currentView === 'settings' && currentSubView === 'Diagnostics') loadDiagnostics();
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
            const bEl = document.getElementById('sys-backlog');
            const tEl = document.getElementById('sys-throughput');
            if (cpuEl) cpuEl.textContent = `${m.cpu_util}%`;
            if (memEl) memEl.textContent = `${m.mem_util}%`;
            if (diskEl) diskEl.textContent = `${m.disk_util}%`;
            if (mpsEl) mpsEl.textContent = `${m.mps.toFixed(1)} msg/s`;
            if (qEl) qEl.textContent = m.queue_size;
            if (bEl) bEl.textContent = m.backlog;
            if (tEl) tEl.textContent = `${m.throughput.toFixed(2)} MB/s`;
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
                    <td class="px-4 py-3">${check('admin')}</td>
                    <td class="px-4 py-3">${check('pxmx_manage')}</td>
                    <td class="px-4 py-3">${check('pxmx_view')}</td>
                    <td class="px-4 py-3">${check('opn_edit')}</td>
                    <td class="px-4 py-3">${check('dns_manage')}</td>
                    <td class="px-4 py-3">${check('cppm_manage')}</td>
                    <td class="px-4 py-3">${check('cppm_view')}</td>
                    <td class="px-4 py-3 text-right">
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

        console.log(`[OPNsense] Fetching ${subMenu} from ${endpoint}...`);
        const response = await fetch(endpoint);
        if (!response.ok) throw new Error(`Failed to fetch ${subMenu}: ${response.status} ${response.statusText}`);

        const data = await response.json();
        console.log(`[OPNsense] Received raw data for ${subMenu}:`, data);

        const items = Array.isArray(data) ? data : (data.data || []);
        console.log(`[OPNsense] Processed items for ${subMenu}:`, items);

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

async function loadDiagnostics() {
    const container = document.getElementById('diag-container');
    if (!container) return;

    container.innerHTML = `<div class="py-12 text-center text-slate-400 animate-pulse">Fetching spoke telemetry...</div>`;

    try {
        const response = await fetch('/setup/diagnostics');
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        const data = await response.json();
        const spokes = data.spokes || [];

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
    if (side === 'left') return;
    const container = document.getElementById(`logo-${side}`);
    if (!container) return;

    const showLogo = config.show_logo_right;
    const logoUrl = config.logo_url_right;

    if (!showLogo) {
        container.innerHTML = '';
        return;
    }

    let html = '';
    if (logoUrl === 'hpe-svg' || !logoUrl) {
        html = `<img src="assets/hpe-logo.svg" class="h-8 w-auto" alt="HPE Logo">`;
    } else {
        html = `<img src="${logoUrl}" class="h-8 w-auto" alt="Logo" onerror="this.style.display='none'">`;
    }

    container.innerHTML = html;
}

function applyAppearance(config) {
    document.documentElement.style.setProperty('--hpe-green', config.primary_color);
    document.documentElement.style.setProperty('--hpe-navy', config.navy_color);
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

        listEl.innerHTML = `
            <div class="overflow-hidden rounded-md border border-slate-200 bg-white">
                <table class="w-full text-left text-sm">
                    <thead class="bg-slate-100 text-slate-600 uppercase text-xs">
                        <tr>
                            <th class="px-4 py-3 font-bold">Spoke ID</th>
                            <th class="px-4 py-3 font-bold">Status</th>
                            <th class="px-4 py-3 font-bold text-right">Action</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-slate-200">
                        ${spokes.map(spoke => {
                            const sid = spoke.spoke_id;
                            const isApproved = spoke.approved;
                            return `
                                <tr class="hover:bg-slate-50 transition-colors">
                                    <td class="px-4 py-3">
                                        <div class="flex items-center gap-3">
                                            <div class="w-2 h-2 rounded-full ${isApproved ? 'bg-green-500 shadow-[0_0_8px_rgba(34,197,94,0.6)]' : 'bg-yellow-500 shadow-[0_0_8px_rgba(234,179,8,0.6)]'}"></div>
                                            <span class="font-medium text-slate-700">${sid}</span>
                                        </div>
                                    </td>
                                    <td class="px-4 py-3">
                                        <span class="text-[10px] px-2 py-0.5 rounded-full font-bold uppercase ${isApproved ? 'bg-green-100 text-green-600' : 'bg-yellow-100 text-yellow-600'}">
                                            ${isApproved ? 'Approved' : 'Pending'}
                                        </span>
                                    </td>
                                    <td class="px-4 py-3 text-right">
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
