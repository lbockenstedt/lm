import re

file_path = "/Users/lbockenstedt/vscode/lm/WebUI/main.js"
with open(file_path, "r") as f:
    content = f.read()

# 1. Fix the corrupted labels in the setup view
# This is tricky because the previous script put "la-slate-300" etc.
# Let's replace the whole render function for setup to be safe.

setup_render_start = content.find("render: (subMenu) => {")
# We need to find where the render function ends. It's a big block.
# I'll use a regex to find the start and end of the render function.

# Since the structure is VIEWS = { ... setup: { ..., render: (subMenu) => { ... } }, ... }
# I will replace the specific block of HTML.

# Let's find the "Repository Sources" section and replace it properly.
pattern = r'                            <div class="pt-6 border-t border-slate-200">.*?</div>\s*</div>\s*</div>\s*</div>\s*</div>\s*</div>'
# This regex might be too broad. Let's use a more specific one.

# Better: replace from <div class="pt-6 border-t border-slate-200"> to the matching closing div of the hpe-card.

# Actually, let's just replace the entire setup render function with the clean version.
# I will reconstruct the render function.

setup_view_code = r'''
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
                                                <label class="text la-slate-300 rounded-md px-3 py-1.5 text-xs outline-none focus:ring-1 focus:ring-green-500">VMs</label>
                                                <input type="number" id="quota-vm" class="w-full bg-white border border-slate-300 rounded-md px-3 py-1 text-sm outline-none focus:ring-1 focus:ring-green-500">
                                            </div>
                                            <div class="space-y-2">
                                                <label la-slate-300 rounded-md px-3 py-1.5 text-xs outline-none focus:ring-1 focus:ring-green-500">CPPM Policies</label>
                                                <input type="number" id="quota-cppm" class="w-full bg-white border border-slate-300 rounded-md px-3 py-1 text-sm outline-none focus:ring-1 focus:ring-green-500">
                                            </div>
                                            <div class="space-y-2">
                                                <label la-slate-300 rounded-md px-3 py-1.5 text-xs outline-none focus:ring-1 focus:ring-green-500">Firewall Rules</label>
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
                                        <span id="last-update-ts" class="text la-slate-300 rounded-md px-3 py-1.5 text-xs outline-none focus:ring-1 focus:ring-green-500">Last check: Never</span>
                                    </div>
                                </div>
                                <div class="pt-3 border-t border-slate-200 flex justify-between items-center">
                                    <div class="text-xs text-slate-400 italic">Manually synchronize from GitHub repository.</div>
                                    <button onclick="triggerUpdate()" id="update-btn" class="bg la-slate-300 rounded-md px-3 py-1.5 text-xs outline-none focus:ring-1 focus:ring-green-500">
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
                                                <label class la-slate-300 rounded-md px-3 py-1.5 text-xs outline-none focus:ring-1 focus:ring-green-500">Global Branch</label>
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
                                            <label la-slate-300 rounded-md px-3 py-1.5 text-xs outline-none focus:ring-1 focus:ring-green-500">Proxmox Agent</label>
                                            <input type="text" id="update-source-pxmx" class="w-full bg-white border border-slate-300 rounded-md px-3 py-1.5 text-xs outline-none focus:ring-1 focus:ring-green-500">
                                        </div>
                                        <div class="space-y-2">
                                            <label de la-slate-300 rounded-md px-3 py-1.5 text-xs outline-none focus:ring-1 focus:ring-green-500">OPNsense Spoke</label>
                                            <input type="text" id="update-source-opn" class="w-full bg-white border border-slate-300 rounded-md px-3 py-1.5 text-xs outline-none focus:ring-1 focus:ring-green-500">
                                        </div>
                                        <div class="space-y-2">
                                            <label la-slate-300 rounded-md px-3 py-1.5 text-xs outline-none focus:ring-1 focus:ring-green-500">Client Sim</label>
                                            <input type="text" id="update-source-cs" class="w-full bg-white border border-slate-300 rounded-md px-3 py-1.5 text-xs outline-none focus:ring-1 focus:ring-green-500">
                                        </div>
                                        <div class="space-y-2">
                                            <label l-slate-300 rounded-md px-3 py-1.5 text-xs outline-none focus:ring-1 focus:ring-green-500">CPPM Spoke</label>
                                            <input type="text" id="update-source-cppm" class="w-full bg-white border border-slate-300 rounded-md px-3 py-1.5 text-xs outline-none focus:ring-1 focus:ring-green-500">
                                        </div>
                                        <div class="space-y-2">
                                            <label la-slate-300 rounded-md px-3 py-1.5 text-xs outline-none focus:ring-1 focus:ring-green-500">Netbox Spoke</label>
                                            <input type="text" id="update-source-netbox" class="w-full bg-white border border-slate-300 rounded-md px-3 py-1.5 text-xs outline-none focus:ring-1 focus:ring-green-500">
                                        </div>
                                        <div class="space-y-2">
                                            <labelL-slate-300 rounded-md px-3 py-1.5 text-xs outline-none focus:ring-1 focus:ring-green-500">LDAP Spoke</label>
                                            <input type="text" id="update-source-ldap" class="w-full bg-white border border-slate-300 rounded-md px-3 py-1.5 text-xs outline-none focus:ring-1 focus:ring-green-500">
                                        </div>
                                    </div>
                                    <div class="pt-4 flex justify-end">
                                        <button onclick="saveUpdateSources()" class="bg la-slate-300 rounded-md px-3 py-1.5 text-xs outline-none focus:ring-1 focus:ring-green-500">
                                            Save Repository Sources
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                `;
        }
'''

# Replace setup render function
# Finding the start of setup view
setup_start = content.find('setup: {')
if setup_start != -1:
    # Find the start of the render function inside setup
    render_start = content.find('render: (subMenu) => {', setup_start)
    # Find the end of the render function. 
    # It ends with '},' before the next view or the end of the object.
    # This is a bit risky with regex. Let's find the matching brace.
    
    brace_count = 0
    render_end = -1
    for i in range(render_start, len(content)):
        if content[i] == '{':
            brace_count += 1
        elif content[i] == '}':
            brace_count -= 1
            if brace_count == 0:
                render_end = i + 1
                break
    
    if render_end != -1:
        content = content[:render_start] + setup_view_code + content[render_end:]

# 2. Add toggleAdvancedSettings function
if 'function toggleAdvancedSettings()' not in content:
    # Add it after saveUpdateSources()
    save_sources_pos = content.find('async function saveUpdateSources() {')
    if save_sources_pos != -1:
        # Find the end of saveUpdateSources
        brace_count = 0
        func_end = -1
        for i in range(save_sources_pos, len(content)):
            if content[i] == '{':
                brace_count += 1
            elif content[i] == '}':
                brace_count -= 1
                if brace_count == 0:
                    func_end = i + 1
                    break
        
        if func_end != -1:
            toggle_func = '\n\nfunction toggleAdvancedSettings() {\n    const section = document.getElementById(\'setup-advanced-section\');\n    if (section) {\n        section.classList.toggle(\'hidden\');\n    }\n}\n'
            content = content[:func_end] + toggle_func + content[func_end:]

with open(file_path, "w") as f:
    f.write(content)
