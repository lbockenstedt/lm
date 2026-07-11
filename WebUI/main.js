// main.js — LM hub WebUI single-page app (vanilla JS, no framework).
//
// This is the hub admin/operator console. It is a browser SPA: every piece of
// data is fetched from the hub REST API in core/src/api.py (routes mounted at
// /setup/*, /api/*, /admin/*, /auth/*). The Simulations sub-module is split
// into a second file, sim-views.js, whose helper `csFetch` prepends /sim/api
// and is served by core/src/simulations/routes.py (NOT api.py). update_handler
// .js owns the "Update All" button. See the ROUTES table below for the
// handler→endpoint→api.py-function mapping.
//
// Three fetch helpers are used (see setupFetch JSDoc ~line 1862 for the full
// comparison):
//   fetch(url)        — public routes (no auth header, same-origin cookie only).
//   setupFetch(url)   — hub /setup/* + /api/* + /admin/* admin routes; adds
//                       JSON content-type + same-origin credentials.
//   csFetch(url)      — Simulations /sim/api/* routes (defined in sim-views.js);
//                       prepends /sim/api, injects tenant id, handles 401/404.
//
// Section index (names only — line numbers were dropped because they drift on
// every edit; grep the section name instead):
//   Bug-report console capture (window.__lmBugBuffer ring buffer)
//   Global registries: MODULE_CLASSES, PRODUCT_MAP, VIEW_* registries
//   Auth helpers: isAdmin(), canSeeModule()
//   UI utilities: showToast(), fileBug(), submitBugReport()
//   refreshModuleCache() — per-module cache invalidation
//   updateStatus() + _updateMetrics/_applyHubHealth/_updateSpokeCount/
//          _rebuildMainNav/_renderDashboardLists + _renderSpokeAgentRow — the
//          periodic /status poll that drives dashboard tiles + sidebar lists
//   renderSpokeIndicators() — header status dots
//   Navigation: setView(), setSubView() + VIEW_LOADERS dispatch table
//   setupFetch() — authed fetch helper
//   Section renderers: _renderLogsSection, _renderSettingsSection,
//          _renderSetupSection (+ _renderSetup*Tile helpers + SETUP_TILES)
//   Setup → Simulations admin overview (subnet-filter, USB, DHCP status)
//   Setup data loaders (cache, firewalls, spokes/agents, users, sessions)
//   Diagnostics & logs (loadModuleLogs, loadRecoveryLogs,
//          loadBugReports, showBugReport)
//   Generic agents & roles (loadApprovedSpokes, fetchLoadedRoles,
//          showLoadRoleModal, loadRole, showDeployAgentInfo)
//   OPNsense management (loadOpnsenseManagement + add/edit modals)
//   Proxmox (loadPxmxData)
//   NetBox IPAM/DCIM (loadNetboxData + device/rack/prefix/IP modals)
//   DNS (loadDNSData + record modal)
//   DHCP (loadDHCPData + reservation modal)
//   CPPM/NAC (loadCPPMNACStatus, loadCPPMData, device detail, claim)
//   OPNsense add/edit submit handlers
//   LDAP (loadLDAPData + entity/password modals)
//   User/firewall/instance modals (showAddUserModal, showAddFirewallModal,
//          loadInstances, showAddInstanceModal)
//   Appearance (loadAppearance, loadAppearanceForm, saveAppearance)
//   Dashboard (loadAllTenantsOverview, loadDashboardSummary, showDeviceDashboard)
//
// ────────────────────────────────────────────────────────────────────────────
// ROUTES — handler → backend endpoint map. `api` is the handler function in
// core/src/api.py; `sim` means the route is in core/src/simulations/routes.py.
// Handlers marked "(modal)" only render UI; the fetch is issued by the sibling
// function named in `via`. Kept as a const so it is greppable and could be used
// for runtime diagnostics. Update it when you add/rename a handler or route.
// CRUD/action handlers (delete*, save*, edit* form-save, toggle*, approve*,
// unapprove*, revoke*, reset*, assign*/remove*, plus auth + search) live in the
// companion CRUD_ROUTES const immediately below ROUTES — same {m, p, api} shape.
const ROUTES = {
    // ── Setup / config ──
    loadSetupConfig:        { m: 'GET',  p: '/setup/config',              api: 'get_global_config' },
    saveUpdateSources:      { m: 'POST', p: '/setup/config',              api: 'update_global_config' },
    scanGitHubRepos:        { m: 'GET',  p: '/setup/github-repos',        api: 'get_github_repos' },
    triggerUpdate:          { m: 'POST', p: '/setup/update',              api: 'trigger_update' }, // update_handler.js

    // ── Tenants ──
    loadTenantConfig:       { m: 'GET',  p: '/setup/tenants',             api: 'get_tenants' },
    saveTenantConfig:       { m: 'POST', p: '/setup/tenant',              api: 'update_tenant' },
    addTenant:              { m: 'POST', p: '/setup/tenants',             api: 'create_tenant' },
    syncTenantsFromNetBox:  { m: 'POST', p: '/setup/sync-tenants',        api: 'sync_tenants_from_netbox' },
    loadTenantPrefixes:     { m: 'GET',  p: '/auth/prefixes',             api: 'get_session_prefixes' },
    loadAllTenantsOverview: { m: 'GET',  p: '/api/dashboard/all-tenants', api: 'dashboard_all_tenants' },

    // ── Users / sessions ──
    loadUsers:              { m: 'GET',  p: '/setup/users',               api: 'get_users' },
    loadActiveSessions:     { m: 'GET',  p: '/admin/sessions',            api: 'admin_get_sessions' },
    showAddUserModal:       { m: 'POST', p: '/setup/users',               api: 'update_user', via: 'saveUser/editUser' }, // (modal)

    // ── Spokes / agents / firewalls ──
    loadFirewalls:          { m: 'GET',  p: '/setup/firewalls',           api: 'get_firewalls' },
    loadFirewallsList:      { m: 'GET',  p: '/setup/firewalls',           api: 'get_firewalls', via: 'loadFirewalls' }, // NOT a dead alias: renders #firewalls-list (Setup tile + post-delete refresh); issues its GET through loadFirewalls.
    loadSpokesAndAgents:    { m: 'GET',  p: '/setup/pending_spokes',      api: 'get_all_spokes_status',
                              m2: 'GET', p2: '/api/pxmx/agents',          api2: 'get_pxmx_agents' },
    loadApprovedSpokes:     { m: 'GET',  p: '/setup/pending_spokes',      api: 'get_all_spokes_status' },
    loadRole:               { m: 'POST', p: '/api/agent/{spokeId}/load-role', api: 'load_agent_role' },
    showLoadRoleModal:      { modal: true, via: 'loadRole' },
    showDeployAgentInfo:    { modal: true, via: null }, // static modal, no fetch
    showAddFirewallModal:   { m: 'POST', p: '/setup/firewalls',           api: 'add_firewall', via: 'saveFirewall' }, // (modal)

    // ── Endpoint sync (IPAM → NAC) ──
    loadEndpointSyncSources:{ m: 'GET',  p: '/setup/endpoint-sync/sources', api: 'endpoint_sync_sources' },
    loadEndpointSyncConfig: { m: 'GET',  p: '/setup/config',              api: 'get_global_config' },
    loadEndpointSyncStatus: { m: 'GET',  p: '/setup/endpoint-sync/status',api: 'endpoint_sync_status' },
    runEndpointSyncNow:     { m: 'POST', p: '/setup/endpoint-sync/run',   api: 'run_endpoint_sync' },
    saveEndpointSyncConfig: { m: 'POST', p: '/setup/config',              api: 'update_global_config' },

    // ── Realtime NAC → IPAM reverse sync (the bidirectional counterpart) ──
    loadRealtimeNacSyncConfig: { m: 'GET',  p: '/setup/config',                    api: 'get_global_config' },
    loadRealtimeNacSyncStatus: { m: 'GET',  p: '/setup/realtime-nac-sync/status',  api: 'realtime_nac_sync_status' },
    runRealtimeNacNow:         { m: 'POST', p: '/setup/realtime-nac-sync/run',     api: 'run_realtime_nac_sync' },
    saveRealtimeNacSyncConfig: { m: 'POST', p: '/setup/config',                    api: 'update_global_config' },

    // ── VM sync (Hypervisor → NetBox) ──
    loadVmSyncSources:      { m: 'GET',  p: '/setup/vm-sync/sources',     api: 'vm_sync_sources' },
    loadVmSyncConfig:       { m: 'GET',  p: '/setup/config',              api: 'get_global_config' },
    loadVmSyncStatus:       { m: 'GET',  p: '/setup/vm-sync/status',      api: 'vm_sync_status' },
    runVmSyncNow:           { m: 'POST', p: '/setup/vm-sync/run',         api: 'run_vm_sync' },
    saveVmSyncConfig:       { m: 'POST', p: '/setup/config',              api: 'update_global_config' },

    // ── Firewall discovery sync (Firewall → NetBox devices) ──
    loadFwDiscoverySources: { m: 'GET',  p: '/setup/fw-discovery-sync/sources', api: 'fw_discovery_sync_sources' },
    loadFwDiscoveryConfig:  { m: 'GET',  p: '/setup/config',              api: 'get_global_config' },
    loadFwDiscoveryStatus:  { m: 'GET',  p: '/setup/fw-discovery-sync/status', api: 'fw_discovery_sync_status' },
    runFwDiscoveryNow:      { m: 'POST', p: '/setup/fw-discovery-sync/run', api: 'run_fw_discovery_sync' },
    saveFwDiscoveryConfig:  { m: 'POST', p: '/setup/config',              api: 'update_global_config' },

    // ── Network Devices discovery sync (NW → NetBox devices) ──
    loadNwDiscoverySources: { m: 'GET',  p: '/setup/nw-discovery-sync/sources', api: 'nw_discovery_sync_sources' },
    loadNwDiscoveryConfig:  { m: 'GET',  p: '/setup/config',              api: 'get_global_config' },
    loadNwDiscoveryStatus:  { m: 'GET',  p: '/setup/nw-discovery-sync/status', api: 'nw_discovery_sync_status' },
    runNwDiscoveryNow:      { m: 'POST', p: '/setup/nw-discovery-sync/run', api: 'run_nw_discovery_sync' },
    saveNwDiscoveryConfig:  { m: 'POST', p: '/setup/config',              api: 'update_global_config' },

    // ── NetBox staleness sweep (cluster-wide; System → Sync) ──
    loadStalenessSweepConfig: { m: 'GET',  p: '/setup/config',                  api: 'get_global_config' },
    loadStalenessSweepStatus: { m: 'GET',  p: '/setup/staleness-sweep/status',  api: 'staleness_sweep_status' },
    runStalenessSweepNow:     { m: 'POST', p: '/setup/staleness-sweep/run',     api: 'run_staleness_sweep' },
    saveStalenessSweepConfig: { m: 'POST', p: '/setup/config',                  api: 'update_global_config' },

    // ── GitHub repo sync (System → Sync; replaces the old auto-update loop) ──
    loadRepoSyncConfig: { m: 'GET',  p: '/setup/config',            api: 'get_global_config' },
    loadRepoSyncStatus: { m: 'GET',  p: '/setup/repo-sync/status',  api: 'repo_sync_status' },
    runRepoSyncNow:     { m: 'POST', p: '/setup/repo-sync/run',     api: 'run_repo_sync' },
    saveRepoSyncConfig: { m: 'POST', p: '/setup/config',            api: 'update_global_config' },

    // ── Spoke out-of-contact alerts (System → Sync; saved via /setup/config) ──
    loadSpokeAlertConfig:     { m: 'GET',  p: '/setup/config',                  api: 'get_global_config' },
    loadSpokeAlerts:          { m: 'GET',  p: '/setup/spoke-alerts',            api: 'spoke_alerts' },
    saveSpokeAlertConfig:     { m: 'POST', p: '/setup/config',                  api: 'update_global_config' },

    // ── Source-of-truth per module (System → Sync; saved via /setup/config) ──
    loadSourceOfTruthConfig:  { m: 'GET',  p: '/setup/config',              api: 'get_global_config' },
    saveSourceOfTruthConfig:  { m: 'POST', p: '/setup/config',              api: 'update_global_config' },

    // ── Network Devices management ──
    loadNwDevices:          { m: 'GET',  p: '/setup/nw-devices',          api: 'get_nw_devices' },
    loadNwData:             { m: 'GET',  p: '/api/nw/{devices|info|macs|arp|interfaces}', api: 'nw_list_devices/nw_get_device_data' },
    submitNwConfig:         { m: 'POST', p: '/api/nw/{deviceId}/config',  api: 'nw_run_config' },
    showAddNwDeviceModal:   { m: 'POST', p: '/setup/nw-devices',          api: 'add_nw_device', via: 'saveNwDevice' },

    // ── Cache / subnet-filter / diagnostics / logs ──
    loadCacheConfig:        { m: 'GET',  p: '/admin/cache/config',        api: 'admin_get_cache_config' },
    saveCacheConfig:        { m: 'PUT',  p: '/admin/cache/config',        api: 'admin_update_cache_config' },
    purgeAllCaches:         { m: 'POST', p: '/admin/cache/purge',         api: 'admin_purge_cache' },
    loadSubnetFilterToggles:{ m: 'GET',  p: '/admin/subnet-filter-config',api: 'get_subnet_filter_config' },
    loadSpokesAndAgents:    { m: 'GET',  p: '/setup/pending_spokes + /api/pxmx/agents + /setup/diagnostics', api: 'get_pending_spokes / get_pxmx_agents / get_diagnostics' },
    loadModuleLogs:         { m: 'GET',  p: '/setup/logs/{module}',       api: 'get_module_logs' },
    loadRecoveryLogs:       { m: 'GET',  p: '/setup/logs',                api: 'get_hub_logs' },

    // ── Appearance / bug reports ──
    loadAppearance:         { m: 'GET',  p: '/setup/appearance',          api: 'get_appearance' },
    loadAppearanceForm:     { m: 'GET',  p: '/setup/appearance',          api: 'get_appearance' },
    saveAppearance:         { m: 'POST', p: '/setup/appearance',          api: 'update_appearance' },
    loadToastConfig:        { m: 'GET',  p: '/setup/toast-config',        api: 'get_toast_config' },
    loadToastConfigForm:    { m: 'GET',  p: '/setup/toast-config',        api: 'get_toast_config' },
    saveToastConfig:        { m: 'POST', p: '/setup/toast-config',        api: 'update_toast_config' },
    loadBugReports:         { m: 'GET',  p: '/setup/bug-reports',         api: 'list_bug_reports' },
    showBugReport:          { m: 'GET',  p: '/setup/bug-reports/{rid}',   api: 'get_bug_report' },
    submitBugReport:        { m: 'POST', p: '/api/bug-report',            api: 'file_bug_report' },

    // ── OPNsense management ──
    loadOpnsenseManagement: { m: 'GET',  p: '/api/firewall/{fwId}/{rules|dhcp|interfaces|nat|dns|aliases}', api: 'get_firewall_data' },
    submitOpnsenseAdd:      { m: 'POST', p: '/api/firewall/{fwId}/{rules|aliases|nat|dns}', api: 'add_firewall_rule/add_firewall_alias/add_nat_rule/add_dns_record' },
    submitOpnsenseEdit:     { m: 'PUT',  p: '/api/firewall/{fwId}/{rules|aliases|nat|dns}/{id}', api: 'edit_firewall_rule/edit_firewall_alias/edit_nat_rule/edit_dns_record' },
    showOpnsenseAddModal:   { modal: true, via: 'submitOpnsenseAdd' },
    showOpnsenseEditModal:  { modal: true, via: 'submitOpnsenseEdit' },

    // ── Proxmox ──
    loadPxmxData:           { m: 'GET',  p: '/api/pxmx/vms',              api: 'get_pxmx_vms',
                              m2: 'GET', p2: '/api/pxmx/nodes',           api2: 'get_pxmx_nodes' },

    // ── NetBox IPAM/DCIM ──
    loadNetboxData:         { m: 'GET',  p: '/api/netbox/{devices|racks|prefixes|ips}', api: 'netbox_get_devices/netbox_get_racks/netbox_get_prefixes/netbox_get_ips' },
    submitNetboxAddDevice:  { m: 'POST', p: '/api/netbox/devices',        api: 'netbox_add_device' },
    submitNetboxRack:       { m: 'POST', p: '/api/netbox/racks',          api: 'netbox_add_rack/netbox_update_rack' },
    submitNetboxAllocatePrefix: { m: 'POST', p: '/api/netbox/prefixes',   api: 'netbox_allocate_prefix' },
    submitFindSubnetAssign: { m: 'POST', p: '/api/netbox/subnet-assign',  api: 'netbox_assign_subnet' },
    submitNetboxAllocateIP: { m: 'POST', p: '/api/netbox/ips',            api: 'netbox_allocate_ip' },
    showNetboxAddModal:     { modal: true, via: 'show*Modal dispatch' },
    showNetboxAddDeviceModal:{ modal: true, via: 'submitNetboxAddDevice' },
    showNetboxRackModal:    { modal: true, via: 'submitNetboxRack' },
    showNetboxAllocatePrefixModal:{ modal: true, via: 'submitNetboxAllocatePrefix' },
    showFindSubnetModal:    { modal: true, via: 'submitFindSubnetAssign' },
    showNetboxAllocateIPModal:{ modal: true, via: 'submitNetboxAllocateIP' },

    // ── DNS / DHCP ──
    loadDNSData:            { m: 'GET',  p: '/api/dns/records',           api: 'dns_list_records' },
    showDnsRecordModal:     { m: 'POST', p: '/api/dns/record',            api: 'dns_add_record/dns_update_record', via: 'saveDnsRecord' }, // (modal)
    loadDHCPData:           { m: 'GET',  p: '/api/dhcp/{subnets|leases|reservations}', api: 'dhcp_list_subnets/dhcp_list_leases/dhcp_list_reservations' },
    showDhcpReservationModal:{ m: 'GET', p: '/api/dhcp/subnets',          api: 'dhcp_list_subnets', via: '_loadDhcpSubnetOptions' }, // (modal)

    // ── CPPM / NAC ──
    loadCPPMNACStatus:      { m: 'GET',  p: '/api/cppm/nac-status',       api: 'get_cppm_nac_status' },
    loadCPPMData:           { m: 'GET',  p: '/api/cppm/{sessions|devices|unknown-devices}', api: 'get_cppm_sessions/get_cppm_devices/get_cppm_unknown_devices' },
    showCPPMDeviceDetail:   { m: 'GET',  p: '/api/cppm/{device-enrich|device-sessions}', api: 'get_cppm_device_enrich/get_cppm_device_sessions' },
    showClaimDeviceModal:   { m: 'GET',  p: '/api/netbox/claim-device/options', api: 'netbox_claim_device_options' },
    submitClaimDevice:      { m: 'POST', p: '/api/netbox/claim-device',   api: 'netbox_claim_device' },

    // ── LDAP ──
    loadLDAPData:           { m: 'GET',  p: '/api/ldap/{ous|users|groups}', api: 'get_ldap_ous/get_ldap_users/get_ldap_groups' },
    showLDAPModal:          { m: 'POST', p: '/api/ldap/{ous|users|groups}', api: 'create_*/update_*_ldap_*', via: 'saveLDAPEntity' }, // (modal)
    showLDAPPasswordModal:  { m: 'POST', p: '/api/ldap/users/password',   api: 'set_ldap_user_password', via: 'changeUserPassword' }, // (modal)

    // ── Instances (multi-instance Setup tabs) ──
    loadInstances:          { m: 'GET',  p: '/setup/{nac|ipam|ldap|dns|dhcp}-instances', api: 'list_instances (_instance_crud)' },
    showAddInstanceModal:   { m: 'POST', p: '/setup/{...}-instances',     api: 'add_instance/update_instance', via: 'saveInstance' }, // (modal)

    // ── Dashboard ──
    loadDashboardSummary:   { m: 'GET',  p: '/api/dashboard/summary',     api: 'dashboard_summary' },
    showDeviceDashboard:    { m: 'GET',  p: '/api/device-detail',         api: 'get_device_detail' },

    // ── Simulations (csFetch → /sim/api/*, served by simulations/routes.py) ──
    loadSimAdminOverview:   { aggregator: true, via: 'loadUsbOverview+loadDiscoveredUsb+loadDhcpServerStatus' },
    loadDhcpServerStatus:   { m: 'GET',  p: '/sim/api/superadmin/dhcp-status', api: 'sim_superadmin_dhcp_status', sim: true },
    loadUsbOverview:        { m: 'GET',  p: '/sim/api/superadmin/tenants/usb', api: 'sim_superadmin_tenants_usb', sim: true },
};

// ────────────────────────────────────────────────────────────────────────────
// CRUD_ROUTES — companion to ROUTES for the action/CRUD handlers that were
// omitted from the original table (delete*, save*, edit* form-save, toggle*,
// approve*/unapprove*, revoke*, reset*, assign*/remove*, refresh*, auth, search).
// Same {m, p, api} shape; `sim` means core/src/simulations/routes.py. Handlers
// that issue >1 fetch use m2/p2/api2 (and m3/…). "(modal)" entries issue their
// own fetch on open (no `via`). Greppable; update when you add/rename a handler.
const CRUD_ROUTES = {
    // ── Spokes / agents ──
    approveSpoke:           { m: 'POST', p: '/setup/approve_spoke',                          api: 'approve_spoke' },
    unapproveSpoke:         { m: 'POST', p: '/setup/approve_spoke',                          api: 'approve_spoke' }, // unapprove action
    deleteSpoke:            { m: 'DELETE', p: '/setup/spokes/{spokeId}',                     api: 'delete_spoke' },
    resetSpokeSecret:       { m: 'POST', p: '/setup/spokes/{spokeId}/reset-secret',          api: 'reset_spoke_secret' },
    openSpokeMetadataModal: { m: 'GET',  p: '/setup/spoke-metadata/{spokeId}',               api: 'get_spoke_metadata' }, // (modal)
    saveSpokeMetadata:      { m: 'POST', p: '/setup/spoke-metadata',                         api: 'update_spoke_metadata',
                              m2: 'POST', p2: '/setup/spoke-name',                          api2: 'rename_spoke' },
    openSpokeAssignModal:   { m: 'GET',  p: '/setup/tenants',                                api: 'get_tenants' }, // (modal)
    saveSpokeAssign:        { m: 'POST', p: '/setup/approve_spoke',                          api: 'approve_spoke' },
    approveAgent:           { m: 'POST', p: '/setup/spokes/{spokeId}/agents/{agentId}/approve', api: 'approve_agent_under_spoke',
                              m2: 'GET', p2: '/api/pxmx/agents',                              api2: 'get_pxmx_agents' }, // resolves the agent's real owning spoke first (hypervisor OR simulation)
    revokeAgent:            { m: 'POST', p: '/api/pxmx/agents/{agentId}/revoke',             api: 'revoke_pxmx_agent' },
    editAgentName:          { m: 'POST', p: '/api/pxmx/agents/{agentId}/rename',             api: 'rename_pxmx_agent' },
    openAgentConfigModal:   { m: 'GET',  p: '/api/pxmx/agents/{agentId}/config',             api: 'get_pxmx_agent_config',
                              m2: 'GET', p2: '/setup/tenants',                               api2: 'get_tenants' }, // (modal)
    saveAgentConfig:        { m: 'POST', p: '/api/pxmx/agents/{agentId}/config',             api: 'set_pxmx_agent_config' },
    openAgentAssignModal:   { m: 'GET',  p: '/api/pxmx/agents/{agentId}/config',             api: 'get_pxmx_agent_config',
                              m2: 'GET', p2: '/setup/tenants',                               api2: 'get_tenants' }, // (modal) dedicated Tenant button
    saveAgentTenant:        { m: 'POST', p: '/api/pxmx/agents/{agentId}/config',             api: 'set_pxmx_agent_config' },
    deleteAgent:            { m: 'DELETE', p: '/api/pxmx/agents/{agentId}',                  api: 'delete_pxmx_agent' },

    // ── Tenants / users / sessions ──
    setTenant:              { m: 'POST', p: '/setup/tenant',                                 api: 'update_tenant' },
    editTenant:             { m: 'GET',  p: '/setup/tenants/{tenantId}',                     api: 'get_tenant_details' }, // (modal) form-save via saveTenantConfig
    updateGlobalConfig:     { m: 'POST', p: '/setup/config',                                 api: 'update_global_config' },
    saveUser:               { m: 'POST', p: '/setup/users',                                  api: 'update_user' },
    editUser:               { m: 'GET',  p: '/setup/users',                                  api: 'get_users',
                              m2: 'GET', p2: '/setup/tenants',                               api2: 'get_tenants' }, // (modal)
    saveUserEdits:          { m: 'POST', p: '/setup/users',                                  api: 'update_user',
                              m2: 'POST', p2: '/setup/users/assign-tenant',                  api2: 'assign_user_tenant',
                              m3: 'POST', p3: '/setup/users/remove-tenant',                  api3: 'remove_user_tenant' },
    promptSetPassword:      { m: 'POST', p: '/setup/users/{userId}/set-password',            api: 'set_user_password' },
    deleteUser:             { m: 'DELETE', p: '/setup/users/{userId}',                       api: 'delete_user' },
    revokeSession:          { m: 'DELETE', p: '/admin/sessions/{sid}',                 api: 'admin_revoke_session' },

    // ── Firewalls / instances ──
    saveFirewall:           { m: 'POST|PUT', p: '/setup/firewalls{/{id}}',                   api: 'add_firewall/update_firewall' }, // PUT when id present
    deleteFirewallEntry:    { m: 'DELETE', p: '/setup/firewalls/{id}',                       api: 'delete_firewall' },
    saveInstance:           { m: 'POST|PUT', p: '/setup/{nac|ipam|ldap|dns|dhcp}-instances{/{id}}', api: 'add_instance/update_instance' },
    deleteInstance:         { m: 'DELETE', p: '/setup/{nac|ipam|ldap|dns|dhcp}-instances/{id}', api: 'delete_instance (_instance_crud)' },

    // ── Recovery / diagnostics / debug / cache ──
    setRecoveryPause:       { m: 'POST', p: '/setup/spoke/{spokeId}/recovery',               api: 'set_spoke_recovery_pause' },
    toggleDebugLogging:     { m: 'GET',  p: '/setup/debug-mode',                             api: 'get_debug_mode',
                              m2: 'POST', p2: '/setup/debug-mode',                           api2: 'toggle_debug_mode' },
    executeProbe:           { m: 'GET',  p: '/setup/api-probe',                              api: 'probe_spoke_api' },
    toggleSubnetFilter:     { m: 'PUT',  p: '/admin/subnet-filter-config',                   api: 'set_subnet_filter_config' },
    refreshModuleCache:     { m: 'POST', p: '/auth/cache/refresh?module={key}',              api: 'refresh_my_cache' },
    refreshOpnsenseCache:   { m: 'GET',  p: '/api/firewall/{fwId}/refresh',                  api: 'refresh_firewall_cache' },

    // ── NetBox CRUD ──
    deleteNetboxDevice:     { m: 'DELETE', p: '/api/netbox/devices/{deviceId}',              api: 'netbox_delete_device' },
    deleteNetboxRack:       { m: 'DELETE', p: '/api/netbox/racks/{rackId}',                  api: 'netbox_delete_rack' },
    deleteNetboxPrefix:     { m: 'DELETE', p: '/api/netbox/prefixes/{prefixId}',             api: 'netbox_delete_prefix' },
    releaseNetboxIP:        { m: 'DELETE', p: '/api/netbox/ips/{ipId}',                      api: 'netbox_release_ip' },
    releaseSubnetToPool:    { m: 'GET',  p: '/api/netbox/ips?prefix={prefix}',               api: 'netbox_get_ips',
                              m2: 'DELETE', p2: '/api/netbox/prefixes/{prefixId}',           api2: 'netbox_delete_prefix' },
    searchAvailableSubnets: { m: 'GET',  p: '/api/netbox/available-subnets',                 api: 'netbox_find_available_subnets' },

    // ── DNS / DHCP CRUD ──
    saveDnsRecord:          { m: 'POST|PUT', p: '/api/dns/record',                           api: 'dns_add_record/dns_update_record' }, // PUT when editing
    deleteDnsRecord:        { m: 'DELETE', p: '/api/dns/record',                             api: 'dns_delete_record' },
    saveDhcpReservation:    { m: 'POST|PUT', p: '/api/dhcp/reservation',                     api: 'dhcp_add_reservation/dhcp_update_reservation' },
    deleteDhcpReservation:  { m: 'DELETE', p: '/api/dhcp/reservation',                       api: 'dhcp_delete_reservation' },

    // ── LDAP CRUD ──
    saveLDAPEntity:         { m: 'POST|PUT', p: '/api/ldap/{ous|users|groups}',              api: 'create_*/update_*_ldap_*' }, // PUT when editing
    deleteLDAPEntity:       { m: 'DELETE', p: '/api/ldap/entity',                            api: 'delete_ldap_entity' },
    changeUserPassword:     { m: 'POST', p: '/api/ldap/users/password',                      api: 'set_ldap_user_password' },

    // ── OPNsense delete ──
    deleteOpnsenseItem:     { m: 'DELETE', p: '/api/firewall/{fwId}/{rules|aliases|nat|dns}/{id}', api: 'delete_firewall_rule/delete_firewall_alias/delete_nat_rule/delete_dns_record' },

    // ── Proxmox ──
    lookupVMDetails:        { m: 'GET',  p: '/vm/{vmId}/details',                            api: 'get_vm_details' },
    showPxmxInstallModal:   { m: 'GET',  p: '/api/pxmx/agent-install-cmd',                   api: 'get_pxmx_agent_install_cmd' }, // (modal)

    // ── USB management (sim routes) ──
    loadDiscoveredUsb:      { m: 'GET',  p: '/sim/api/superadmin/discovered-usb-vidpids',    api: 'sim_get_discovered_usb', sim: true },
    addGlobalUsbCert:       { m: 'GET',  p: '/sim/api/superadmin/global-usb-vidpids',        api: 'sim_get_global_usb_vidpids',
                              m2: 'PUT', p2: '/sim/api/superadmin/global-usb-vidpids',       api2: 'sim_put_global_usb_vidpids', sim: true },
    removeGlobalUsbCert:    { m: 'GET',  p: '/sim/api/superadmin/global-usb-vidpids',        api: 'sim_get_global_usb_vidpids',
                              m2: 'PUT', p2: '/sim/api/superadmin/global-usb-vidpids',       api2: 'sim_put_global_usb_vidpids', sim: true },
    addGlobalUsbIgnore:     { m: 'GET',  p: '/sim/api/superadmin/global-usb-ignored-vidpids',api: 'sim_get_global_usb_ignored',
                              m2: 'PUT', p2: '/sim/api/superadmin/global-usb-ignored-vidpids', api2: 'sim_put_global_usb_ignored', sim: true },
    removeGlobalUsbIgnore:  { m: 'PUT',  p: '/sim/api/superadmin/global-usb-ignored-vidpids',api: 'sim_put_global_usb_ignored', sim: true },
    approveGlobalUsb:       { m: 'PUT',  p: '/sim/api/superadmin/global-usb-vidpids',        api: 'sim_put_global_usb_vidpids',
                              m2: 'PUT', p2: '/sim/api/superadmin/global-usb-ignored-vidpids', api2: 'sim_put_global_usb_ignored', sim: true },
    ignoreGlobalUsb:        { m: 'PUT',  p: '/sim/api/superadmin/global-usb-ignored-vidpids',api: 'sim_put_global_usb_ignored',
                              m2: 'PUT', p2: '/sim/api/superadmin/global-usb-vidpids',       api2: 'sim_put_global_usb_vidpids', sim: true },

    // ── Auth / lifecycle / search ──
    doLogin:                { m: 'POST', p: '/auth/login',                                   api: 'local_login' },
    doLogout:               { m: 'POST', p: '/auth/logout',                                  api: 'auth_logout' },
    doSetup:                { m: 'POST', p: '/auth/setup',                                   api: 'first_run_setup',
                              m2: 'GET', p2: '/auth/me',                                     api2: 'auth_me' },
    handleSearch:           { m: 'GET',  p: '/api/search?q={q}',                             api: 'cross_system_search' },
    updateStatus:           { m: 'GET',  p: '/status',                                       api: 'get_status',
                              m2: 'GET', p2: '/setup/pending_spokes',                        api2: 'get_all_spokes_status',
                              m3: 'GET', p3: '/setup/diagnostics',                           api3: 'get_diagnostics' },
};

// ────────────────────────────────────────────────────────────────────────────
// Bug-report console capture (runs first so early errors are caught).
//
// The "File a Bug" footer button (fileBug()) includes this buffer in the
// report so a developer can see what the browser console showed at the time of
// the bug, without the user having to open devtools. JS cannot read the actual
// devtools console, so we monkey-patch console.* + install global error
// handlers and keep a capped ring buffer (last 200 entries) on
// window.__lmBugBuffer. Each entry: {ts, level, msg}. Originals are still
// called so devtools behaves normally.
(function __lmInstallBugBuffer() {
    const CAP = 200;
    const buf = [];
    window.__lmBugBuffer = buf;
    function push(level, args) {
        try {
            const msg = Array.from(args).map(a => {
                if (a instanceof Error) return a.stack || (a.name + ': ' + a.message);
                if (typeof a === 'object' && a !== null) {
                    try { return JSON.stringify(a); } catch { return String(a); }
                }
                return String(a);
            }).join(' ');
            buf.push({ ts: new Date().toISOString(), level, msg });
            while (buf.length > CAP) buf.shift();
        } catch (_) { /* never let capture break the app */ }
    }
    ['log', 'info', 'warn', 'error'].forEach(level => {
        const orig = console[level] ? console[level].bind(console) : null;
        console[level] = function (...args) {
            push(level === 'log' ? 'log' : level, args);
            if (orig) orig(...args);
        };
    });
    window.addEventListener('error', e => push('error', [e.message + ' (' + (e.filename || '') + ':' + (e.lineno || 0) + ')']));
    window.addEventListener('unhandledrejection', e => push('error', ['Unhandled rejection: ' + (e.reason && e.reason.stack ? e.reason.stack : String(e.reason))]));
})();

const MODULE_CLASSES = {
    'Hypervisors': ['pxmx', 'kvm', 'vmware', 'utm'],
    'Firewalls': ['opnsense', 'pfsense', 'juniper', 'fortigate'],
    'IPAM': ['netbox', 'phpipam'],
    'Security/NAC': ['cppm', 'ise'],
    'DNS': ['dns'],
    'DHCP': ['dhcp'],
    'Network': ['nw'],
    'Simulations': ['cs'],
    'Certificates': ['le'],
    'Console': ['console']
};

// Header module label: maps the active view/product to the nav class name shown
// in the header (Logo | Lab Manager | <Module>). e.g. opnsense -> 'Firewalls',
// cs -> 'Simulations'. Standalone views get an explicit label below.
const PRODUCT_LABEL = {};
for (const _cls of Object.keys(MODULE_CLASSES)) {
    for (const _p of MODULE_CLASSES[_cls]) PRODUCT_LABEL[_p] = _cls;
}
const VIEW_LABEL = {
    dashboard: 'Dashboard', setup: 'Setup', settings: 'System', logs: 'Logs', ldap: 'Directory',
};
function updateHeaderModule() {
    const sep = document.getElementById('header-module-sep');
    const el = document.getElementById('header-module');
    if (!el || !sep) return;
    const label = VIEW_LABEL[currentView] || PRODUCT_LABEL[currentView] || '';
    if (label) {
        el.textContent = label;
        el.classList.remove('hidden');
        sep.classList.remove('hidden');
    } else {
        el.classList.add('hidden');
        sep.classList.add('hidden');
    }
}

// Page-context actions rendered into the persistent footer slot rather than
// the page body (keeps the content frame clear). The Firewalls page puts its
// "Refresh Cache" button here, and the global "Update" (hub + spokes) action
// lives here for admins only — visible on every view, gated by isAdmin() and
// enforced server-side (POST /setup/update requires admin → 403 otherwise).
function updateContextActions() {
    const fa = document.getElementById('footer-actions');
    if (!fa) return;
    const parts = [];
    if (currentView === 'opnsense') {
        parts.push(`<button onclick="refreshOpnsenseCache()" class="text-[10px] uppercase tracking-widest opacity-80 hover:opacity-100 border border-slate-500 hover:border-white px-2 py-0.5 rounded transition-all">↻ Refresh Cache</button>`);
    }
    if (isAdmin()) {
        parts.push(`<button onclick="triggerUpdate(event)" id="update-btn" class="text-[10px] uppercase tracking-widest opacity-80 hover:opacity-100 border border-slate-500 hover:border-white px-2 py-0.5 rounded transition-all">↻ Update</button>`);
    }
    fa.innerHTML = parts.join('');
}

// Roles available to load on a generic agent (matches lm/agent/src/agent_spoke.py _ROLE_MAP)
const AGENT_ROLES = {
    'dns':        { name: 'DNS Server (Unbound)',  desc: 'Manages Unbound DNS. Syncs records from NetBox.', deploy: false },
    'dhcp':       { name: 'DHCP Server (Kea)',     desc: 'Manages Kea DHCP4. Syncs subnets and reservations from NetBox.', deploy: false },
    'network':    { name: 'Network Devices (nw)',  desc: 'Polls fleet switches for ARP/MAC topology and syncs device/MAC/ARP data into NetBox.', deploy: false },
    'netbox':     { name: 'IPAM/DCIM (NetBox)',    desc: 'Source-of-truth for sites, racks, devices, prefixes, IPs, VMs, tenants. Sinks every discovery sync and runs the NetBox→Kea DHCP scope sync. This is the API MODULE — it needs a running NetBox server (deploy the "NetBox Server" role, then point this module\'s connection settings at it).', deploy: false },
    'netbox-server': { name: 'NetBox Server', desc: 'Deploys the NetBox application itself — PostgreSQL, Redis, gunicorn, and nginx serving the WebUI on port 80. Runs as its own service on this host; does NOT create a spoke. Load the "IPAM/DCIM (NetBox)" module role to talk to it.', deploy: true },
    'opnsense':   { name: 'Firewall (OPNsense)',   desc: 'Manages an OPNsense firewall — aliases, filter/NAT rules, Unbound DNS, DHCP leases, ARP. Syncs DHCP/ARP into NetBox.', deploy: false },
    'ldap':       { name: 'Directory (LDAP)',      desc: 'Wraps an LDAP directory for identity/group lookups.', deploy: false },
    'simulation': { name: 'Client Simulator (cs)', desc: 'Client-sim engine, client registry, USB auto-provisioning relay, per-client override control panel, and the DHCP/client API for the isolated sim-client network.', deploy: false },
    'cppm':       { name: 'NAC (Aruba ClearPass)', desc: 'Syncs ClearPass sessions/endpoints (by-MAC / by-IP) into NetBox.', deploy: false },
    'proxmox':    { name: 'Hypervisor (Proxmox / pxmx)', desc: 'Proxmox spoke bridging the hub to per-host pxmx agents (VM lifecycle, VNC console, USB auto-provisioning).', deploy: false },
    'le':         { name: 'Certificate Management (Let\'s Encrypt)', desc: 'Issues/renews prod Let\'s Encrypt certs via certbot (HTTP-01 / DNS-01) and serves them to the hub for distribution to target spokes (e.g. OPNsense). Installs certbot + DNS-01 plugins.', deploy: false },
    'console':    { name: 'Console Server', desc: 'Serial console access to attached hardware (USB adapters + on-board UART). Auto-detects baud, auto-identifies devices, and relays an xterm.js terminal through the hub.', deploy: false },
    'statuspage': { name: 'Simulation Status Page', desc: 'Public, read-only status page for one tenant — cloud-provider style (overall banner, per-component status, 90-day uptime history) plus a Clients view whose demo dropdown lets visitors trigger a live 2h simulation. Bind it to a tenant; the hub pushes that tenant\'s redacted dashboard down. Serves its own HTTPS page (cert via the le role).', deploy: false },
    'bugfixer':   { name: 'BugFixer', desc: 'Autonomous GitHub issue bot. Installs as a systemd service on this host and connects to the Hub as its own agent.', deploy: true },
};

const PRODUCT_MAP = {
    'pxmx': 'pxmx',
    'opn': 'opnsense',
    'opnsense': 'opnsense',
    'cs': 'cs',
    'cppm': 'cppm',
    'netbox': 'netbox',
    'dns': 'dns',
    'dhcp': 'dhcp',
    'nw': 'nw',
    'le': 'le',
    'console': 'console',
};

// module_type -> nav product. A spoke's REGISTERED module_type is the
// authoritative signal that a module is actually loaded: a generic node
// (module_type "agent") with no role loaded must NOT light a product nav item
// even when its NAME resembles a product (e.g. an agent named "lm-opnsense").
// Only a real module spoke (module_type "firewall" / "dns" / ...) or a loaded
// role sub-spoke ("{base}-{role}", module_type = the role's) maps to a product.
// "agent" / "qa" have no product; "directory" (LDAP) has no nav class (it lives
// behind its own view), matching the old PRODUCT_MAP which had no ldap entry.
const MODULE_TYPE_PRODUCT = {
    hypervisor: 'pxmx',
    firewall: 'opnsense',
    nac: 'cppm',
    simulation: 'cs',
    ipam: 'netbox',
    dns: 'dns',
    dhcp: 'dhcp',
    nw: 'nw',
    certificates: 'le',
    console: 'console',
};

// spoke_id prefix -> product, used ONLY as a fallback when a spoke's module_type
// is unknown — i.e. an approved-but-OFFLINE spoke whose module_type was popped on
// disconnect (hub spoke_module_types is cleared when the WS closes), so its
// historical Logs tab stays reachable while it is briefly down. PREFIX match
// (sid === prefix OR sid.startsWith(prefix + '-')), mirroring the hub's
// _PREFIX_MODULE (api.py _module_type_for), NOT substring — so a generic agent
// named "lm-opnsense" never matches the "opn" / "opnsense" prefix and can't ghost
// a Firewalls nav item. A connected generic agent has module_type "agent" (known)
// so this fallback is never reached for it.
const _ID_PREFIX_PRODUCT = {
    pxmx: 'pxmx', opn: 'opnsense', opnsense: 'opnsense', pfsense: 'opnsense',
    cppm: 'cppm', ise: 'cppm', cs: 'cs', netbox: 'netbox', phpipam: 'netbox',
    dns: 'dns', dhcp: 'dhcp', nw: 'nw', le: 'le',
};
function _productFromIdPrefix(sid) {
    for (const [prefix, product] of Object.entries(_ID_PREFIX_PRODUCT)) {
        if (sid === prefix || sid.startsWith(prefix + '-')) return product;
    }
    return null;
}

const LOG_NAMES = {
    'hub': 'Lab Manager Logs',
    'opn': 'Firewall Logs',
    'pxmx': 'Hypervisor Logs',
    'cppm': 'Security/NAC Logs',
    'cs': 'Client Simulator Logs',
    'le': 'Certificate Logs'
};

// Friendly product name per registered module_type (each spoke sets its own on
// connect). Shared by the Hub Status page and the Setup → Spokes & Agents tile.
// Unknown types fall back to a title-cased version of the raw value so new
// spokes still render something readable.
const MODULE_LABELS = {
    hypervisor: 'Proxmox',
    firewall:   'OPNsense',
    nac:        'ClearPass',
    simulation: 'Client Simulator',
    nw:         'Network',
    dhcp:       'DHCP',
    dns:        'DNS',
    directory:  'LDAP',
    ipam:       'NetBox',
    agent:      'Agent',
    qa:         'QA',
    certificates: 'Certificate Management',
};
function moduleLabel(mt) {
    mt = String(mt || '').toLowerCase();
    return MODULE_LABELS[mt] || (mt ? mt.charAt(0).toUpperCase() + mt.slice(1) : '—');
}

let currentView = 'dashboard';
let currentSubView = 'General';
// For modules with a two-tier nav (cs/Simulations), the active child tab
// within the current primary (e.g. 'VMs' under 'VM Server'). '' when the
// current primary has no children.
let currentSubChild = '';
// Configured firewalls (Setup → Firewalls). The Firewalls page no longer has a
// single-firewall selector — it aggregates every firewall's rules/NAT/etc. into
// one table, so each item carries its source firewall id (_fwId) + name.
let _opnFirewalls = [];
let showHiddenOnlyFirewallRules = false;
let currentUser = null;
// Cached outerHTML of the admin-only nav items (Setup/Logs/System), captured
// from the static HTML on first sight. Lets _rebuildMainNav restore them after
// a rebuild that ran while isAdmin() was momentarily false dropped them from
// the DOM (see _rebuildMainNav). null until first capture.
let _adminNavHtmlCache = null;
let _opnCurrentItems = {};
let currentTenant = 'default';
let currentProduct = null;

function isAdmin() {
    // Global Admin (system-wide) — today's "admin" tier. Returns FALSE for a
    // tenant Admin (role:"tenant_admin"), so every system-config / fleet /
    // all-tenants gate that reads isAdmin() automatically hides for tenant
    // Admins without any per-call change.
    const p = currentUser?.permissions || {};
    return p.admin === true || p.role === 'admin';
}

function isTenantAdmin() {
    // Tenant-level Admin — admin WITHIN their assigned tenants only, tenant-
    // confined server-side (check_tenant_access / filter_session). Not a Global
    // Admin (isAdmin() is False for this tier).
    const p = currentUser?.permissions || {};
    return p.role === 'tenant_admin';
}

function _taUsersBase() {
    // Tenant-scoped user-management base URL (Phase 2). A tenant Admin manages
    // the users of its CURRENT tenant (the active tenant in the header picker),
    // via /api/tenant/{tenant}/users*. Returns null for a Global Admin, who keeps
    // using the system-wide /setup/users* routes. Switching the header tenant
    // picker re-scopes the Users page (loadUsers re-fetches on showSection).
    if (!isTenantAdmin()) return null;
    return `/api/tenant/${encodeURIComponent(currentTenant || 'default')}/users`;
}

function _isPermsAdminTier(perms) {
    // True if the (effective) permissions describe an admin-tier user (Global
    // Admin or tenant Admin). A tenant Admin viewing the Users list may not
    // edit/remove these (the backend 403s; hide the buttons to match).
    const p = perms || {};
    return p.admin === true || p.role === 'admin' || p.role === 'tenant_admin';
}

function _taTenantQuery() {
    // Shared-infrastructure writes (firewall/DNS/DHCP) by a tenant Admin must
    // target an explicit owned tenant — the hub middleware rejects an
    // ambiguous (tenantless) write with 403 ("must target an explicit owned
    // tenant"). Returns "?tenant=<currentTenant>" for a tenant Admin (whose
    // currentTenant is one of its owned tenants via the picker), else "" (a
    // Global Admin needs no explicit tenant). Append to write URLs.
    if (!isTenantAdmin()) return '';
    return `?tenant=${encodeURIComponent(currentTenant || 'default')}`;
}

function hasConsoleWrite() {
    const p = currentUser?.permissions || {};
    return isAdmin() || isTenantAdmin() || p.console_write === true;
}

// ─── Session-expiry guard ───────────────────────────────────────────────────
// This is a single-page client-rendered app: after the server session dies
// (8h TTL, or an admin revoke), every gated fetch returns 401 JSON, but the
// viewport keeps showing the last-rendered ("cached") view because nothing
// re-checked auth and /status — the only recurring poll — is public and stays
// 200 forever. We wrap window.fetch once, globally, so ANY 401 received while
// a user is logged in tears down the stale view and returns them to the login
// screen instead of silently failing into a "still loading" page. A periodic
// /auth/me ping (started in _initApp) trips the same guard even when the user
// is idle with no data calls in flight.
const _lmOrigFetch = window.fetch.bind(window);
function _lmIsAuthSubmitEndpoint(input) {
    // /auth/login and /auth/setup legitimately 401 on bad credentials; never
    // treat those as session expiry. (/auth/me 401 during bootstrap is skipped
    // by the currentUser guard below.)
    try {
        const u = typeof input === 'string' ? input : (input && input.url) || '';
        return u.indexOf('/auth/login') !== -1 || u.indexOf('/auth/setup') !== -1;
    } catch (_) { return false; }
}
function handleSessionExpired() {
    if (!currentUser) return;              // already sent to login / not logged in
    currentUser = null;
    const errEl = document.getElementById('login-error');
    if (errEl) { errEl.textContent = 'Your session has expired. Please sign in again.'; errEl.classList.remove('hidden'); }
    document.getElementById('setup-panel')?.classList.add('hidden');
    document.getElementById('login-panel')?.classList.remove('hidden');
    document.getElementById('login-overlay')?.classList.remove('hidden');
    document.getElementById('user-chip')?.classList.add('hidden');
    document.getElementById('user-chip')?.classList.remove('flex');
    document.getElementById('login-username')?.focus();
    refreshOidcButton();
}
window.fetch = async function lmFetch(input, init) {
    const res = await _lmOrigFetch(input, init);
    if (res && res.status === 401 && currentUser && !_lmIsAuthSubmitEndpoint(input)) {
        handleSessionExpired();
        throw new Error('Session expired');
    }
    return res;
};

// Module visibility: admins see every module; a non-admin sees a module only if
// granted its explicit right. Today only the Simulations (cs) module is gated
// this way; other modules remain product-driven (visible when their spoke is
// connected). Add a key here to gate another module the same way.
const MODULE_RIGHT = { 'Simulations': 'cs', 'Network': 'nw', 'IPAM': 'ipam', 'Certificates': 'le', 'Console': 'console', 'Firewalls': 'firewall', 'Security/NAC': 'nac', 'DNS': 'dns', 'DHCP': 'dhcp', 'Hypervisors': 'pxmx', 'Directory': 'ldap' };
function canSeeModule(className) {
    const right = MODULE_RIGHT[className];
    if (!right) return true;              // no right defined → product-driven
    if (isAdmin() || isTenantAdmin()) return true;
    const p = currentUser?.permissions || {};
    return p[right] === true;
}

// Write-user tier: may EDIT their own tenant's DEDICATED module configs. Global
// Admin and tenant-admin always; otherwise the global `edit` right (legacy
// `console_write` also grants it, backward compat). Gates edit controls in the
// module views (the server enforces the same via access.write_scope, so this is
// UX — a view user still can't write even if a button leaks through).
function canEdit() {
    if (isAdmin() || isTenantAdmin()) return true;
    const p = currentUser?.permissions || {};
    return p.edit === true || p.console_write === true;
}

// Hide inline row Edit/Delete buttons in module tables from VIEW users (server
// enforces write_scope — this is UX only). Rather than wrap each per-row button
// pair (firewall/netbox/dns/dhcp/ldap, rendered by async loaders), toggle a root
// class that a one-time stylesheet keys off, so every title="Edit"/"Delete"
// button in the viewport — including ones added later by loaders — is covered.
function _applyEditVisibility() {
    if (!document.getElementById('lm-edit-vis-style')) {
        const s = document.createElement('style');
        s.id = 'lm-edit-vis-style';
        // Row-level write controls carry a descriptive title; hide them all from
        // view users (the server enforces regardless). Covers Edit/Delete plus the
        // netbox allocate/release and certificate renew/revoke row actions.
        const _t = ['Edit', 'Delete', 'Allocate IP', 'Return to pool', 'Release', 'Renew', 'Revoke'];
        s.textContent = _t.map(t => `:root.lm-no-edit #viewport button[title="${t}"]`).join(',') + '{display:none !important;}';
        document.head.appendChild(s);
    }
    document.documentElement.classList.toggle('lm-no-edit', !canEdit());
}

function showToast(message, type = 'info') {
    const colors = { success: '#01A982', error: '#e53e3e', info: '#4a5568' };
    const toast = document.createElement('div');
    toast.className = 'lm-toast';
    // Stack under any toasts already on screen so simultaneous ones (e.g. Apply
    // Schema's result + warning) don't overlap. Top-right of the viewport.
    const stack = document.querySelectorAll('.lm-toast').length;
    const topOffset = 1.5 + stack * 4.0; // rem
    toast.style.cssText = `
        position:fixed;top:${topOffset}rem;right:1.5rem;z-index:9999;
        display:flex;align-items:center;gap:.75rem;
        background:${colors[type] || colors.info};color:#fff;
        padding:.75rem 1rem .75rem 1.25rem;border-radius:.5rem;font-size:.875rem;
        box-shadow:0 4px 12px rgba(0,0,0,.2);opacity:0;
        transition:opacity .2s ease;max-width:20rem;`;
    const text = document.createElement('span');
    text.style.cssText = 'flex:1;white-space:pre-line;';
    text.textContent = message;
    toast.appendChild(text);
    const dismiss = () => {
        toast.style.opacity = '0';
        toast.addEventListener('transitionend', () => toast.remove());
    };
    const closeBtn = document.createElement('button');
    closeBtn.textContent = '×';
    closeBtn.setAttribute('aria-label', 'Dismiss');
    closeBtn.style.cssText = 'background:none;border:none;color:inherit;opacity:.75;' +
        'cursor:pointer;font-size:1.1rem;line-height:1;padding:0;';
    closeBtn.addEventListener('mouseenter', () => { closeBtn.style.opacity = '1'; });
    closeBtn.addEventListener('mouseleave', () => { closeBtn.style.opacity = '.75'; });
    closeBtn.addEventListener('click', dismiss);
    toast.appendChild(closeBtn);
    document.body.appendChild(toast);
    requestAnimationFrame(() => { toast.style.opacity = '1'; });
    setTimeout(dismiss, window.TOAST_DURATION_MS || 10000);
}

// Interactive confirm toast — a non-blocking replacement for window.confirm()
// on destructive actions (e.g. delete spoke/agent). Renders a toast carrying
// Cancel + Confirm buttons and returns a Promise<boolean>: true on Confirm,
// false on Cancel, dismiss, or timeout (a confirm prompt must default to the
// safe no-op choice if ignored). Stacks under existing toasts like showToast.
function showConfirmToast(message, opts = {}) {
    const { confirmLabel = 'Confirm', cancelLabel = 'Cancel', danger = true } = opts;
    return new Promise((resolve) => {
        const toast = document.createElement('div');
        toast.className = 'lm-toast';
        const stack = document.querySelectorAll('.lm-toast').length;
        const topOffset = 1.5 + stack * 4.0; // rem
        toast.style.cssText = `
            position:fixed;top:${topOffset}rem;right:1.5rem;z-index:9999;
            display:flex;flex-direction:column;gap:.6rem;
            background:#263040;color:#fff;
            padding:.85rem 1rem;border-radius:.5rem;font-size:.875rem;
            box-shadow:0 4px 12px rgba(0,0,0,.25);opacity:0;
            transition:opacity .2s ease;max-width:22rem;`;
        const text = document.createElement('div');
        text.style.cssText = 'white-space:pre-line;line-height:1.35;';
        text.textContent = message;
        toast.appendChild(text);

        const row = document.createElement('div');
        row.style.cssText = 'display:flex;gap:.5rem;justify-content:flex-end;';
        let settled = false;
        let timer;
        const close = (val) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            toast.style.opacity = '0';
            toast.addEventListener('transitionend', () => toast.remove());
            resolve(val);
        };
        const cancelBtn = document.createElement('button');
        cancelBtn.textContent = cancelLabel;
        cancelBtn.style.cssText = 'background:rgba(255,255,255,.15);border:none;color:#fff;' +
            'cursor:pointer;font-size:.8rem;font-weight:600;padding:.35rem .8rem;border-radius:.35rem;';
        cancelBtn.addEventListener('click', () => close(false));
        const okBtn = document.createElement('button');
        okBtn.textContent = confirmLabel;
        okBtn.style.cssText = `background:${danger ? '#e53e3e' : '#01A982'};border:none;color:#fff;` +
            'cursor:pointer;font-size:.8rem;font-weight:700;padding:.35rem .8rem;border-radius:.35rem;';
        okBtn.addEventListener('click', () => close(true));
        row.appendChild(cancelBtn);
        row.appendChild(okBtn);
        toast.appendChild(row);

        document.body.appendChild(toast);
        requestAnimationFrame(() => { toast.style.opacity = '1'; });
        okBtn.focus();
        timer = setTimeout(() => close(false), window.CONFIRM_TOAST_DURATION_MS || 12000);
    });
}

// Like showConfirmToast but with a text/password input. Resolves the entered
// string on confirm, or null on cancel/timeout. Used for the NetBox admin
// password reset knob.
function showPromptToast(message, opts = {}) {
    const { confirmLabel = 'OK', cancelLabel = 'Cancel', type = 'text', placeholder = '' } = opts;
    return new Promise((resolve) => {
        const toast = document.createElement('div');
        toast.className = 'lm-toast';
        const stack = document.querySelectorAll('.lm-toast').length;
        const topOffset = 1.5 + stack * 4.0;
        toast.style.cssText = `
            position:fixed;top:${topOffset}rem;right:1.5rem;z-index:9999;
            display:flex;flex-direction:column;gap:.6rem;
            background:#263040;color:#fff;
            padding:.85rem 1rem;border-radius:.5rem;font-size:.875rem;
            box-shadow:0 4px 12px rgba(0,0,0,.25);opacity:0;
            transition:opacity .2s ease;max-width:22rem;`;
        const text = document.createElement('div');
        text.style.cssText = 'white-space:pre-line;line-height:1.35;';
        text.textContent = message;
        toast.appendChild(text);

        const input = document.createElement('input');
        input.type = type;
        input.placeholder = placeholder;
        input.autocomplete = 'new-password';
        input.style.cssText = 'width:100%;box-sizing:border-box;padding:.4rem .6rem;border-radius:.35rem;' +
            'border:1px solid rgba(255,255,255,.25);background:rgba(255,255,255,.1);color:#fff;font-size:.85rem;';
        toast.appendChild(input);

        const row = document.createElement('div');
        row.style.cssText = 'display:flex;gap:.5rem;justify-content:flex-end;';
        let settled = false, timer;
        const close = (val) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            toast.style.opacity = '0';
            toast.addEventListener('transitionend', () => toast.remove());
            resolve(val);
        };
        const cancelBtn = document.createElement('button');
        cancelBtn.textContent = cancelLabel;
        cancelBtn.style.cssText = 'background:rgba(255,255,255,.15);border:none;color:#fff;' +
            'cursor:pointer;font-size:.8rem;font-weight:600;padding:.35rem .8rem;border-radius:.35rem;';
        cancelBtn.addEventListener('click', () => close(null));
        const okBtn = document.createElement('button');
        okBtn.textContent = confirmLabel;
        okBtn.style.cssText = 'background:#01A982;border:none;color:#fff;' +
            'cursor:pointer;font-size:.8rem;font-weight:700;padding:.35rem .8rem;border-radius:.35rem;';
        okBtn.addEventListener('click', () => close(input.value));
        input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') close(input.value);
            else if (e.key === 'Escape') close(null);
        });
        row.appendChild(cancelBtn);
        row.appendChild(okBtn);
        toast.appendChild(row);

        document.body.appendChild(toast);
        requestAnimationFrame(() => { toast.style.opacity = '1'; });
        input.focus();
        timer = setTimeout(() => close(null), window.PROMPT_TOAST_DURATION_MS || 30000);
    });
}

// ────────────────────────────────────────────────────────────────────────────
// "File a Bug" — footer button. Collects the user's explanation plus a
// browser-console buffer (window.__lmBugBuffer, installed at top of file),
// the serialized DOM, and an html2canvas screenshot, then POSTs it to the hub
// (/api/bug-report — auth-required, any logged-in user). The hub logs a short
// [bug-report] marker and stores the full artifacts on disk; bugfixer then
// files a (clean-body) GitHub issue and pulls the artifacts from the hub to use
// as AI-fix context. See plan bright-launching-thompson.md.
function fileBug() {
    // One modal at a time.
    const existing = document.getElementById('file-bug-modal');
    if (existing) { existing.remove(); return; }

    const modal = document.createElement('div');
    modal.id = 'file-bug-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm';
    modal.innerHTML = `
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-lg overflow-hidden">
            <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50">
                <h3 class="text-lg font-bold text-[#263040]">🐞 File a Bug</h3>
                <button onclick="this.closest('#file-bug-modal').remove()" class="text-slate-400 hover:text-slate-600 transition-colors">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                </button>
            </div>
            <div class="p-6 space-y-4">
                <div class="space-y-2">
                    <label class="text-xs text-slate-500 uppercase font-bold">What's wrong? <span class="text-red-500">*</span></label>
                    <textarea id="bug-description" rows="4" placeholder="Describe what you were doing and what went wrong — e.g. 'Clicked Save on the firewall rule form and the page went blank.'" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"></textarea>
                </div>
                <div class="space-y-2">
                    <label class="text-xs text-slate-500 uppercase font-bold">Severity (optional)</label>
                    <select id="bug-severity" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                        <option value="low">Low — minor / cosmetic</option>
                        <option value="medium" selected>Medium — broken feature, workaround exists</option>
                        <option value="high">High — feature unusable / data risk</option>
                    </select>
                </div>
                <p class="text-[11px] text-slate-400 leading-relaxed">
                    Your browser console log, the current page HTML, and a screenshot will be captured and sent to the hub.
                    BugFixer will open a GitHub issue and attempt a fix. The public issue contains only your explanation and
                    context — the console/HTML/screenshot stay on the hub and are used only as fix context.
                </p>
                <div id="bug-submit-status" class="text-xs text-slate-500 hidden"></div>
                <div class="pt-2 flex justify-end gap-3">
                    <button onclick="this.closest('#file-bug-modal').remove()" class="px-4 py-2 text-sm font-medium text-slate-600 hover:text-slate-800">Cancel</button>
                    <button id="bug-submit-btn" onclick="submitBugReport()" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm">Submit</button>
                </div>
            </div>
        </div>`;
    document.body.appendChild(modal);
    setTimeout(() => document.getElementById('bug-description')?.focus(), 50);
}

async function submitBugReport() {
    const explanation = (document.getElementById('bug-description')?.value || '').trim();
    if (!explanation) {
        showToast('Please describe what’s wrong before submitting', 'error');
        return;
    }
    const severity = document.getElementById('bug-severity')?.value || 'medium';
    const btn = document.getElementById('bug-submit-btn');
    const statusEl = document.getElementById('bug-submit-status');
    const setBusy = (msg) => {
        if (btn) { btn.disabled = true; btn.classList.add('opacity-60', 'cursor-wait'); btn.textContent = 'Submitting…'; }
        if (statusEl) { statusEl.textContent = msg; statusEl.classList.remove('hidden'); }
    };
    setBusy('Capturing console, HTML, and screenshot…');

    // Console buffer (installed at top of main.js).
    const consoleLogs = (window.__lmBugBuffer || [])
        .map(e => `[${e.ts}] ${e.level.toUpperCase()}: ${e.msg}`)
        .join('\n');

    // Raw DOM, truncated to keep the payload sane.
    const MAX_HTML = 256 * 1024;
    let html = '';
    try { html = document.documentElement.outerHTML || ''; } catch (_) { html = ''; }
    if (html.length > MAX_HTML) html = html.slice(0, MAX_HTML) + '\n<!-- truncated -->';

    // Screenshot via vendored html2canvas. Never block submission on failure.
    let screenshot = null;
    try {
        if (typeof html2canvas === 'function') {
            const canvas = await html2canvas(document.body, { scale: 1, useCORS: true, logging: false, backgroundColor: '#ffffff' });
            let dataUrl = canvas.toDataURL('image/png');
            // Re-encode as JPEG if the PNG is huge (keeps the WS/HTTP payload bounded).
            if (dataUrl && dataUrl.length > 4 * 1024 * 1024) {
                dataUrl = canvas.toDataURL('image/jpeg', 0.7);
            }
            screenshot = dataUrl;
        }
    } catch (e) {
        console.warn('File-a-Bug: screenshot capture failed', e);
        screenshot = null;
    }

    const payload = {
        explanation,
        severity,
        console_logs: consoleLogs,
        html,
        screenshot,
        context: {
            currentView,
            currentSubView,
            currentTenant,
            url: location.href,
            userAgent: navigator.userAgent,
            timestamp: Date.now(),
            hubVersion: window.__lmHubVersion || 'unknown',
            webuiVersion: window.__lmWebuiVersion || 'unknown',
            username: currentUser?.username || null,
        },
    };

    setBusy('Submitting to hub…');
    try {
        const res = await setupFetch('/api/bug-report', {
            method: 'POST',
            body: JSON.stringify(payload),
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        showToast(`Bug report submitted (id ${data.id || ''}) — bugfixer will file an issue`, 'success');
        document.getElementById('file-bug-modal')?.remove();
    } catch (err) {
        console.error('File-a-Bug: submit failed', err);
        if (statusEl) { statusEl.textContent = 'Failed to submit: ' + err.message; statusEl.classList.remove('hidden'); }
        showToast('Failed to submit bug report: ' + err.message, 'error');
        if (btn) { btn.disabled = false; btn.classList.remove('opacity-60', 'cursor-wait'); btn.textContent = 'Retry'; }
    }
}

function userAllowedTenants() {
    return currentUser?.tenants || [];
}

function canAccessTenant(tenantId) {
    if (isAdmin()) return true;
    const allowed = userAllowedTenants();
    return allowed.length === 0 || allowed.includes(tenantId);
}

// Can the CURRENT user bind a NEW device/instance to `spoke`? Mirrors the
// server-side access.can_bind_spoke: Global Admin → any spoke; tenant-admin →
// only a spoke assigned to their OWN tenant (strictly own, NOT shared); plain
// user → none. Used to filter the Add-device spoke dropdowns; the backend
// enforces the same rule, so this is UX only.
function _spokeBindable(spoke) {
    if (isAdmin()) return true;
    if (!isTenantAdmin()) return false;
    const t = spoke && spoke.tenant_id;
    return !!t && userAllowedTenants().includes(t);
}

// Tenant-scoped visibility of a spoke for the CURRENT user. NEVER narrows the
// admin all-tenants view. For a non-admin: a spoke bound to the SHARED tenant is
// visible to everyone (objects still subnet-scoped); a spoke bound to one of the
// user's own tenants is visible; a spoke bound to another tenant is hidden; and
// an UNASSIGNED spoke (no tenant_id) is admin-only (a holding state — the admin
// must assign it; it is NO LONGER treated as global). `spoke` is a
// /setup/pending_spokes row (carries `tenant_id` + `tenant_shared`). Mirrors the
// server-side access.spoke_visible_to_session. Used by _rebuildMainNav +
// _renderDashboardLists.
function _spokeVisibleToTenant(spoke) {
    if (isAdmin()) return true;                 // admin: all-tenants view unchanged
    if (spoke && spoke.tenant_shared) return true;  // shared tenant — visible to all
    const t = spoke && spoke.tenant_id;
    if (!t) return false;                       // unassigned → admin-only now
    return canAccessTenant(t);
}

// ─── Tenant prefix filtering ──────────────────────────────────────────────────

let _tenantPrefixes = [];  // e.g. ['172.16.0.0/23', '10.20.0.0/16']

function _ipToInt(ip) {
    return ip.split('.').reduce((a, o) => ((a << 8) + parseInt(o, 10)) >>> 0, 0);
}

function _isIPInCIDR(ip, cidr) {
    try {
        const [net, bits] = cidr.includes('/') ? cidr.split('/') : [cidr, '32'];
        const b = parseInt(bits, 10);
        const mask = b === 0 ? 0 : (~0 << (32 - b)) >>> 0;
        return (_ipToInt(ip) & mask) === (_ipToInt(net) & mask);
    } catch { return false; }
}

function _cidrsOverlap(a, b) {
    try {
        const [an, ab] = a.includes('/') ? a.split('/') : [a, '32'];
        const [bn, bb] = b.includes('/') ? b.split('/') : [b, '32'];
        const shorter = Math.min(parseInt(ab, 10), parseInt(bb, 10));
        const mask = shorter === 0 ? 0 : (~0 << (32 - shorter)) >>> 0;
        return (_ipToInt(an) & mask) === (_ipToInt(bn) & mask);
    } catch { return false; }
}

// Extract concrete IP/CIDR strings from a rule field. Returns null if the value
// is non-IP (alias name, 'any', empty) — null means "can't filter, pass through".
function _extractAddrs(val) {
    if (!val) return null;
    const s = String(val).trim();
    if (!s || s === 'any' || s === '*' || s === '—' || s === '-') return null;
    const hits = s.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\/\d{1,2})?)\b/g);
    return hits?.length ? hits : null;
}

function _addrInPrefixes(addr) {
    if (!_tenantPrefixes.length) return true;
    return addr.includes('/')
        ? _tenantPrefixes.some(p => _cidrsOverlap(addr, p))
        : _tenantPrefixes.some(p => _isIPInCIDR(addr, p));
}

/**
 * Return true if the item should be visible given the tenant's prefix list.
 * ipFields: the field names on the item that may contain IP addresses.
 *
 * Logic:
 *  - Admins and users without prefixes see everything.
 *  - For each IP field, extract concrete addresses. If any address matches
 *    a tenant prefix → show. If a field contains only alias names / 'any' →
 *    treat as a wildcard and pass through (we can't resolve aliases here).
 *  - If no field contains a concrete IP → pass through (err on the side of showing).
 */
function itemInTenantPrefixes(item, ipFields) {
    if (isAdmin() || !_tenantPrefixes.length) return true;
    let hasConcreteIP = false;
    for (const field of ipFields) {
        const addrs = _extractAddrs(item[field]);
        if (addrs === null) continue;          // alias / 'any' — skip this field
        hasConcreteIP = true;
        if (addrs.some(a => _addrInPrefixes(a))) return true;
    }
    return !hasConcreteIP;  // no concrete IPs found → show (can't filter)
}

async function loadTenantPrefixes() {
    if (isAdmin()) { _tenantPrefixes = []; return; }
    try {
        // ?tenant=currentTenant scopes prefixes to the selected tenant so the
        // client-side filter (NAT/DHCP/DNS/Interfaces) tracks the switcher for
        // multi-tenant users; without it, switching tenant would leave the
        // client filtering on the stale session-tenant prefixes. Admins early-
        // return above (they don't client-filter; the server filters by ?tenant=).
        const qs = currentTenant ? `?tenant=${encodeURIComponent(currentTenant)}` : '';
        const r = await fetch(`/auth/prefixes${qs}`, { credentials: 'same-origin' });
        if (!r.ok) { _tenantPrefixes = []; return; }
        const d = await r.json();
        _tenantPrefixes = d.prefixes || [];
        if (_tenantPrefixes.length) {
            console.log(`[Tenant] Prefix filter active: ${_tenantPrefixes.join(', ')}`);
        }
    } catch { _tenantPrefixes = []; }
}

// NOTE: firewall-rule subnet filtering is enforced server-side (the hub's
// filter_firewall_rules resolves OPNsense alias/interface names to concrete
// networks before matching tenant prefixes). The former client-side
// firewallRuleInTenantPrefixes / _isWildcard helpers were removed because they
// could not resolve aliases and would hide rules the server correctly showed.
// itemInTenantPrefixes below remains for the field-based NAT/DHCP/DNS/Interfaces
// views (concrete-IP fields), also enforced server-side.

let logRefreshInterval = null;
let _cacheStatusPoller = null;

// 60s TTL cache of the pxmx agents list for the dashboard sidebar —
// _renderDashboardLists runs on every 10s updateStatus() poll, and re-fetching
// /api/pxmx/agents each tick is wasted work (pxmx agent topology changes
// rarely). loadSpokesAndAgents (Setup → Spokes & Agents Refresh) fetches
// directly and doesn't read this cache, so a manual refresh stays live.
let _pxmxAgentsCache = null;

const _CACHE_MODULE_LABELS = {
    rules: 'Firewall Rules', nat: 'NAT Policies', dhcp: 'DHCP Leases',
    dns: 'DNS Records', interfaces: 'Interfaces', cppm_sessions: 'Access Tracker',
    cppm_devices: 'My Devices', netbox_racks: 'Racks', netbox_devices: 'Devices',
    netbox_ips: 'IP Addresses', netbox_prefixes: 'Prefixes', pxmx_vms: 'Virtual Machines',
};

function _startCacheStatusPolling() {
    if (isAdmin() || _cacheStatusPoller) return;
    _cacheStatusPoller = setInterval(async () => {
        try {
            const r = await fetch('/auth/cache-status', { credentials: 'same-origin' });
            if (!r.ok) { _stopCacheStatusPolling(); return; }
            const d = await r.json();
            _updateCacheBar(d);
            if (d.all_ready) _stopCacheStatusPolling();
        } catch { _stopCacheStatusPolling(); }
    }, 1500);
}

function _stopCacheStatusPolling() {
    clearInterval(_cacheStatusPoller);
    _cacheStatusPoller = null;
    setTimeout(() => {
        const bar = document.getElementById('cache-status-bar');
        if (bar) bar.classList.add('hidden');
    }, 2000);
}

function _updateCacheBar(data) {
    const bar = document.getElementById('cache-status-bar');
    const txt = document.getElementById('cache-status-text');
    if (!bar || !txt) return;
    const loading = (data.loading || []).map(k => {
        const base = k.split(':')[0];
        return _CACHE_MODULE_LABELS[base] || base;
    });
    if (loading.length) {
        bar.classList.remove('hidden');
        txt.textContent = 'Caching: ' + [...new Set(loading)].join(' · ');
    } else if (data.all_ready) {
        txt.textContent = 'Data cached and ready';
        setTimeout(() => bar.classList.add('hidden'), 1500);
    }
}

async function refreshModuleCache(moduleKey) {
    try {
        await fetch(`/auth/cache/refresh?module=${encodeURIComponent(moduleKey)}`,
            { method: 'POST', credentials: 'same-origin' });
    } catch (err) { console.error('refreshModuleCache: cache refresh failed for ' + moduleKey, err); }
}

const VIEW_SUBMENUS = {
    dashboard: ['Overview'],
    settings: ['General', 'User Access', 'SSO', 'Tenant Config', 'Sync', 'Hub Status', 'API Tokens', 'Self-Backup'],
    logs:     ['logs-hub', 'logs-pxmx', 'logs-opn', 'logs-netbox', 'logs-cppm', 'logs-cs', 'logs-agents', 'logs-recovery', 'logs-errors', 'logs-bugs'],
    setup: ['Spokes & Agents', 'Module Management', 'Simulations', 'Remote Console'],
    opnsense: ['Firewall Rules', 'NAT Policies', 'DNS Records', 'Aliases', 'DHCP Leases', 'Interfaces'],
    pxmx: ['Overview', 'Virtual Machines', 'Settings'],
    ldap: ['OUs', 'Users', 'Groups'],
    cppm: ['NAC Status', 'Access Tracker', 'My Devices', 'Unknown Devices'],
    cs: ['Dashboard', 'Clients', 'Central', 'VM Server', 'Config', 'Setup', 'Spoke Management'],
    netbox: ['Overview', 'Devices', 'Racks', 'Prefixes', 'IP Addresses'],
    dns: ['Records', 'Statistics', 'Forwarders'],
    dhcp: ['Overview', 'Subnets', 'Leases', 'Reservations'],
    nw: ['Devices', 'MAC Table', 'ARP', 'Interfaces'],
};

// Two-tier horizontal nav: child tabs that appear in #top-nav-secondary under
// a primary. Only cs (Simulations) uses this today — its primaries mirror the
// solutions-hpe webui-hub tenant sub-nav, and the child sets mirror webui-hub's
// own subtab lists (VM Server 11, Setup 7, Central 3, Simulations 3, Clients 3,
// Config 0). Primaries not listed here (Spoke Management) have no
// children → render directly, no secondary strip. Config has NO sub-tabs — the
// former "Simulation" tab is now the Config root (the "API" tab was dropped);
// loadCSData's `case 'Config'` renders csRenderConfigSimulation directly.
const VIEW_CHILDREN = {
    cs: {
        'Dashboard': ['Checks', 'Hardware', 'Client Count'],
        'Clients':     ['All', 'T1', 'T2', 'T3'],
        'Central':     ['Sites', 'Alerts', 'Insights', 'Clients', 'Hardware'],
        'VM Server':   ['Overview', 'VMs', 'Console', 'Terminal', 'USB', 'IoT', 'VirtualHere', 'Command Queue', 'Details'],
        'Setup':       ['General', 'Central API', 'Proxmox', 'GitHub', 'Security', 'Notifications'],
    },
};

// First child of a primary, or '' if the primary/module has no children.
function _csDefaultChild(viewId, primary) {
    const kids = (VIEW_CHILDREN[viewId] || {})[primary];
    return (kids && kids.length) ? kids[0] : '';
}

const SUBMENU_LABELS = {
    'logs-hub': 'Hub',
    'logs-errors': 'Error',
    'logs-recovery': 'Recovery',
    'logs-bugs': 'Bug Report',
    'logs-opn': 'Firewall',
    'logs-pxmx': 'Hypervisor',
    'logs-cppm': 'Security/NAC',
    'logs-netbox': 'IPAM',
    'logs-cs': 'Simulations',
    'logs-agents': 'Agents',
};

// Logs submenu: only show a module's log tab when that module is actually
// installed/approved (window.activeProducts, rebuilt by _rebuildMainNav from
// /setup/pending_spokes + active connections). Hub-native tabs (hub, recovery,
// errors, bugs) always show. logs-agents shows when any agent is connected
// (window.hasAgents, set by _renderDashboardLists). The module→product map
// mirrors PRODUCT_MAP so a tab appears exactly when the matching spoke exists.
const LOG_MODULE_PRODUCT = {
    'logs-pxmx':   'pxmx',
    'logs-opn':    'opnsense',
    'logs-netbox': 'netbox',
    'logs-cppm':   'cppm',
    'logs-cs':     'cs',
};
function logsSubmenu() {
    const products = window.activeProducts || new Set();
    const hasAgents = !!window.hasAgents;
    // Preserve the canonical order: hub first, then installed module tabs in
    // their fixed sequence, agents, then the hub-native filtered views last.
    const order = ['logs-hub', 'logs-pxmx', 'logs-opn', 'logs-netbox', 'logs-cppm', 'logs-cs', 'logs-agents', 'logs-recovery', 'logs-errors', 'logs-bugs'];
    return order.filter(m => {
        if (m === 'logs-hub' || m === 'logs-recovery' || m === 'logs-errors' || m === 'logs-bugs') return true;
        if (m === 'logs-agents') return hasAgents;
        const product = LOG_MODULE_PRODUCT[m];
        return !product || products.has(product);
    });
}

async function loadFirewalls() {
    try {
        const response = await setupFetch('/setup/firewalls');
        if (!response.ok) throw new Error('Failed to fetch firewalls');
        const data = await response.json();
        return data.firewalls || [];
    } catch (err) {
        console.error('Error loading firewalls:', err);
        return [];
    }
}

async function setTenant(tenant) {
    currentTenant = tenant;
    localStorage.setItem('lm_tenant', tenant);

    try {
        const response = await setupFetch('/setup/tenant', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ tenant_id: tenant, config: { active: true } })
        });
        if (response.ok) {
            console.log(`Switched to tenant: ${tenant}`);
            // Reload tenant prefixes for the newly-selected tenant BEFORE the
            // view re-renders, so the client-side subnet filter (NAT/DHCP/DNS/
            // Interfaces) and the server-side ?tenant= filter on the firewall
            // fetch agree on the same tenant. Without this, a multi-tenant user
            // switching tenant would filter on stale session-tenant prefixes.
            await loadTenantPrefixes();
            // Preserve the active sub-view across a tenant switch. setView()
            // re-renders the whole view and resets currentSubView to the first
            // sub-menu (Overview/Devices), so a user on Prefixes who switches
            // tenant would be bounced back to the default tab. Instead, just
            // reload the current sub-view's data for the new tenant — the view
            // layout (nav/header) is unchanged, only the tenant filter moved.
            // Fall back to setView() only if the recorded sub-view isn't valid
            // for the current view (e.g. view changed mid-flight).
            const subs = VIEW_SUBMENUS[currentView] || [];
            if (subs.includes(currentSubView)) {
                setSubView(currentSubView);
            } else {
                setView(currentView);
            }
        }
    } catch (err) {
        console.error('Failed to set tenant', err);
    }
}

async function updateGlobalConfig(key, value) {
    try {
        await setupFetch('/setup/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ config: { [key]: value } })
        });
    } catch (err) {
        console.error('Failed to update config', err);
    }
}

async function scanGitHubRepos() {
    const btn = event?.target;
    const origText = btn?.textContent;
    if (btn) { btn.disabled = true; btn.textContent = 'Scanning…'; }
    try {
        const response = await setupFetch('/setup/github-repos');
        if (!response.ok) throw new Error('Failed to fetch repos');
        const data = await response.json();
        const repos = data.repos;

        if (repos.length === 0) {
            showToast('No repositories found.', 'info');
            return;
        }

        // Map each field to the repo name(s) that should fill it
        const fieldMap = {
            'update-source-hub':    ['lm'],
            'update-source-pxmx':   ['pxmx'],
            'update-source-opn':    ['opnsense', 'opn'],
            'update-source-cs':     ['cs'],
            'update-source-cppm':   ['cppm', 'clearpass'],
            'update-source-netbox': ['netbox'],
            'update-source-ldap':   ['ldap'],
            'update-source-nw':     ['nw'],
            'update-source-le':     ['le', 'certificates'],
        };

        const repoByName = Object.fromEntries(repos.map(r => [r.name.toLowerCase(), r]));
        const filled = [], missing = [];

        for (const [fieldId, candidates] of Object.entries(fieldMap)) {
            const el = document.getElementById(fieldId);
            if (!el) continue;
            const match = candidates.map(c => repoByName[c]).find(Boolean);
            if (match) {
                el.value = match.url;
                filled.push(match.name);
            } else {
                missing.push(candidates[0]);
            }
        }

        const msg = filled.length
            ? `Auto-filled ${filled.length} source(s): ${filled.join(', ')}.`
            : 'No matching repositories found.';
        const missMsg = missing.length ? ` Not found: ${missing.join(', ')}` : '';
        showToast(msg + missMsg + (filled.length ? ' Click Save to apply.' : ''), filled.length ? 'success' : 'info');
    } catch (err) {
        showToast('Error scanning GitHub: ' + err.message, 'error');
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = origText; }
    }
}

// Populate a <select> with the branches of `repo` (a module key like 'hub',
// an "owner/name", or a full git URL) from the hub's git-ls-remote endpoint,
// preserving `currentVal` as the selected option even if it isn't in the list
// (a custom/feature branch). Degrades gracefully: on any fetch failure the
// select just holds the current value so the branch isn't lost.
async function populateBranchSelect(selectId, repo, currentVal) {
    const el = document.getElementById(selectId);
    if (!el) return;
    const cur = currentVal || 'main';
    let branches = null;
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 9000);
    try {
        const res = await setupFetch('/setup/repo-branches?repo=' + encodeURIComponent(repo), { signal: ctrl.signal });
        if (res.ok) {
            const data = await res.json();
            if (Array.isArray(data.branches) && data.branches.length) branches = data.branches;
        }
    } catch (err) { console.warn('populateBranchSelect: could not list branches for', repo, err); }
    finally { clearTimeout(timer); }
    if (!branches) branches = [cur];
    if (cur && !branches.includes(cur)) branches = [cur, ...branches];
    el.innerHTML = branches.map(b =>
        `<option value="${escapeHtml(b)}" ${b === cur ? 'selected' : ''}>${escapeHtml(b)}</option>`).join('');
    el.value = cur;
}

async function saveUpdateSources() {
    const formSources = {
        hub: document.getElementById('update-source-hub').value,
        pxmx: document.getElementById('update-source-pxmx').value,
        opnsense: document.getElementById('update-source-opn').value,
        cs: document.getElementById('update-source-cs').value,
        cppm: document.getElementById('update-source-cppm').value,
        netbox: document.getElementById('update-source-netbox').value,
        ldap: document.getElementById('update-source-ldap').value,
        nw: document.getElementById('update-source-nw').value,
        le: document.getElementById('update-source-le').value,
    };
    const globalBranch = document.getElementById('global-branch').value;

    // MERGE over the existing update_sources so keys NOT exposed in this form
    // (legacy "opn", "agent", "qa", …) are preserved. POST /setup/config does
    // gc.update(config) — a TOP-LEVEL merge — so the entire update_sources dict
    // is replaced by whatever we send. Sending only the form keys would silently
    // wipe e.g. update_sources.le the installer seeded (the bug that left the le
    // spoke un-updatable → "Unknown command: LE_SET_DNS_CRED"). Overlay the form
    // on the fetched existing sources so nothing is dropped on save.
    let existingSources = {};
    try {
        const r = await setupFetch('/setup/config');
        if (r.ok) {
            const data = await r.json();
            existingSources = (data && data.global_config && data.global_config.update_sources) || {};
        }
    } catch (e) { /* fetch failed — fall back to form-only below */ }
    const sources = Object.assign({}, existingSources, formSources);

    try {
        const response = await setupFetch('/setup/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ config: { update_sources: sources, global_branch: globalBranch } })
        });
        if (response.ok) {
            showToast('Update sources and global branch saved successfully!', 'success');
        } else {
            showToast('Failed to save update sources.', 'error');
        }
    } catch (err) {
        showToast('Error saving update sources: ' + err.message, 'error');
    }
}


async function loadSetupConfig() {
    try {
        const response = await setupFetch('/setup/config');
        if (!response.ok) return;
        const data = await response.json();
        const config = data.global_config || {};

        // Auto-update checkbox/interval removed — the System → Sync "GitHub
        // Repo Sync" card now owns the schedule (global_config.repo_sync).

        const tsEl = document.getElementById('last-update-ts');
        if (tsEl && config.last_update_ts) {
            const date = new Date(config.last_update_ts * 1000);
            tsEl.textContent = `Last check: ${date.toLocaleString()}`;
        }

        const sources = config.update_sources || {};
        // Migrate legacy "opn" key → canonical "opnsense" so deployments that
        // saved the OPNsense repo URL before the key-mismatch fix still show it
        // in the field (and a re-save persists it under the key the hub reads).
        if (sources.opn && !sources.opnsense) sources.opnsense = sources.opn;
        const globalBranch = config.global_branch || 'main';
        // Populate the Global Branch dropdown from the configured hub repo's
        // live branch list (via git ls-remote on the hub); keeps the saved
        // branch selected even if listing fails or it's a custom branch.
        populateBranchSelect('global-branch', sources.hub || 'hub', globalBranch);
        const sourceFields = {
            'hub': 'update-source-hub',
            'pxmx': 'update-source-pxmx',
            'opnsense': 'update-source-opn',
            'cs': 'update-source-cs',
            'cppm': 'update-source-cppm',
            'netbox': 'update-source-netbox',
            'ldap': 'update-source-ldap',
            'nw': 'update-source-nw',
            'le': 'update-source-le'
        };
        for (const [key, id] of Object.entries(sourceFields)) {
            const el = document.getElementById(id);
            if (el) el.value = sources[key] || '';
        }

        // IPAM → CPPM endpoint sync schedule (System → Sync).
        // The source dropdown is populated by loadEndpointSyncSources; here we
        // only set its value if the element already exists.
        const epSync = config.netbox_cppm_sync || {};
        const epChk = document.getElementById('ep-sync-enabled');
        const epSrc = document.getElementById('ep-sync-source');
        const epMode = document.getElementById('ep-sync-mode');
        const epInt = document.getElementById('ep-sync-interval');
        const epTime = document.getElementById('ep-sync-time');
        if (epChk) epChk.checked = epSync.enabled === true;
        if (epSrc && epSync.source) epSrc.value = epSync.source;
        if (epMode) epMode.value = epSync.mode === 'daily' ? 'daily' : 'interval';
        if (epInt) epInt.value = Math.max(1, Math.round((epSync.interval_seconds || 3600) / 60));
        if (epTime) epTime.value = epSync.daily_time || '02:00';

        if ((currentView === 'setup' && currentSubView === 'Proxmox') || (currentView === 'pxmx' && currentSubView === 'Configuration')) {
            loadProxmoxConfig(config.pxmx || {});
        } else if ((currentView === 'setup' && currentSubView === 'OPNsense') || (currentView === 'opnsense' && currentSubView === 'Configuration')) {
            loadOpnsenseConfig(config.opn || {});
        } else if ((currentView === 'setup' && currentSubView === 'Client Sim') || (currentView === 'cs' && currentSubView === 'Configuration')) {
            loadCSConfig(config.cs || {});
        } else if (currentView === 'setup' && currentSubView === 'CPPM Config') {
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

function fmtDate(val) {
    if (!val) return '—';
    // Unix timestamp (integer seconds, or fractional seconds — time.time() floats)
    const num = Number(val);
    if (!isNaN(num) && String(val).trim().match(/^\d+(\.\d+)?$/)) return new Date(num * 1000).toLocaleString();
    // Normalize: replace space separator with T so Safari parses it
    const s = String(val).trim().replace(' ', 'T');
    const d = new Date(s);
    return isNaN(d) ? String(val) : d.toLocaleString();
}

// Parse a ClearPass `acctstarttime` (OpenAPI date-time / RFC 3339, ISO 8601).
// ClearPass commonly emits "YYYY-MM-DD HH:MM:SS(.ffffff)" in server-local time
// (space-separated, microseconds, no tz marker); JS Date only guarantees
// millisecond (3-digit) fractional precision, so Safari treats 6-digit
// microseconds as Invalid Date and fmtDate falls through to the raw string.
// We normalize space→T, clamp fractional seconds to 3 digits, and fall back to
// explicit field parsing so it always renders as a clean, human-readable time.
function _parseSessionDate(val) {
    if (!val) return null;
    const s = String(val).trim();
    if (/^\d+(\.\d+)?$/.test(s)) return new Date(Number(s) * 1000); // epoch seconds (incl. fractional, e.g. 1782694940.000000)
    let norm = s.replace(' ', 'T');
    // Clamp fractional seconds to exactly 3 digits (drop microseconds), keep
    // any trailing Z or ±hh:mm offset intact.
    norm = norm.replace(/(\.\d{1,6})(Z|[+-]\d{2}:?\d{2}|$)/, (m, frac, after) =>
        '.' + frac.slice(1).padEnd(3, '0').slice(0, 3) + after);
    let d = new Date(norm);
    if (!isNaN(d)) return d;
    // Last-resort explicit parse: YYYY-MM-DDTHH:MM:SS (local time).
    const m = norm.match(/(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})/);
    if (m) return new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]),
        Number(m[4]), Number(m[5]), Number(m[6]));
    return null;
}

function _relTimeAgo(d) {
    if (!d || isNaN(d)) return '';
    const sec = Math.floor((Date.now() - d.getTime()) / 1000);
    if (sec < 0 || sec > 60 * 60 * 24 * 7) return ''; // future or > 1 week: skip
    if (sec < 60) return ` (${sec}s ago)`;
    if (sec < 3600) return ` (${Math.floor(sec / 60)}m ago)`;
    if (sec < 86400) return ` (${Math.floor(sec / 3600)}h ${Math.floor((sec % 3600) / 60)}m ago)`;
    return ` (${Math.floor(sec / 86400)}d ago)`;
}

// Human-readable Start Time for Access Tracker / device sessions, with an
// optional relative "Xm ago" hint when the session started within the last week.
function fmtSessionStart(val) {
    const d = _parseSessionDate(val);
    if (!d || isNaN(d)) return val ? String(val) : '—';
    const abs = d.toLocaleString(undefined, {
        month: 'short', day: 'numeric', year: 'numeric',
        hour: 'numeric', minute: '2-digit',
    });
    return abs + _relTimeAgo(d);
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
    const fields = { 'cppm-host': 'host', 'cppm-client-id': 'client_id', 'cppm-client-secret': 'client_secret', 'cppm-user': 'user', 'cppm-pass': 'password' };
    for (const [id, key] of Object.entries(fields)) {
        const el = document.getElementById(id);
        if (el) el.value = config[key] || '';
    }
}

async function loadTenantConfig() {
    const listEl = document.getElementById('tenant-list');
    if (!listEl) return;

    try {
        const response = await setupFetch('/setup/tenants');
        if (!response.ok) throw new Error('Failed to fetch tenants');
        const data = await response.json();
        window._sharedTenantId = data.shared_tenant_id || null;  // for the shared badge / gate
        const tenants = data.tenants || [];

        listEl.innerHTML = tenants.map(t => {
            const accessible = canAccessTenant(t.id);
            const isActive = t.id === currentTenant;
            // A Global Admin may edit ANY tenant; a tenant Admin may edit only
            // its accessible (own) tenants. Plain users get no edit affordance.
            const canEdit = isAdmin() || (isTenantAdmin() && accessible);
            const btnCls = isActive
                ? 'bg-green-500 text-white cursor-default'
                : accessible
                    ? 'bg-slate-100 hover:bg-green-100 text-slate-600 hover:text-green-700 cursor-pointer'
                    : 'bg-slate-50 text-slate-300 cursor-not-allowed';
            const btnLabel = isActive ? 'Active' : accessible ? 'View as' : 'No access';
            const btnAction = accessible && !isActive ? `onclick="viewAsTenant('${t.id}')"` : '';
            return `
            <div class="flex items-center justify-between p-2 rounded-md transition-all ${isActive ? 'bg-green-50 border-l-4 border-green-500' : 'bg-white border border-slate-200'}">
                <div class="flex items-center gap-2 flex-1 ${canEdit ? 'cursor-pointer group' : ''}" ${canEdit ? `onclick="editTenant('${t.id}')"` : ''}>
                    <span class="text-xs font-medium text-slate-700 ${canEdit ? 'group-hover:text-green-600' : ''}">${t.name}</span>
                    ${t.description ? `<span class="text-[10px] text-slate-400 hidden sm:inline">${t.description}</span>` : ''}
                </div>
                <div class="flex items-center gap-2">
                    <span class="text-[10px] font-mono text-slate-400">${t.slug || t.id}</span>
                    <button ${btnAction} title="${btnLabel}" class="text-[10px] px-2 py-0.5 rounded ${btnCls} transition-colors">
                        ${btnLabel}
                    </button>
                </div>
            </div>`;
        }).join('');
    } catch (err) {
        console.error('Error loading tenant config:', err);
        listEl.innerHTML = `<div class="py-4 text-center text-red-500 text-xs">Error loading tenants: ${err.message}</div>`;
    }
}

async function editTenant(tenantId) {
    const editor = document.getElementById('tenant-editor');
    const emptyState = document.getElementById('tenant-empty-state');
    if (!editor) return;

    // A tenant Admin edits via the tenant-scoped route (GET /api/tenant/{id});
    // a Global Admin uses the /setup/ route (full record). The tenant-scoped
    // route enforces ownership server-side (the {id} must be in user.tenants).
    const tadm = isTenantAdmin();
    const url = tadm ? `/api/tenant/${encodeURIComponent(tenantId)}`
                     : `/setup/tenants/${encodeURIComponent(tenantId)}`;
    const fetcher = tadm ? (u, o) => fetch(u, { credentials: 'same-origin', ...(o||{}) })
                         : setupFetch;

    try {
        const response = await fetcher(url);
        if (!response.ok) throw new Error('Failed to fetch tenant details');
        const data = await response.json();
        const config = data.config || {};

        document.getElementById('edit-tenant-id').textContent = tenantId;
        document.getElementById('tenant-name').value = config.name || tenantId;
        document.getElementById('tenant-active').checked = (currentTenant === tenantId);
        const _shEl = document.getElementById('tenant-shared');
        if (_shEl) _shEl.checked = !!config.shared;

        const quotas = config.quotas || {};
        document.getElementById('quota-vm').value = quotas.vm || 0;
        document.getElementById('quota-cppm').value = quotas.cppm || 0;
        document.getElementById('quota-opn').value = quotas.opn || 0;

        // Tenant scoping fields (read-only for a tenant Admin — re-scoping to
        // another tenant's NetBox/Proxmox/LDAP would be a cross-tenant escalation).
        document.getElementById('tenant-netbox-slug').value  = config.netbox_tenant_slug || '';
        document.getElementById('tenant-proxmox-tag').value  = config.proxmox_tag        || '';
        document.getElementById('tenant-ldap-base-dn').value = config.ldap_base_dn       || '';
        const lockScoping = tadm;
        ['tenant-netbox-slug', 'tenant-proxmox-tag', 'tenant-ldap-base-dn', 'tenant-active'].forEach(id => {
            const el = document.getElementById(id);
            if (!el) return;
            el.disabled = lockScoping;
            el.classList.toggle('bg-slate-100', lockScoping);
            el.classList.toggle('cursor-not-allowed', lockScoping);
        });

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
    const _v = id => (document.getElementById(id)?.value || '').trim();
    const config = {
        name: _v('tenant-name'),
        quotas: {
            vm:   parseInt(document.getElementById('quota-vm').value)   || 0,
            cppm: parseInt(document.getElementById('quota-cppm').value) || 0,
            opn:  parseInt(document.getElementById('quota-opn').value)  || 0,
        },
        netbox_tenant_slug: _v('tenant-netbox-slug'),
        proxmox_tag:        _v('tenant-proxmox-tag'),
        ldap_base_dn:       _v('tenant-ldap-base-dn'),
    };
    // Shared-tenant flag is a Global-Admin decision (designates the one tenant
    // whose spokes are visible to all). Only sent by an admin; the tenant-admin
    // save route ignores it server-side.
    const _shEl = document.getElementById('tenant-shared');
    if (_shEl && isAdmin()) config.shared = _shEl.checked;

    try {
        // A tenant Admin saves via the tenant-scoped route (POST
        // /api/tenant/{id}); the server drops scoping/active fields it cannot
        // set, so editing is confined to name/description/quotas for its OWN
        // tenant. A Global Admin saves via /setup/tenant (full record).
        const tadm = isTenantAdmin();
        const url = tadm ? `/api/tenant/${encodeURIComponent(tenantId)}`
                         : '/setup/tenant';
        const fetcher = tadm ? (u, o) => fetch(u, { credentials: 'same-origin', ...(o||{}) })
                             : setupFetch;
        const body = tadm ? { config } : { tenant_id: tenantId, config };
        const response = await fetcher(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        if (response.ok) {
            alert('Tenant configuration saved successfully!');
            await loadTenantConfig();
        } else {
            const d = await response.json().catch(() => ({}));
            alert('Failed to save tenant configuration: ' + (d.detail || response.statusText));
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
        const response = await setupFetch('/setup/tenants', {
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

async function syncTenantsFromNetBox() {
    const btn = event.target;
    const orig = btn.textContent;
    btn.textContent = 'Syncing…';
    btn.disabled = true;
    try {
        const resp = await setupFetch('/setup/sync-tenants', { method: 'POST' });
        const data = await resp.json();
        if (resp.ok) {
            await loadTenantConfig();
            const msg = data.message || `Sync complete`;
            alert(msg);
        } else {
            alert('Sync failed: ' + (data.detail || resp.statusText));
        }
    } catch (err) {
        alert('Sync error: ' + err.message);
    } finally {
        btn.textContent = orig;
        btn.disabled = false;
    }
}

async function viewAsTenant(tenantId) {
    if (!canAccessTenant(tenantId)) {
        console.warn(`Tenant switch to '${tenantId}' blocked — not in user's allowed list`);
        return;
    }
    await setTenant(tenantId);
    await loadTenantConfig();
    // Refresh the header chip label to the newly active tenant.
    const labelEl = document.getElementById('user-chip-tenant');
    if (labelEl) {
        const pick = (window._lmTenantPicker || []).find(t => t.id === tenantId);
        labelEl.textContent = (pick && pick.name) || tenantId;
    }
    // Re-mark the active item in the picker (bold/green) and close the menu.
    document.querySelectorAll('#tenant-picker-menu button[data-tid]').forEach(b => {
        const on = b.dataset.tid === tenantId;
        b.classList.toggle('font-bold', on);
        b.classList.toggle('text-[#01A982]', on);
    });
    closeTenantPicker();
    // Reload any open spoke data views so they reflect the tenant filter
    const activeMain = document.querySelector('[data-active-main]')?.dataset?.activeMain;
    if (activeMain) {
        showSection(activeMain);
    }
}

// ── Tenant picker dropdown (click-toggled, not hover) ───────────────────────
// The old hover-only menu vanished mid-click: the mt-1 gap between the button
// and the absolute menu left the wrapper's hover region, so group-hover
// deactivated before the cursor reached an item. Click-toggle + outside-click
// keeps it open until the user picks a tenant or clicks away.
function toggleTenantPicker(evt) {
    if (evt) evt.stopPropagation();
    const m = document.getElementById('tenant-picker-menu');
    if (m) m.classList.toggle('hidden');
}
function closeTenantPicker() {
    const m = document.getElementById('tenant-picker-menu');
    if (m) m.classList.add('hidden');
}
let _tpListenersBound = false;
function _bindTenantPickerListeners() {
    if (_tpListenersBound) return;
    _tpListenersBound = true;
    document.addEventListener('click', (e) => {
        const wrap = document.getElementById('tenant-picker-wrap');
        if (wrap && !wrap.contains(e.target)) closeTenantPicker();
    });
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeTenantPicker(); });
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
        const firewalls = await _ensureFirewalls();
        if (firewalls.length === 0) {
            alert('No firewalls configured to refresh.');
            return;
        }
        let ok = 0, fail = 0;
        for (const fw of firewalls) {
            const r = await fetch(`/api/firewall/${fw.id}/refresh`);
            if (r.ok) ok++; else fail++;
        }
        alert(`Refreshed cache for ${ok} firewall(s)${fail ? ` (${fail} failed)` : ''}.`);
        console.log(`Firewall cache refresh: ${ok} ok, ${fail} failed of ${firewalls.length}`);

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

// Shared renderer for one sidebar card row in the dashboard Spokes/Agents lists
// (called by _renderDashboardLists() below). `status` is 'online' | 'pending' |
// 'offline'. The dot + badge color scheme is identical for spokes and agents:
//   online  -> green dot (8px glow) + green "Online" badge
//   pending -> amber dot + amber "Pending" badge
//   offline -> slate dot + slate "Offline" badge
// `spokeVariant` adds the hover-border + group-hover name styling used only on
// the Spokes list; the Agents list passes false for the plain container. This
// preserves the exact container/name classes the two lists had before the
// refactor. NOTE: the Setup → Spokes & Agents admin table (loadSpokesAndAgents)
// intentionally does NOT use this helper — its rows are full <table> rows with
// action buttons and a different color scheme (bg-yellow-400 pending, green
// dot without the 8px glow), so routing them here would change their output.
function _renderSpokeAgentRow(label, mod, status, spokeVariant, tenant) {
    const dot = status === 'online'
        ? 'bg-green-500 shadow-[0_0_8px_rgba(34,197,94,0.6)]'
        : (status === 'pending' ? 'bg-amber-400' : 'bg-slate-400');
    const badge = status === 'online'
        ? '<span class="text-[10px] uppercase tracking-widest text-green-600 font-bold">Online</span>'
        : (status === 'pending'
            ? '<span class="text-[10px] uppercase tracking-widest text-amber-500 font-bold">Pending</span>'
            : '<span class="text-[10px] uppercase tracking-widest text-slate-400 font-bold">Offline</span>');
    const container = spokeVariant
        ? 'flex items-center justify-between p-3 rounded-lg bg-slate-50 border border-slate-200 hover:border-green-500 transition-all group'
        : 'flex items-center justify-between p-3 rounded-lg bg-slate-50 border border-slate-200';
    const nameCls = spokeVariant
        ? 'text-sm font-medium text-slate-700 group-hover:text-green-600 transition-colors'
        : 'text-sm font-medium text-slate-700';
    // Read-only tenant chip: shows which tenant a spoke is bound to (or nothing
    // when unassigned/global). Additive — surfaces the binding already returned
    // by /setup/pending_spokes so an admin can see at a glance which tenant owns
    // a spoke without opening Setup → Spokes & Agents.
    // A spoke whose tenant is the SHARED tenant is visible to every tenant
    // (objects still subnet-scoped) — badge it amber so it's distinct from a
    // private tenant binding (emerald).
    const _isShared = tenant && window._sharedTenantId && tenant === window._sharedTenantId;
    const tenantChip = tenant
        ? `<span class="text-[10px] px-2 py-0.5 rounded-full font-bold uppercase ${_isShared ? 'bg-amber-100 text-amber-800' : 'bg-emerald-50 text-emerald-700'}" title="${_isShared ? 'Shared tenant — visible to all tenants: ' : 'Tenant: '}${escapeHtml(String(tenant))}">${_isShared ? 'shared · ' : ''}${escapeHtml(String(tenant))}</span>`
        : '';
    // Live per-spoke/agent metrics (from /status metrics, stashed by
    // _updateMetrics) shown on the SAME line as tenant + online/offline:
    //   • msg/s — inbound message rate (blue)
    //   • backlog — hub-side queued/unacked messages for this id (amber; hidden
    //     when zero). A rising backlog = messages not draining to that spoke.
    const _m = window.__lmHubMetrics || {};
    const _mps = _m.spoke_mps ? _m.spoke_mps[label] : undefined;
    const _bk = (_m.backlog_stats && _m.backlog_stats.by_spoke) ? _m.backlog_stats.by_spoke[label] : undefined;
    const mpsChip = (_mps !== undefined && _mps !== null)
        ? `<span class="text-[10px] px-2 py-0.5 rounded-full font-semibold bg-sky-50 text-sky-700" title="Inbound message rate">${Number(_mps).toFixed(1)}/s</span>`
        : '';
    const backlogChip = (_bk)
        ? `<span class="text-[10px] px-2 py-0.5 rounded-full font-semibold bg-amber-50 text-amber-700" title="Hub-side backlog (queued/unacked) for this ${spokeVariant ? 'spoke' : 'agent'}">${_bk} queued</span>`
        : '';
    // Backpressure badge — the hub throttles a spoke/agent when it's over its
    // rate (level 1, "offending") or when a fleet-wide slow-down is active
    // (level 2, "throttled"). The badged node is being asked to coalesce its
    // updates LOCALLY and slow down. spoke_levels is keyed by hub spoke id.
    const _bp = _m.backpressure || {};
    const _lvl = (_bp.spoke_levels && _bp.spoke_levels[label]) || 0;
    const throttleChip = _lvl === 1
        ? `<span class="text-[10px] px-2 py-0.5 rounded-full font-bold uppercase bg-red-100 text-red-700 animate-pulse" title="Offending — this ${spokeVariant ? 'spoke' : 'agent'} is over its message rate; the hub asked it to slow down &amp; coalesce updates locally">⚠ Offending</span>`
        : (_lvl >= 2
            ? `<span class="text-[10px] px-2 py-0.5 rounded-full font-bold uppercase bg-orange-100 text-orange-700" title="Throttled — fleet-wide slow-down active; this ${spokeVariant ? 'spoke' : 'agent'} is coalescing updates locally">⏳ Throttled</span>`
            : '');
    return `
        <div class="${container}">
            <div class="flex items-center gap-3">
                <div class="w-2 h-2 rounded-full ${dot}"></div>
                <span class="${nameCls}">${label}</span>
                <span class="text-[10px] px-2 py-0.5 rounded-full font-bold uppercase bg-slate-200 text-slate-600">${mod}</span>
                ${tenantChip}
            </div>
            <div class="flex items-center gap-2">
                ${throttleChip}${mpsChip}${backlogChip}${badge}
            </div>
        </div>`;
}

// updateStatus() — periodic hub status poll. GET /status (public) plus, for
// admins, GET /setup/pending_spokes + /setup/diagnostics (see core/src/api.py
// get_status / get_pending_spokes / get_diagnostics). The body is split into
// the _update* / _rebuild* / _render* helpers below; each takes the already-
// fetched data so the helpers stay pure w.r.t. network. Side-effect order
// (metrics → hub health → spoke count → nav rebuild → dashboard lists) and the
// outer try/catch are preserved exactly from the pre-refactor body — note
// _renderDashboardLists is awaited so its errors surface in this catch.
let _statusBackoffUntil = 0;   // hub-requested polling backoff (protect mode)
async function updateStatus() {
    // Honor hub overload backpressure: if the hub told us to back off, skip
    // this tick instead of hammering a saturated loop.
    if (Date.now() < _statusBackoffUntil) return;
    try {
        const requests = [fetch('/status')];
        if (isAdmin()) {
            requests.push(setupFetch('/setup/pending_spokes'), setupFetch('/setup/diagnostics'));
        }
        const [statusRes, approvalsRes, diagRes] = await Promise.all(requests);

        // 503 + Retry-After = hub in protect mode → back off polling.
        if (statusRes.status === 503) {
            const ra = parseInt(statusRes.headers.get('Retry-After') || '30', 10) || 30;
            _statusBackoffUntil = Date.now() + ra * 1000;
            if (typeof showToast === 'function') showToast(`Hub busy (protecting) — backing off ${ra}s`, 'info');
            return;
        }
        _statusBackoffUntil = 0;
        if (!statusRes.ok) throw new Error('API Error');
        const approvalsOk = isAdmin() && approvalsRes?.ok;
        const diagOk = isAdmin() && diagRes?.ok;

        const statusData = await statusRes.json();
        // /setup/pending_spokes + /setup/diagnostics are SHED (503) during a
        // protect spike (they iterate all spokes). When that happens, REUSE the
        // last-known-good spoke list instead of an empty one — otherwise the nav
        // + dashboard lists rebuild EMPTY and the whole left menu vanishes for a
        // few seconds until the next successful poll. Cache on success, fall back
        // on shed/failure so the UI stays stable through a spike.
        const approvalsData = approvalsOk ? await approvalsRes.json()
            : (window.__lmLastApprovals || { spokes: [] });
        if (approvalsOk) window.__lmLastApprovals = approvalsData;
        const diagData = diagOk ? await diagRes.json()
            : (window.__lmLastDiag || { spokes: [] });
        if (diagOk) window.__lmLastDiag = diagData;

        const allSpokes = approvalsData.spokes || [];
        const approvedSpokes = allSpokes.filter(s => s.approved);
        // Online/offline tiles use the grace-based "in contact" set (connected
        // now OR seen within the grace window) so a transient hub loop-stall or a
        // brief reconnect doesn't flip a module offline — only genuine long
        // absence does. Falls back to active_connections on an older hub.
        const connections = statusData.in_contact || statusData.active_connections || [];

        _updateMetrics(statusData);
        _applyHubHealth(diagData);
        _updateSpokeCount(approvedSpokes);
        _rebuildMainNav(allSpokes, connections);
        await _renderDashboardLists(allSpokes, approvedSpokes, connections);
    } catch (err) {
        console.error('Status update error:', err);
    }
}

// Write the sys-* metric tiles + footer version from /status `metrics`.
function _updateMetrics(statusData) {
    if (!statusData.metrics) return;
    const m = statusData.metrics;
    // Stash for the per-spoke msg/s + backlog chips in the Spokes/Agents tiles
    // (_renderSpokeAgentRow reads spoke_mps / backlog_stats.by_spoke by id).
    window.__lmHubMetrics = m;
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

    // Rate-limit drops tile + Backlog & Rate-Limiting detail card
    const rdEl = document.getElementById('sys-rate-drops');
    if (rdEl) rdEl.textContent = (m.rate_limit_drops_total ?? 0);
    const detEl = document.getElementById('sys-backlog-detail');
    if (detEl) {
        const bs = m.backlog_stats || {};
        const rl = m.rate_limit || {};
        const drops = m.rate_limit_drops || {};
        const esc = (s) => String(s).replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
        const kv = (obj) => Object.keys(obj || {}).length
            ? Object.entries(obj).sort((a,b)=>b[1]-a[1])
                .map(([k,v]) => `<span class="inline-block bg-slate-100 rounded px-2 py-0.5 mr-1 mb-1">${esc(k)}: <b>${v}</b></span>`).join('')
            : '<span class="text-slate-400 italic">none</span>';
        detEl.innerHTML = `
            <div><span class="text-slate-400 uppercase text-[10px] font-bold tracking-widest">Backlog</span>
                 &nbsp;total <b>${bs.total ?? 0}</b> · unacked <b>${bs.pending_ack ?? 0}</b> · queued <b>${bs.queued ?? 0}</b>
                 ${bs.oldest_age_s ? `· oldest <b>${bs.oldest_age_s}s</b>` : ''}</div>
            <div><span class="text-slate-400 uppercase text-[10px] font-bold tracking-widest">By type</span><br>${kv(bs.by_type)}</div>
            <div><span class="text-slate-400 uppercase text-[10px] font-bold tracking-widest">By spoke</span><br>${kv(bs.by_spoke)}</div>
            <div class="pt-1 border-t border-slate-100"><span class="text-slate-400 uppercase text-[10px] font-bold tracking-widest">Rate limit</span>
                 &nbsp;burst <b>${rl.capacity ?? '—'}</b> · <b>${rl.fill_rate ?? '—'}</b>/s
                 &nbsp;·&nbsp;drops total <b>${m.rate_limit_drops_total ?? 0}</b></div>
            <div><span class="text-slate-400 uppercase text-[10px] font-bold tracking-widest">Drops by spoke</span><br>${kv(drops)}</div>
            ${(() => {
                // Backpressure ladder status: the graceful-degradation control
                // loop. level 1 = offenders throttled, 2 = fleet-wide slow-down.
                const bp = m.backpressure || {};
                const lvl = bp.level || 0;
                if (!lvl && !(bp.telemetry_coalesced)) return '';
                const label = lvl >= 2 ? '<b class="text-orange-600">FLEET slow-down</b>'
                    : lvl === 1 ? '<b class="text-red-600">throttling offenders</b>'
                    : '<b class="text-slate-500">normal</b>';
                const thr = (bp.spokes_throttled || []);
                return `<div class="pt-1 border-t border-slate-100">
                    <span class="text-slate-400 uppercase text-[10px] font-bold tracking-widest">Backpressure</span>
                    &nbsp;level <b>${lvl}</b> · ${label}
                    ${thr.length ? `· throttled <b>${thr.length}</b>` : ''}
                    ${bp.coalesce_pending ? `· hub-queue <b>${bp.coalesce_pending}</b>` : ''}
                    <br><span class="text-slate-400">telemetry</span> recv <b>${bp.telemetry_received ?? 0}</b>
                    · processed <b>${bp.telemetry_processed ?? 0}</b>
                    · <span title="frames merged latest-wins (not dropped)">coalesced <b>${bp.telemetry_coalesced ?? 0}</b></span>
                    ${thr.length ? `<br><span class="text-slate-400">throttled:</span> ${kv(bp.spoke_levels || {})}` : ''}</div>`;
            })()}`;
    }
    // Populate the rate-limit knobs from live config — but skip a field while
    // it's focused so the 10s status poll doesn't clobber what's being typed.
    const rl = m.rate_limit || {};
    const capIn = document.getElementById('rl-capacity');
    const rateIn = document.getElementById('rl-fillrate');
    if (capIn && document.activeElement !== capIn && rl.capacity != null) capIn.value = rl.capacity;
    if (rateIn && document.activeElement !== rateIn && rl.fill_rate != null) rateIn.value = rl.fill_rate;

    const versionEl = document.getElementById('footer-sys-version');
    if (versionEl && m.version) {
        // m.version is the RUNNING version (what this process booted with), NOT
        // the on-disk VERSION file — so it only advances after a real restart,
        // not the moment a `git pull` rewrites VERSION. The dot is the
        // disk-vs-running + remote-vs-local drift signal:
        //   GREEN  = running the latest (disk == running, remote == local)
        //   YELLOW (behind)        = a newer VERSION is on disk but the hub
        //                           hasn't restarted into it yet (disk != running)
        //   YELLOW (update_avail)  = a newer version is on the remote, not pulled
        // Rendered as "● Version | <running .nnn>".
        const wd = m.watchdog || {};
        const behind = !!wd.behind;
        const updateAvail = !!wd.update_available;
        const dotTone = (behind || updateAvail) ? 'bg-amber-400' : 'bg-green-500';
        // wd.running_version mirrors m.version (both the running process's boot
        // version); target_version is the on-disk VERSION. Surface the explicit
        // running/target pair in the tooltip so the drift is obvious.
        const running = wd.running_version || m.version;
        const target = wd.target_version || '';
        const title = behind
            ? `Behind — disk has ${target} but running ${running}; restart pending (watchdog will in-window)`
            : updateAvail
                ? `Update available — a newer version is on the remote (running ${running}); click Update to pull`
                : `Up to date (running ${running})`;
        versionEl.innerHTML = `<span class="inline-block w-1.5 h-1.5 rounded-full ${dotTone} align-middle mr-1.5" title="${escapeHtml(title)}"></span>Version | ${escapeHtml(m.version)}`;
        window.__lmHubVersion = m.version;  // for File-a-Bug context (running version)
        window.__lmTargetVersion = target || null;  // on-disk VERSION, for the Update toast
    }

    // Out-of-contact alerts (SpokeAlertMixin) — surfaced on the already-polled
    // /status fetch so the header status tooltip can show a count with no extra
    // polling. renderSpokeIndicators() reads window.activeAlerts.
    window.activeAlerts = Array.isArray(statusData.active_alerts) ? statusData.active_alerts : [];
    window.activeAlertCount = Number(statusData.active_alert_count) || 0;
}

// Diag: drop the hub's outbound message backlog (System → Hub Status button).
// Clears a stuck backlog (e.g. undeliverable SPOKE_UPDATE to a flapping spoke)
// without deleting the spoke. Admin only (server enforces 403).
// Zero the per-spoke rate-limit drop counters (in-memory running totals). They
// otherwise only reset on a hub restart. Admin only (server enforces 403).
async function resetRateLimitDrops() {
    const btn = document.getElementById('reset-drops-btn');
    if (btn) { btn.disabled = true; btn.textContent = 'Resetting…'; }
    try {
        const res = await fetch('/setup/rate-limit-drops/reset', { method: 'POST' });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
        if (typeof showToast === 'function') showToast('Rate-limit drop counters reset.', 'success');
        updateStatus();
    } catch (e) {
        if (typeof showToast === 'function') showToast(`Reset failed: ${e.message}`, 'error');
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = 'Reset Drops'; }
    }
}

async function dropHubBacklog() {
    const btn = document.getElementById('drop-backlog-btn');
    if (!confirm('Drop ALL queued/unacked messages in the hub backlog? '
               + 'In-flight commands will not be retried. This is a diagnostic action.')) return;
    if (btn) { btn.disabled = true; btn.textContent = 'Dropping…'; }
    try {
        const res = await fetch('/setup/hub-backlog/purge', { method: 'POST' });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
        if (typeof showToast === 'function') showToast(`Dropped ${data.dropped} backlog message(s).`, 'success');
        updateStatus();  // refresh the tiles/detail
    } catch (e) {
        if (typeof showToast === 'function') showToast(`Drop backlog failed: ${e.message}`, 'error');
        else alert(`Drop backlog failed: ${e.message}`);
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = 'Drop Backlog'; }
    }
}

// Save the per-spoke rate-limit knob (System → Hub Status). Shallow-merges into
// global_config["rate_limit"] via POST /setup/config; the hub applies it to each
// spoke on its next (re)connect (main.py _rate_limit_params). Admin only.
// ── Backpressure Tuning panel (System → Hub Status) ─────────────────────────
// The knobs live in global_config.backpressure; the hub reads them fresh each
// 1s tick, so a Save applies LIVE (no deploy). Field id → config key + default.
const _BP_DEFAULTS = {
    fleet_cpu_soft: 55, fleet_cpu_hard: 85, fleet_cpu_clear: 40,
    coalesce_min_interval_s: 2, coalesce_max_interval_s: 15,
    release_dwell_s: 20, per_spoke_soft_mps: 50, ddos_disconnect: false,
    fleet_min_mps: 5, protect_shed_min_mps: 50, protect_shed_top_k: 20, ddos_grace_s: 30,
};
const _BP_FIELDS = [
    ['bp-fleet-cpu-soft', 'fleet_cpu_soft'], ['bp-fleet-cpu-hard', 'fleet_cpu_hard'],
    ['bp-fleet-cpu-clear', 'fleet_cpu_clear'], ['bp-coalesce-min', 'coalesce_min_interval_s'],
    ['bp-coalesce-max', 'coalesce_max_interval_s'], ['bp-release-dwell', 'release_dwell_s'],
    ['bp-per-spoke-soft', 'per_spoke_soft_mps'], ['bp-ddos-disconnect', 'ddos_disconnect'],
    ['bp-fleet-min', 'fleet_min_mps'], ['bp-protect-shed-min', 'protect_shed_min_mps'],
    ['bp-protect-shed-topk', 'protect_shed_top_k'], ['bp-ddos-grace', 'ddos_grace_s'],
];

// Load: GET the live backpressure subtree, fill the panel inputs (default where
// unset), and cache the FULL subtree so Save can merge onto it (not overwrite).
// Update / maintenance-window gate (global_config.update_gate). Default: apply
// auto-update restarts during a daily 02:00 window so they never interrupt
// logged-in users; the footer Update button bypasses it (force). Also renders
// the auto-heal watchdog's live status so the operator can see it's armed.
const _UG_DEFAULTS = { mode: 'window', window_hour: 2, window_duration_h: 2 };

async function loadUpdateGateConfig() {
    try {
        const res = await setupFetch('/setup/config');
        const data = await res.json();
        const g = (data.global_config && data.global_config.update_gate) || {};
        window.__lmUpdateGateCfg = g;
        const setv = (id, v) => { const el = document.getElementById(id); if (el && document.activeElement !== el) el.value = v; };
        setv('ug-mode', g.mode || _UG_DEFAULTS.mode);
        setv('ug-window-hour', g.window_hour !== undefined ? g.window_hour : _UG_DEFAULTS.window_hour);
        setv('ug-window-duration', g.window_duration_h !== undefined ? g.window_duration_h : _UG_DEFAULTS.window_duration_h);
    } catch (e) { /* leave inputs as-is on failure */ }
    // Live watchdog status from /status → metrics.watchdog (bridge loop).
    try {
        const s = await (await fetch('/status', { credentials: 'same-origin' })).json();
        const w = (s.metrics && s.metrics.watchdog) || {};
        const el = document.getElementById('ug-watchdog-status');
        if (el) el.innerHTML = w.armed
            ? `<span class="text-green-600">● auto-heal watchdog armed</span>${w.heartbeat ? ' · ' + escapeHtml(String(w.heartbeat)) : ''}`
            : `<span class="text-amber-600">● watchdog not armed</span>`;
        const pill = document.getElementById('ug-watchdog-pill');
        if (pill) {
            pill.className = 'text-[10px] px-2 py-0.5 rounded-full font-bold uppercase normal-case '
                + (w.armed ? 'bg-green-100 text-green-700' : 'bg-amber-100 text-amber-700');
            pill.textContent = w.armed ? 'watchdog ✓' : 'watchdog off';
        }
    } catch (e) { /* ignore */ }
}

function resetUpdateGateConfig() {
    const setv = (id, v) => { const el = document.getElementById(id); if (el) el.value = v; };
    setv('ug-mode', _UG_DEFAULTS.mode);
    setv('ug-window-hour', _UG_DEFAULTS.window_hour);
    setv('ug-window-duration', _UG_DEFAULTS.window_duration_h);
    if (typeof showToast === 'function') showToast('Defaults filled (02:00 window) — click Save to apply.', 'info');
}

async function saveUpdateGateConfig() {
    const btn = document.getElementById('ug-save-btn');
    const merged = Object.assign({}, window.__lmUpdateGateCfg || {}, {
        mode: document.getElementById('ug-mode').value,
        window_hour: Number(document.getElementById('ug-window-hour').value),
        window_duration_h: Number(document.getElementById('ug-window-duration').value),
    });
    if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
    try {
        const res = await fetch('/setup/config', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ config: { update_gate: merged } }),
        });
        if (!res.ok) { const d = await res.json().catch(() => ({})); throw new Error(d.detail || res.status); }
        if (typeof showToast === 'function') showToast('Update window saved (applies live).', 'success');
        window.__lmUpdateGateCfg = merged;
    } catch (e) {
        if (typeof showToast === 'function') showToast('Save failed: ' + e.message, 'error');
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = 'Save'; }
    }
}

async function loadBackpressureConfig() {
    try {
        const res = await setupFetch('/setup/config');
        const data = await res.json();
        const bp = (data.global_config && data.global_config.backpressure) || {};
        window.__lmBackpressureCfg = bp;   // keep the full subtree so Save doesn't wipe unshown knobs
        for (const [id, key] of _BP_FIELDS) {
            const el = document.getElementById(id);
            if (!el) continue;
            const val = bp[key] !== undefined ? bp[key] : _BP_DEFAULTS[key];
            if (el.type === 'checkbox') el.checked = !!val;
            else if (document.activeElement !== el) el.value = val;   // don't clobber while typing
        }
    } catch (e) { /* leave inputs blank on failure */ }
}

// Reset: fill inputs with the recommended defaults locally — NOT persisted
// until the operator clicks Save (so a mis-click is recoverable by reloading).
function resetBackpressureConfig() {
    for (const [id, key] of _BP_FIELDS) {
        const el = document.getElementById(id);
        if (!el) continue;
        if (el.type === 'checkbox') el.checked = !!_BP_DEFAULTS[key];
        else el.value = _BP_DEFAULTS[key];
    }
    if (typeof showToast === 'function') showToast('Defaults filled in — click Save to apply.', 'info');
}

// Save: merge panel fields onto the cached subtree and POST to /setup/config;
// the hub picks it up on the next 1s tick (live, no deploy). See §8 of
// docs/backpressure-throttling.md for the full knob reference.
async function saveBackpressureConfig() {
    const btn = document.getElementById('bp-save-btn');
    // Merge onto the last-loaded subtree so knobs NOT shown in this panel
    // (surgical shed, source-shed, ddos grace, etc.) are preserved on save
    // (the hub's /setup/config does a top-level replace of `backpressure`).
    const merged = Object.assign({}, window.__lmBackpressureCfg || {});
    for (const [id, key] of _BP_FIELDS) {
        const el = document.getElementById(id);
        if (!el) continue;
        merged[key] = el.type === 'checkbox' ? el.checked : Number(el.value);
    }
    // Light sanity: soft below hard below the 90% protect line, clear below soft.
    if (!(merged.fleet_cpu_clear < merged.fleet_cpu_soft && merged.fleet_cpu_soft < merged.fleet_cpu_hard)) {
        const m = 'CPU marks must satisfy: release < engage < max (e.g. 40 < 55 < 85).';
        if (typeof showToast === 'function') showToast(m, 'error'); else alert(m);
        return;
    }
    if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
    try {
        const res = await fetch('/setup/config', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ config: { backpressure: merged } }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
        window.__lmBackpressureCfg = merged;
        if (typeof showToast === 'function')
            showToast('Backpressure tuning saved — applies live on the next tick.', 'success');
    } catch (e) {
        if (typeof showToast === 'function') showToast(`Save failed: ${e.message}`, 'error');
        else alert(`Save failed: ${e.message}`);
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = 'Save'; }
    }
}

async function saveRateLimit() {
    const capIn = document.getElementById('rl-capacity');
    const rateIn = document.getElementById('rl-fillrate');
    const btn = document.getElementById('rl-save-btn');
    const capacity = Number(capIn && capIn.value);
    const fill_rate = Number(rateIn && rateIn.value);
    if (!(capacity >= 1) || !(fill_rate > 0)) {
        const msg = 'Enter a burst ≥ 1 and a refill rate > 0.';
        if (typeof showToast === 'function') showToast(msg, 'error'); else alert(msg);
        return;
    }
    if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
    try {
        const res = await fetch('/setup/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ config: { rate_limit: { capacity, fill_rate } } }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
        if (typeof showToast === 'function')
            showToast(`Rate limit saved (burst ${capacity}, ${fill_rate}/s). Applies as spokes reconnect.`, 'success');
    } catch (e) {
        if (typeof showToast === 'function') showToast(`Save rate limit failed: ${e.message}`, 'error');
        else alert(`Save rate limit failed: ${e.message}`);
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = 'Save'; }
    }
}

// Mark the hub online + build the spoke-health map (from /setup/diagnostics)
// that renderSpokeIndicators() reads to color the header status dots.
function _applyHubHealth(diagData) {
    window.hubOnline = true;
    window.spokeHealth = {};
    (diagData.spokes || []).forEach(s => {
        window.spokeHealth[s.spoke_id] = {
            // Grace-based: in contact now or recently (falls back to the live WS
            // flag on an older hub) so a transient stall doesn't drop the dot.
            online: (s.in_contact !== undefined ? s.in_contact : s.authenticated),
            error: !!s.last_error
        };
    });
    renderSpokeIndicators();
}

// Update the sidebar "Spokes" count badge from the approved-spoke count.
function _updateSpokeCount(approvedSpokes) {
    const spokeCount = document.getElementById('spoke-count');
    if (spokeCount) spokeCount.textContent = approvedSpokes.length;
}

// Rebuild #main-nav from the active module classes. Nav class items are driven
// by APPROVED spokes (activeProducts) — online OR offline — so a registered role
// keeps its left-menu item, rendered normally (no offline dimming), instead of
// vanishing on disconnect. Approval is still required: a freshly-connected
// still-pending (unapproved) spoke can't ghost a nav item, because
// activeProducts is approved-only. connectedProducts is retained only to prefer
// a live product for the class icon. Drops classes the user can't see
// (canSeeModule).
function _rebuildMainNav(allSpokes, connections) {
    // Tenant scoping (additive, non-admin only). For a tenant-scoped user, drop
    // spokes bound to a tenant they can't access before deriving the nav, so a
    // tenant-A firewall never lights the Firewalls nav for a tenant-B user.
    // Admins are unaffected (_spokeVisibleToTenant returns true for them), and
    // unassigned/global spokes stay visible to everyone. Narrowing allSpokes
    // here propagates to approvedIds/typeBy/connectedProducts below, so no other
    // change in this function is needed.
    allSpokes = allSpokes.filter(_spokeVisibleToTenant);

    // Drive nav off each spoke's REGISTERED module_type — NOT its spoke_id name.
    // A generic node named "lm-opnsense" is module_type "agent" (no role loaded)
    // and must NOT light the Firewalls nav; only a real firewall spoke
    // (module_type "firewall" — a standalone opn-spoke or a loaded-role sub-spoke
    // "{base}-opnsense") does. Substring-matching the spoke_id against PRODUCT_MAP
    // (the old approach) matched the agent's NAME, ghosting a Firewalls nav item
    // even with no role loaded. module_type is authoritative when present; the
    // id-prefix fallback (_productFromIdPrefix) only fires for approved-but-offline
    // spokes whose module_type was popped on disconnect.
    const typeBy = {};
    allSpokes.forEach(s => { typeBy[s.spoke_id] = String(s.module_type || '').toLowerCase(); });
    const productFor = sid => {
        const mt = typeBy[sid];
        if (mt) return MODULE_TYPE_PRODUCT[mt] || null;   // known type is authoritative
        return _productFromIdPrefix(sid);                  // offline spoke -> prefix fallback
    };

    // connectedProducts = products backed by a LIVE connection to an APPROVED
    // module. The main-nav class items (Firewalls/IPAM/...) are driven by THIS
    // set, so:
    //   - a stale approved-but-offline registry entry can't ghost a nav item
    //     (connection required), AND
    //   - a freshly-connected zero-touch spoke that is still PENDING admin
    //     approval can't light its module menu either (approval required) —
    //     the menu only appears once a module of that class has been approved.
    const approvedIds = new Set(allSpokes.filter(s => s.approved).map(s => s.spoke_id));
    const connectedProducts = new Set();
    connections.forEach(id => {
        if (!approvedIds.has(id)) return;   // unapproved/pending — no menu yet
        const p = productFor(id);
        if (p) connectedProducts.add(p);
    });

    // activeProducts adds approved-but-offline modules on top, so the Logs
    // submenu (logsSubmenu) + the setView product picker still reach a
    // configured module's historical logs while it is briefly disconnected.
    const activeProducts = new Set(connectedProducts);
    allSpokes.forEach(spoke => {
        if (spoke.approved) {
            const p = productFor(spoke.spoke_id);
            if (p) activeProducts.add(p);
        }
    });

    window.activeProducts = activeProducts;

    // Show a class nav item once ANY module of that class is APPROVED/registered,
    // even while it is offline — a registered role keeps its left-menu item
    // instead of vanishing on disconnect. activeProducts is approved-only, so the
    // approval gate is preserved: a PENDING/unapproved spoke still can't light the
    // menu. (Was connectedProducts, which required a LIVE connection and dropped
    // the item the moment the spoke/agent/module went offline.)
    const activeClasses = [];
    for (const [className, products] of Object.entries(MODULE_CLASSES)) {
        if (products.some(p => activeProducts.has(p))) {
            activeClasses.push(className);
        }
    }

    const mainNav = document.getElementById('main-nav');
    if (!mainNav) return;
    const staticNavs = ['dashboard', 'settings', 'setup'];
    // Drop module classes the current user has no right to see (e.g. a
    // non-admin without the "cs" right never gets a Simulations nav item).
    const visibleClasses = activeClasses.filter(className => canSeeModule(className));
    const dynamicHtml = visibleClasses.map(className => {
        // A class nav item is active when the current view IS the class
        // (multi-product class — setView keeps currentView on the class)
        // OR when currentView is one of its products (single-product
        // class — setView sets currentView to the product, e.g. 'cs' for
        // 'Simulations'). Without the product check, the rebuild inside
        // updateStatus() strips .active whenever currentView is a product
        // and the green left-border context indicator vanishes.
        const isActive = (currentView === className
            || (MODULE_CLASSES[className] || []).includes(currentView))
            ? 'active' : '';
        // Prefer a connected product for the icon; fall back to any approved
        // (offline) product so the icon still resolves while the module is offline.
        const firstProduct = MODULE_CLASSES[className].find(p => connectedProducts.has(p))
            || MODULE_CLASSES[className].find(p => activeProducts.has(p));
        let icon = '';

        if (className === 'Firewalls') {
            icon = '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>';
        } else if (className === 'Hypervisors') {
            icon = '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12H3m18 0h-2M12 5V3m0 18v-2m5.657-14.343l-1.414 1.414M6.757 17.243l-1.414 1.414m12.728 0l-1.414-1.414M6.757 6.757L5.343 5.343M12 8a4 4 0 100 8 4 4 0 000-8z"></path></svg>';
        } else if (className === 'Security/NAC') {
            icon = '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg>';
        } else if (className === 'IPAM') {
            icon = '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zm10 0a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zm10 0a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M8 8v2m0 4v-2m8-2v2m0 4v-2M8 12h8"></path></svg>';
        } else if (className === 'Simulations') {
            icon = '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z"></path></svg>';
        } else if (className === 'DNS') {
            icon = '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3.6 9h16.8M3.6 15h16.8M11.5 3a17 17 0 000 18M12.5 3a17 17 0 010 18"></path></svg>';
        } else if (className === 'DHCP') {
            icon = '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12.5a7 7 0 0114 0M8.5 12.5a3.5 3.5 0 017 0M2 12.5h2M20 12.5h2M12 19.5v2"></path></svg>';
        } else if (className === 'Network') {
            icon = '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3.6 9h16.8M3.6 15h16.8M11.5 3a17 17 0 000 18M12.5 3a17 17 0 010 18M12 21a9 9 0 110-18 9 9 0 010 18z"></path></svg>';
        } else if (className === 'Certificates') {
            icon = '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m-6-8h6M5 21h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v14a2 2 0 002 2z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M14.5 19.5l1.5 1.5 2.5-2.5"></path></svg>';
        } else if (firstProduct && window.VIEWS && window.VIEWS[firstProduct]) {
            icon = window.VIEWS[firstProduct].icon || '';
        }

        return `
            <div onclick="setView('${className}')" id="nav-${className}" class="nav-item ${isActive} p-3 rounded-r-lg flex items-center gap-3 text-sm font-medium">
                <div>${icon}</div>
                <span>${className}</span>
            </div>
        `;
    }).join('');

    const dashboardNav = document.getElementById('nav-dashboard') ? document.getElementById('nav-dashboard').outerHTML : '';
    // Strip 'hidden' before capturing so the nav items are visible after the rebuild.
    const _getNavHtml = (id) => {
        const el = document.getElementById(id);
        if (!el) return '';
        el.classList.remove('hidden');
        return el.outerHTML;
    };
    // Admin nav items (Setup/Logs/System) live in the static HTML. Cache their
    // HTML on first sight so a rebuild that runs while isAdmin() is momentarily
    // false (a transient state where currentUser is null/not-yet-admin) can't
    // PERMANENTLY destroy them: once a rebuild omits them they're gone from the
    // DOM and `_getNavHtml` returns '' on every later tick, forcing a hard
    // refresh to bring them back. The cache is sourced from the static HTML
    // (single source of truth) and reused verbatim until a fresh capture is
    // available. Capture happens before the destructive innerHTML write below.
    const setupNav    = _getNavHtml('nav-setup');
    const logsNav     = _getNavHtml('nav-logs');
    const settingsNav = _getNavHtml('nav-settings');
    if (setupNav && logsNav && settingsNav) {
        _adminNavHtmlCache = { setup: setupNav, logs: logsNav, settings: settingsNav };
    }
    const _cachedNavs = _adminNavHtmlCache || {};
    const adminSetup    = setupNav    || _cachedNavs.setup    || '';
    const adminLogs     = logsNav     || _cachedNavs.logs     || '';
    const adminSettings = settingsNav || _cachedNavs.settings || '';

    // Tenant-admins don't get Setup/Logs/System, but they DO manage the
    // firewall/network/NAC/IPAM/directory/DNS/DHCP devices bound to their own
    // tenant via the "My Devices" view (session-scoped /tenant/devices/*).
    const _myDevicesNavHtml = () => `
        <div onclick="setView('mydevices')" id="nav-mydevices" class="nav-item p-3 rounded-r-lg flex items-center gap-3 text-sm font-medium">
            <div><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01"></path></svg></div>
            <span>My Devices</span>
        </div>`;

    mainNav.innerHTML = `
        ${dashboardNav}
        ${dynamicHtml}
        <div class="pt-4 mt-4 border-t border-slate-200"></div>
        ${isAdmin() ? adminSetup : ''}
        ${isAdmin() ? adminLogs : ''}
        ${isAdmin() ? adminSettings : ''}
        ${(!isAdmin() && isTenantAdmin()) ? _myDevicesNavHtml() : ''}
    `;

    // The Logs submenu is dynamic (logsSubmenu gates module tabs on
    // activeProducts), so re-render it when the approved-module set changes
    // while the Logs view is open — otherwise newly-approved modules wouldn't
    // gain a log tab until the user re-opens Logs. Preserve the active tab.
    if (currentView === 'logs') {
        renderTopNav('logs');
        if (currentSubView && document.querySelector(`#top-nav .sub-nav-item[data-submenu="${currentSubView}"]`)) {
            document.querySelectorAll('#top-nav .sub-nav-item').forEach(el => {
                el.classList.toggle('active', el.dataset.submenu === currentSubView);
            });
        }
    }
}

// Render the dashboard sidebar Spokes + Agents lists. Splits known modules by
// module_type: infrastructure spokes (incl. the pxmx "hypervisor" spoke) stay
// in Spokes; only generic Hub-direct agents (module_type "agent", e.g.
// bugfixer) move to Agents. Proxmox node agents are fetched separately via
// GET /api/pxmx/agents and appended. Each row is rendered by the shared
// _renderSpokeAgentRow() helper above. The pxmx agents fetch is best-effort —
// on failure the generic agents still render (see catch below).
async function _renderDashboardLists(allSpokes, approvedSpokes, connections) {
    // Split known modules by module_type: infrastructure spokes (including
    // the pxmx "hypervisor" spoke) stay in the Spokes list; only generic
    // Hub-direct agents (module_type "agent", e.g. bugfixer) move to the
    // Agents list. Proxmox node agents are fetched separately via
    // /api/pxmx/agents and appended below — they are distinct from the
    // hypervisor spoke itself.
    // Tenant scoping (additive, non-admin only) — same rule as _rebuildMainNav:
    // a tenant-scoped user only sees spokes for tenants they can access, plus
    // unassigned/global spokes. Admins keep the full all-tenants list.
    allSpokes = allSpokes.filter(_spokeVisibleToTenant);
    approvedSpokes = approvedSpokes.filter(_spokeVisibleToTenant);

    const isAgent = s => {
        const mt = String(s.module_type || '').toLowerCase();
        return mt === 'agent';
    };
    // Spokes list shows approved AND pending non-agent spokes — a freshly
    // connected zero-touch spoke sits as Pending until an admin approves it,
    // and should still be visible on this page (not just in Setup).
    const spokeListItems = allSpokes.filter(s => !isAgent(s));
    const approvedHubAgents  = approvedSpokes.filter(isAgent);
    const pendingHubAgents   = allSpokes.filter(s => isAgent(s) && !s.approved);

    const spokeList = document.getElementById('spoke-list');
    if (spokeList) {
        if (spokeListItems.length === 0) {
            spokeList.innerHTML = `<p class="text-xs text-slate-400 italic">No spokes configured.</p>`;
        } else {
            spokeList.innerHTML = spokeListItems.map(spoke => {
                const id = spoke.spoke_id;
                const mod = moduleLabel(spoke.module_type);
                const status = !spoke.approved ? 'pending'
                    : (connections.includes(id) ? 'online' : 'offline');
                return _renderSpokeAgentRow(id, mod, status, true, spoke.tenant_id);
            }).join('');
        }
    }

    const agentList = document.getElementById('agent-list');
    const agentCount = document.getElementById('agent-count');
    if (!agentList) return;
    // Generic Hub-direct agents (module_type "agent") from /setup/pending_spokes.
    const hubAgentRows = [
        ...approvedHubAgents.map(a => ({ id: a.spoke_id, label: a.display_name || a.spoke_id, status: connections.includes(a.spoke_id) ? 'online' : 'offline', mod: moduleLabel(a.module_type) })),
        ...pendingHubAgents.map(a => ({ id: a.spoke_id, label: a.display_name || a.spoke_id, status: 'pending', mod: moduleLabel(a.module_type) })),
    ];
    // Proxmox node agents relayed through the pxmx hypervisor spoke
    // (best-effort). This runs on every 10s updateStatus() poll, so cache the
    // pxmx agents response for ~60s (pxmx agent connect/disconnect is rare) —
    // avoids a round-trip per poll tick while still picking up new agents
    // within a minute. Manual Refresh in Setup → Spokes & Agents bypasses this
    // cache (loadSpokesAndAgents fetches /api/pxmx/agents directly).
    let pxmxRows = [];
    const now = Date.now();
    if (_pxmxAgentsCache && (now - _pxmxAgentsCache.ts) < 60000) {
        pxmxRows = _pxmxAgentsCache.rows;
    } else {
        try {
            const agentRes = await fetch('/api/pxmx/agents', { credentials: 'same-origin' });
            if (agentRes.ok) {
                const agentData = await agentRes.json();
                pxmxRows = [
                    ...(agentData.agents || []).map(a => ({ id: a.agent_id, label: a.display_name || a.hostname || a.agent_id, status: 'online', mod: 'Proxmox' })),
                    ...(agentData.pending_agents || []).map(a => ({ id: a.agent_id, label: a.display_name || a.agent_id, status: 'pending', mod: 'Proxmox' })),
                ];
                _pxmxAgentsCache = { ts: now, rows: pxmxRows };
            }
        } catch (err) { console.error('updateStatus: pxmx agents fetch failed — generic agents still render', err); }
    }

    const all = [...hubAgentRows, ...pxmxRows];
    // Cache agent presence so the Logs submenu (logsSubmenu) can gate the
    // "Agents" tab on whether any agent is actually connected.
    window.hasAgents = all.length > 0;
    if (agentCount) agentCount.textContent = all.length;
    if (all.length === 0) {
        agentList.innerHTML = `<p class="text-xs text-slate-400 italic">No agents connected.</p>`;
    } else {
        agentList.innerHTML = all.map(a => _renderSpokeAgentRow(a.label, a.mod, a.status, false)).join('');
    }
}

function renderSpokeIndicators() {
    const hubDot = document.getElementById('hub-status-dot');
    const moduleDot = document.getElementById('module-status-dot');
    const tooltipEl = document.getElementById('system-status-tooltip');
    if (!hubDot || !moduleDot || !tooltipEl || !window.spokeHealth) return;

    const isHubOnline = window.hubOnline || false;
    const hubColor = isHubOnline ? 'bg-green-500' : 'bg-red-500';
    hubDot.className = `w-2 h-2 rounded-full ${hubColor} transition-all`;

    const statuses = Object.entries(window.spokeHealth);
    if (statuses.length === 0) {
        moduleDot.className = 'w-2 h-2 rounded-full bg-slate-500 transition-all';
        tooltipEl.innerHTML = `<div class="text-center italic opacity-60">No spokes connected</div>`;
        return;
    }

    let allGreen = true;
    let allRed = true;
    let tooltipHtml = '';

    statuses.forEach(([id, health]) => {
        const isOnline = health.online;
        const hasError = health.error;
        const isPerfectGreen = isOnline && !hasError;
        const isRed = !isOnline;

        if (!isPerfectGreen) allGreen = false;
        if (!isRed) allRed = false;

        let dotColor = 'bg-red-500';
        let statusText = 'Offline';
        if (isOnline) {
            dotColor = hasError ? 'bg-yellow-500' : 'bg-green-500';
            statusText = hasError ? 'Online (Error)' : 'Online';
        }

        tooltipHtml += `<div class="flex items-center justify-between gap-4 py-0.5"><span class="font-mono opacity-80">${id}</span><div class="flex items-center gap-1.5"><div class="w-1.5 h-1.5 rounded-full ${dotColor}"></div><span class="text-[9px]">${statusText}</span></div></div>`;
    });

    let overallColor = 'bg-yellow-500';
    if (allGreen) overallColor = 'bg-green-500';
    else if (allRed) overallColor = 'bg-red-500';

    moduleDot.className = `w-2 h-2 rounded-full ${overallColor} transition-all`;

    // Append a forgiving out-of-contact alert summary (SpokeAlertMixin) to the
    // tooltip. Distinct from the realtime dots above — these fire only after a
    // spoke has been out of contact >=5m (warning) / >=30m (error). An active
    // error alert also turns the module dot red so an operator scanning the
    // header notices a sustained outage.
    const alerts = Array.isArray(window.activeAlerts) ? window.activeAlerts : [];
    let alertHtml = '';
    if (alerts.length) {
        const hasErr = alerts.some(a => String(a.tier) === 'error');
        if (hasErr) overallColor = 'bg-red-500';
        moduleDot.className = `w-2 h-2 rounded-full ${overallColor} transition-all`;
        const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
        alertHtml = `<div class="mt-2 pt-2 border-t border-white/15">
            <div class="text-[9px] uppercase opacity-60 mb-1">Out-of-contact alerts</div>
            ${alerts.map(a => `<div class="flex items-center justify-between gap-4 py-0.5"><span class="font-mono opacity-80">${esc(a.spoke_id)}</span><div class="flex items-center gap-1.5"><div class="w-1.5 h-1.5 rounded-full ${a.tier === 'error' ? 'bg-red-400' : 'bg-amber-400'}"></div><span class="text-[9px]">${a.tier}</span></div></div>`).join('')}
        </div>`;
    }
    tooltipEl.innerHTML = tooltipHtml + alertHtml;
}

async function setView(viewId) {
    if ((viewId === 'setup' || viewId === 'settings' || viewId === 'logs') && !isAdmin()) {
        return;  // silently block — nav items are hidden, this guards deep-links
    }
    // My Devices is the tenant-admin device surface — reachable only by a
    // tenant-admin (or a Global Admin); guards deep-links for everyone else.
    if (viewId === 'mydevices' && !(isTenantAdmin() || isAdmin())) {
        return;
    }
    // Directory (LDAP) has no MODULE_CLASSES entry (standalone view), so gate its
    // deep-link explicitly on the `ldap` right (server enforces reads=ldap-right,
    // writes=admin).
    if (viewId === 'ldap' && !canSeeModule('Directory')) {
        return;
    }
    // Module-right gate for deep-links: a non-admin without the module's right
    // cannot enter the view even by URL/manual setView, mirroring the nav filter.
    // Covers both the class name (e.g. 'Simulations') and any product in a
    // gated class (e.g. 'cs').
    const _classForView = (vid) => Object.keys(MODULE_CLASSES).find(
        cls => MODULE_CLASSES[cls].includes(vid));
    const _gateClass = Object.keys(MODULE_CLASSES).includes(viewId)
        ? viewId : _classForView(viewId);
    if (_gateClass && !canSeeModule(_gateClass)) {
        return;
    }
    const prevView = currentView;
    const isClass = Object.keys(MODULE_CLASSES).includes(viewId);

    if (isClass) {
        const products = Array.from(window.activeProducts || []).filter(p => MODULE_CLASSES[viewId].includes(p));

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

    currentSubView = (VIEW_SUBMENUS[currentView] || ['General'])[0];
    currentSubChild = _csDefaultChild(currentView, currentSubView);

    document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
    const navItem = document.getElementById(`nav-${isClass ? viewId : currentView}`);
    if (navItem) navItem.classList.add('active');

    renderTopNav(currentView);
    renderView(currentView);
    initView(currentView, currentSubView);
    updateHeaderModule();
    updateContextActions();

    // Tear down the CS telemetry socket when leaving the Simulations module.
    if (prevView === 'cs' && currentView !== 'cs' && typeof disconnectCSWebSocket === 'function') {
        disconnectCSWebSocket();
    }
}

// Dispatch table for setSubView: maps the active module (currentView) to the
// loader that renders its primary sub-view. Each loader receives `subMenu`
// except where noted. Mirrors the former if/else chain exactly — only one
// entry ever matches per call, and unknown views (e.g. dashboard) have no
// entry and intentionally no-op. cs is wrapped because its loader
// (loadCSData, defined in sim-views.js) takes (subMenu, currentSubChild);
// the child is resolved above via _csDefaultChild. opnsense is wrapped because
// loadOpnsenseManagement() takes no argument (it reads the currentSubView global).
const VIEW_LOADERS = {
    opnsense: () => loadOpnsenseManagement(),
    cppm:     loadCPPMData,
    pxmx:     loadPxmxData,
    ldap:     loadLDAPData,
    netbox:   loadNetboxData,
    dns:      loadDNSData,
    dhcp:     loadDHCPData,
    nw:       loadNwData,
    le:       loadLEData,
    console:  loadConsoleData,
    cs:       (subMenu) => loadCSData(subMenu, currentSubChild),
    setup:    _renderSetupSection,
    settings: _renderSettingsSection,
    logs:     _renderLogsSection,
};

async function setSubView(subMenu) {
    currentSubView = subMenu;
    // Reset the child for the newly-selected primary (two-tier nav). For
    // non-cs modules _csDefaultChild returns '' and the secondary strip is
    // hidden by renderSecondaryNav.
    currentSubChild = _csDefaultChild(currentView, subMenu);

    // Update active state in top-nav
    document.querySelectorAll('#top-nav .sub-nav-item').forEach(el => {
        el.classList.toggle('active', el.dataset.submenu === subMenu);
    });

    // Show/hide + populate the secondary child strip for this primary.
    renderSecondaryNav(currentView);

    // Dispatch to the active module's loader (see VIEW_LOADERS above). Unknown
    // views (e.g. dashboard) have no entry and intentionally no-op, matching
    // the previous fall-through behavior of the if/else chain.
    const loader = VIEW_LOADERS[currentView];
    if (loader) loader(subMenu);
}

function renderTopNav(viewId) {
    const topNav = document.getElementById('top-nav');
    if (!topNav) return;
    // CS (Simulations) is now a set of native LM views (see sim-views.js); it
    // gets a normal sub-nav strip like every other spoke.
    // Logs is dynamic: only show tabs for modules that are actually installed
    // (see logsSubmenu). Every other view uses its fixed VIEW_SUBMENUS list.
    const rawSubmenus = (viewId === 'logs') ? logsSubmenu() : (VIEW_SUBMENUS[viewId] || []);
    const subMenus = rawSubmenus.filter(m => !(m === 'Simulations' && !isAdmin()));
    // Trailing help affordance for tabbed module views (esp. the table-tab
    // modules — opnsense/netbox/nw/dns/dhcp/ldap/le — whose pages are just a
    // table with no on-page section header to attach an inline icon to). Placed
    // AFTER #top-nav-actions so view-specific action buttons that overwrite that
    // container's innerHTML don't wipe it. helpForCurrentView() resolves the
    // active view to its canonical doc. Shown only when a doc mapping exists.
    const helpDoc = (window.LM_DOC_REGISTRY && window.LM_DOC_REGISTRY[viewId]) || null;
    const helpBtn = (helpDoc && subMenus.length)
        ? `<button type="button" class="lm-help-icon ml-1" title="Open documentation" aria-label="Open documentation" onclick="helpForCurrentView()">i</button>`
        : '';
    topNav.innerHTML = subMenus.map((menu, i) => {
        const label = SUBMENU_LABELS[menu] || menu;
        return `<div class="sub-nav-item ${i === 0 ? 'active' : ''} px-2 py-1 text-xs uppercase tracking-widest cursor-pointer select-none" data-submenu="${menu}" onclick="setSubView('${menu}')">${label}</div>`;
    }).join('') + '<div id="top-nav-actions" class="ml-auto flex items-center gap-2"></div>' + helpBtn;
    // Keep the secondary child strip in sync with the active primary.
    renderSecondaryNav(viewId);
}

// Render the second-tier child strip (#top-nav-secondary) for the active
// primary of a two-tier module (cs). Populates it with the primary's children
// and highlights currentSubChild; hides the strip entirely for primaries/modules
// without children so non-cs modules and childless cs primaries are unaffected.
function renderSecondaryNav(viewId) {
    const sec = document.getElementById('top-nav-secondary');
    if (!sec) return;
    const kids = (VIEW_CHILDREN[viewId] || {})[currentSubView] || null;
    if (!kids || !kids.length) {
        sec.classList.add('hidden');
        sec.innerHTML = '';
        return;
    }
    const activeChild = currentSubChild || kids[0];
    const tabs = kids.map((child) =>
        `<div class="sub-nav-item ${child === activeChild ? 'active' : ''} px-2 py-1 cursor-pointer select-none" data-subchild="${child}" onclick="setSubChild('${child.replace(/'/g, "\\'")}')">${child}</div>`
    ).join('');
    // Pin the sim kill-switch to the far right of the Clients (All/T1/T2) and
    // Dashboard (Checks/Hardware/Client Count) child strips — moved out of those
    // views' content banners.
    const ksSlot = (viewId === 'cs' && (currentSubView === 'Clients' || currentSubView === 'Dashboard'))
        ? '<span id="cs-ks-chip" class="ml-auto flex items-center gap-2"></span>' : '';
    sec.innerHTML = tabs + ksSlot;
    sec.classList.remove('hidden');
    if (ksSlot && typeof window.csKillSwitchMountChip === 'function') {
        window.csKillSwitchMountChip('cs-ks-chip');
    }
}

// Select a child tab within the current cs primary (two-tier nav). Sets
// currentSubChild, updates the secondary strip's active state, and dispatches
// the child renderer via loadCSData.
async function setSubChild(child) {
    currentSubChild = child;
    document.querySelectorAll('#top-nav-secondary .sub-nav-item').forEach(el => {
        el.classList.toggle('active', el.dataset.subchild === child);
    });
    if (currentView === 'cs') {
        await loadCSData(currentSubView, child);
    }
}
window.setSubChild = setSubChild;

function renderView(viewId) {
    const vp = document.getElementById('viewport');
    if (!vp) return;
    vp.innerHTML = _viewTemplate(viewId);
    _applyEditVisibility();   // hide row Edit/Delete for view users (CSS-based)
}

function _viewTemplate(viewId) {
    const card = 'hpe-card rounded-lg p-6 shadow-sm';
    const input = 'w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500 text-slate-800';
    const btn = 'bg-[#01A982] hover:bg-[#008c6a] text-white px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm';

    switch (viewId) {
        case 'dashboard':
            if (isAdmin()) {
                return `<div class="space-y-6">
  <div class="${card}" id="all-tenants-card">
    <div class="flex justify-between items-center mb-3">
      <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">All Tenants ${helpIcon('architecture-topology', null, 'Dashboard help')}</h3>
      <button onclick="loadAllTenantsOverview(true)" class="text-xs text-slate-400 hover:text-slate-600">↻ Refresh</button>
    </div>
    <div id="all-tenants-overview"><p class="text-sm text-slate-400 italic">Loading tenants…</p></div>
  </div>
</div>`;
            }
            return `<div class="space-y-6">
  <div class="${card}" id="tenant-summary-card">
    <div class="flex justify-between items-center mb-3">
      <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Tenant Summary — <span id="dash-tenant-name" class="text-[#01A982] font-mono normal-case"></span> ${helpIcon('architecture-topology', null, 'Dashboard help')}</h3>
      <button onclick="loadDashboardSummary()" class="text-xs text-slate-400 hover:text-slate-600">↻ Refresh</button>
    </div>
    <div id="tenant-summary-grid" class="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-500">
      <span><b id="dash-devices" class="text-sm text-slate-700">—</b> Devices</span>
      <span><b id="dash-vms" class="text-sm text-slate-700">—</b> VMs</span>
      <span><b id="dash-sessions" class="text-sm text-slate-700">—</b> NAC Sessions</span>
      <span><b id="dash-prefixes" class="text-sm text-slate-700">—</b> Prefixes</span>
      <span><b id="dash-ips" class="text-sm text-slate-700">—</b> IPs Used</span>
    </div>
  </div>
</div>`;

        case 'opnsense':
            return `<div class="space-y-4">
  <div id="opn-table-container" class="${card}">
    <div class="py-12 text-center text-slate-400 italic">Loading firewalls…</div>
  </div>
</div>`;

        case 'nw':
            return `<div class="space-y-4">
  <div id="nw-table-container" class="${card}">
    <div class="py-12 text-center text-slate-400 italic">Loading network devices…</div>
  </div>
</div>`;

        case 'mydevices':
            // Tenant-admin device management — same unified table as the admin
            // Setup → Managed Devices tile, but the driver (loadAllDevices via
            // _devEndpoint) talks to /tenant/devices/*, so it lists/edits only
            // this tenant's devices and the spoke dropdown is own-tenant-only.
            return `<div class="space-y-6">
  <div class="${card}">
    <div class="flex items-center justify-between mb-4">
      <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">My Devices</h3>
      <button onclick="showAddDeviceModal()" class="${btn}">+ Add Device</button>
    </div>
    <p class="text-xs text-slate-400 mb-3">Firewalls, network devices, NAC, IPAM, directory, DNS, and DHCP instances bound to your tenant. Click <strong>Add Device</strong>, choose the module type, and bind it to one of your tenant's spokes.</p>
    <div id="all-devices-list" class="space-y-2"><p class="text-xs text-slate-400 italic animate-pulse">Loading…</p></div>
  </div>
</div>`;

        case 'console':
            return `<div class="space-y-4">
  <div id="console-container" class="${card}">
    <div class="py-12 text-center text-slate-400 italic">Loading serial consoles…</div>
  </div>
</div>`;

        case 'ldap':
            // Directory writes are tenant-admin tier, OU-scoped to the tenant's
            // ldap_base_dn subtree (server-enforced); a plain ldap-right user can
            // view but not mutate.
            return `<div class="space-y-6">
  <div class="flex justify-end mb-2">${(isAdmin() || isTenantAdmin()) ? `<button onclick="showLDAPModal(currentSubView)" class="${btn}">+ Add</button>` : ''}</div>
  <div class="${card} p-0 overflow-hidden">
    <table class="w-full text-left text-sm">
      <thead class="bg-slate-100 text-slate-600 uppercase text-xs"><tr id="ldap-table-head"></tr></thead>
      <tbody id="ldap-table-body" class="divide-y divide-slate-200"><tr><td class="px-4 py-8 text-center text-slate-400 italic">Select a category above.</td></tr></tbody>
    </table>
  </div>
</div>`;

        case 'settings':
            return `<div class="space-y-6">
  <div id="settings-content"></div>
</div>`;

        case 'logs':
            return `<div class="space-y-6">
  <div id="logs-content"></div>
</div>`;

        case 'setup':
            return `<div class="space-y-6">
  <div id="setup-content"></div>
</div>`;

        case 'pxmx':
            return `<div class="space-y-6">
  <div id="pxmx-content" class="${card}"><p class="text-sm text-slate-400 italic">Loading…</p></div>
</div>`;

        case 'cppm':
            return `<div class="space-y-6">
  <div id="nac-summary" class="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-500">
    <span><b id="nac-sessions" class="text-sm text-[#01A982]">—</b> Active Sessions</span>
    <span><b id="nac-total" class="text-sm text-[#263040]">—</b> Total Devices</span>
    <span><b id="nac-known" class="text-sm text-green-600">—</b> Known</span>
    <span><b id="nac-unknown" class="text-sm text-amber-500">—</b> Unknown</span>
  </div>
  <div id="cppm-content" class="${card}">
    <p class="text-sm text-slate-400 italic">Loading…</p>
  </div>
</div>`;

        case 'cs':
            // Native Client-Sim (Simulations) views. No iframe — the per-tab
            // content is rendered inline into #cs-content by sim-views.js,
            // calling /sim/api/* directly with the lm_session cookie. Tenant
            // scoping reuses the hub's currentTenant global (like netbox/pxmx).
            // The ↻ Refresh button is a floating bottom-right FAB (consistent
            // "all refresh buttons at the bottom right"); the auto-refresh
            // throttle select stays in the top-right toolbar.
            return `<div class="space-y-3">
  <div class="flex justify-end items-center gap-3">
    ${typeof csAutoRefreshControl === 'function' ? csAutoRefreshControl() : ''}
  </div>
  <div id="cs-add-toolbar" class="flex gap-2 hidden"></div>
  <div id="cs-content" class="${card}">
    <div class="py-12 text-center text-slate-400 italic">Loading…</div>
  </div>
  <button onclick="loadCSData(currentSubView, currentSubChild, true)" title="Refresh" class="fixed bottom-4 right-4 z-40 bg-slate-100 hover:bg-slate-200 text-slate-700 px-3 py-2 rounded-md text-xs font-medium transition-all border border-slate-200 shadow-sm">↻ Refresh</button>
</div>`;

        case 'netbox':
            return `<div class="space-y-6">
  <div id="netbox-content" class="${card}"><p class="text-sm text-slate-400 italic">Loading…</p></div>
</div>`;

        case 'dns':
            return `<div class="space-y-6">
  <div class="flex justify-end gap-2">
    ${(isAdmin() || isTenantAdmin()) ? `<button id="dns-add-btn" onclick="showDnsRecordModal()" class="${btn}">+ Add Record</button>` : ''}
  </div>
  <div id="dns-content" class="${card}"><p class="text-sm text-slate-400 italic">Loading…</p></div>
</div>`;

        case 'dhcp':
            return `<div class="space-y-6">
  <div class="flex justify-end gap-2">
    ${(isAdmin() || isTenantAdmin()) ? `<button id="dhcp-add-btn" onclick="showDhcpReservationModal()" class="${btn}">+ Add Reservation</button>` : ''}
  </div>
  <div id="dhcp-content" class="${card}"><p class="text-sm text-slate-400 italic">Loading…</p></div>
</div>`;

        case 'le':
            return `<div class="space-y-6">
  <div id="le-status-bar" class="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-500"></div>
  <div class="flex items-center gap-2">
    <button onclick="showLeIssueModal()" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-3 py-1 rounded-md text-xs font-medium transition-all">＋ Issue certificate</button>
    <button onclick="leRenewAll()" class="bg-green-600 hover:bg-green-700 text-white px-3 py-1 rounded-md text-xs font-medium transition-all">↻ Renew all</button>
    <button onclick="leDistributeNow()" class="bg-green-600 hover:bg-green-700 text-white px-3 py-1 rounded-md text-xs font-medium transition-all">⚡ Distribute now</button>
    <button onclick="loadLEData()" class="bg-slate-100 hover:bg-slate-200 text-slate-700 px-3 py-1 rounded-md text-xs font-medium transition-all border border-slate-200">↻ Refresh</button>
    <button onclick="showDnsCredentialsModal()" class="ml-auto bg-slate-100 hover:bg-slate-200 text-slate-700 px-3 py-1 rounded-md text-xs font-medium transition-all border border-slate-200" title="Manage this tenant's DNS-01 credentials (Hurricane Electric, Cloudflare, rfc2136, Route53), used for DNS-01 issuance">🔑 DNS Credentials</button>
  </div>
  <div id="le-content" class="${card}"><p class="text-sm text-slate-400 italic">Loading…</p></div>
</div>`;

        default:
            return `<div class="hpe-card rounded-lg p-6 shadow-sm"><p class="text-sm text-slate-500 italic">Loading…</p></div>`;
    }
}

function initView(viewId, subView) {
    switch (viewId) {
        case 'dashboard':
            updateStatus();
            if (isAdmin()) loadAllTenantsOverview();
            else loadDashboardSummary();
            break;
        case 'opnsense':
            _loadFirewallData();
            break;
        case 'ldap':
            loadLDAPData(subView || 'OUs');
            break;
        case 'settings':
            _renderSettingsSection(subView || 'Hub Status');
            break;
        case 'logs':
            _renderLogsSection(subView || 'logs-hub');
            break;
        case 'setup':
            _renderSetupSection(subView || 'Spokes & Agents');
            break;
        case 'mydevices':
            loadAllDevices();
            break;
        case 'cppm':
            loadCPPMNACStatus();
            break;
        case 'pxmx':
            loadPxmxData(subView || 'Overview');
            break;
        case 'netbox':
            loadNetboxData(subView || 'Overview');
            break;
        case 'dns':
            loadDNSData(subView || 'Records');
            break;
        case 'dhcp':
            loadDHCPData(subView || 'Overview');
            break;
        case 'nw':
            loadNwData(subView || 'Devices');
            break;
        case 'console':
            loadConsoleData();
            break;
        case 'le':
            loadLEData(subView || 'Certificates');
            break;
        case 'cs':
            loadCSData(subView || 'Dashboard', currentSubChild);
            break;
    }
}

// Populate the configured-firewalls list (once) and render the aggregated
// table. The Firewalls page shows every firewall's data in one view — there is
// no single-firewall selector anymore.
async function _ensureFirewalls() {
    if (_opnFirewalls.length > 0) return _opnFirewalls;
    try {
        _opnFirewalls = await loadFirewalls();
    } catch (e) {
        _opnFirewalls = [];
    }
    return _opnFirewalls;
}

async function _loadFirewallData() {
    await _ensureFirewalls();
    loadOpnsenseManagement();
}

/**
 * Authenticated wrapper around the browser `fetch` for hub REST routes under
 * /setup/* (and a few other admin endpoints). It only guarantees a JSON
 * Content-Type header today; credentials ride the same-origin lm_session cookie
 * automatically, so no explicit Authorization header is added.
 *
 * When to use which fetch helper:
 *   - setupFetch(url)  -> hub /setup/* + /api/* admin routes (core/src/api.py).
 *                         Same-origin cookie auth; JSON body. Prefer this for
 *                         any hub-side call that may need admin scoping.
 *   - raw fetch(url)   -> public/same-origin routes that need no JSON header
 *                         (e.g. /status, /api/pxmx/agents, /api/dhcp/*).
 *   - csFetch(path)    -> Simulations sub-module ONLY. Defined in sim-views.js,
 *                         it prepends `/sim/api` + the tenant id, handles
 *                         401/404 specially, and parses JSON/text. See
 *                         sim-views.js csFetch (~line 55). Routes live in
 *                         core/src/simulations/routes.py.
 *
 * @param {string} url  Request URL (absolute path, e.g. '/setup/pending_spokes').
 * @param {RequestInit} [options] Standard fetch options; headers are merged.
 * @returns {Promise<Response>} Raw Response — callers must check .ok and parse.
 */
async function setupFetch(url, options = {}) {
    const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
    return fetch(url, { ...options, headers });
}
// ──────────────────────────────────────────────────────────────────

function _renderLogsSection(subMenu) {
    const content = document.getElementById('logs-content');
    if (!content) return;
    const card = 'hpe-card rounded-lg shadow-sm overflow-hidden';
    const module = subMenu.replace('logs-', '');
    const title = SUBMENU_LABELS[subMenu] || (module + ' Logs');
    // The Recovery tab is a filtered view of the hub log (the [recovery]
    // watchdog lines already stream through Hub Logs unfiltered); load it with
    // the dedicated loader instead of the generic /setup/logs/<module> one.
    // Bug Reports is its own table view of the hub's bug-report store.
    const isRecovery = subMenu === 'logs-recovery';
    const isBugs = subMenu === 'logs-bugs';
    const refreshCall = isRecovery ? "loadRecoveryLogs()" : isBugs ? "loadBugReports()" : `loadModuleLogs('${module}')`;
    // Clear Logs is destructive + fleet-wide (hub deque + every relayed
    // agent/spoke deque + on-disk /var/log/lm/*.log on the hub AND, via a
    // CLEAR_LOGS broadcast, every connected spoke's own disk). Hidden on the
    // Bug Reports tab — that's a separate store, not a log source.
    const clearBtn = isBugs ? '' :
        `<button onclick="clearLogs(()=>${refreshCall})" class="text-xs text-red-500 hover:text-red-700 font-medium">Clear</button>`;
    content.innerHTML = `
        <div class="${card}">
            <div class="px-4 py-3 border-b border-slate-200 flex justify-between items-center bg-slate-50">
                <h3 class="text-sm font-bold text-slate-600">${title} ${helpIcon('logging-observability-contract', null, 'Logs help')}</h3>
                <div class="flex gap-3 items-center">
                    <button id="debug-toggle-btn" onclick="toggleDebugLogging()"
                        class="text-[10px] bg-white border border-slate-300 px-2 py-1 rounded hover:bg-slate-50 transition-colors font-medium flex items-center gap-1">
                        <span id="debug-mode-text">Debug Logging: OFF</span>
                    </button>
                    <button onclick="copyLogs()" class="text-xs text-blue-500 hover:text-blue-700 font-medium">Copy</button>
                    ${clearBtn}
                    <button onclick="${refreshCall}" class="text-xs text-blue-500 hover:text-blue-700 font-medium">Refresh</button>
                </div>
            </div>
            <div id="system-logs-container" class="h-[32rem] overflow-y-auto font-mono text-xs bg-white border border-slate-200 rounded-md text-slate-700 space-y-0"></div>
        </div>`;
    if (isRecovery) {
        loadRecoveryLogs();
    } else if (isBugs) {
        loadBugReports();
    } else {
        loadModuleLogs(module);
    }
    refreshDebugButtonState();
}

// Recovery logs: the hub watchdog emits greppable [recovery] lines for every
// restart/give-up/clear action. This loads the hub log and filters to those
// lines so an operator can watch auto-recovery without CLI / journalctl.
async function loadRecoveryLogs() {
    const container = document.getElementById('system-logs-container');
    if (!container) return;
    container.innerHTML = `<div class="py-12 text-center text-slate-400 animate-pulse">Fetching recovery logs...</div>`;
    try {
        const response = await fetch('/setup/logs');
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        const data = await response.json();
        const logs = (data.logs || []).slice().reverse();
        const rec = logs.filter(l => typeof l === 'string' && l.includes('[recovery]'));
        if (rec.length === 0) {
            container.innerHTML = `<div class="py-12 text-center text-slate-400 italic">No [recovery] log lines yet. The watchdog logs here when it restarts a stranded spoke or gives up.</div>`;
            return;
        }
        // Collapse repeating [recovery] lines (same except timestamp) with a
        // counter + expand-on-click, same as the main log view. GAVE_UP rows
        // keep their red styling in both the header and the expanded rows.
        container._rawLogs = rec;
        const recoveryRow = (log, count) => {
            const isGiveUp = log.includes('GAVE_UP');
            const cls = isGiveUp ? 'text-red-700 font-semibold bg-red-50' : 'text-slate-600 hover:bg-slate-50';
            const badge = count && count > 1
                ? `<span class="ml-2 px-1.5 py-0.5 rounded-full text-[9px] font-bold bg-slate-200 text-slate-600 align-middle whitespace-nowrap" title="${count} identical events — click to expand">×${count}</span>`
                : '';
            // onclick must be its own attribute, not embedded in the class string.
            const isGroup = count && count > 1;
            const clsExtra = isGroup ? ' cursor-pointer select-none' : '';
            const onClick = isGroup ? ' onclick="toggleLogGroup(this)"' : '';
            const tsMatch = log.match(/^(?:\[([^\]]*)\]\s*)?(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) - ([^-]+?) - ([A-Z]+) - (.*)$/s);
            const body = tsMatch
                ? `${tsMatch[1] ? `<span class="text-slate-400">[${tsMatch[1]}]</span> ` : ''}<span class="text-slate-400">${tsMatch[2]}</span> <span class="font-semibold">${tsMatch[3].trim()}</span> <span class="opacity-60">${tsMatch[4]}</span>${badge}<div class="pl-4 mt-0.5 break-all">${escapeHtml(tsMatch[5])}</div>`
                : `${escapeHtml(log)}${badge}`;
            return `<div class="px-4 py-0.5 border-b border-slate-100 text-xs font-mono ${cls}${clsExtra}"${onClick}>${body}</div>`;
        };
        container.innerHTML = _renderGroupedLogs(rec, recoveryRow);
    } catch (err) {
        container.innerHTML = `<div class="py-12 text-center text-red-500 font-medium">Error loading recovery logs: ${err.message}</div>`;
    }
}

// Bug Reports: the WebUI "File a Bug" footer button writes each report to the
// hub's bug store; bugfixer later files a GitHub issue and flips `filed` to
// true with the issue_url. This lists them (newest first) with status, and a
// click opens a detail modal with the captured console/HTML/screenshot.
async function loadBugReports() {
    const container = document.getElementById('system-logs-container');
    if (!container) return;
    container.innerHTML = `<div class="py-12 text-center text-slate-400 animate-pulse">Fetching bug reports...</div>`;
    try {
        const resp = await fetch('/setup/bug-reports');
        if (!resp.ok) throw new Error(`HTTP error! status: ${resp.status}`);
        const data = await resp.json();
        const reports = data.reports || [];
        if (reports.length === 0) {
            container.innerHTML = `<div class="py-12 text-center text-slate-400 italic">No bug reports yet. Use the 🐞 File a Bug button in the footer to capture the console, page HTML, and a screenshot.</div>`;
            return;
        }
        container.className = 'h-[32rem] overflow-y-auto bg-white border border-slate-200 rounded-md text-slate-700';
        container.innerHTML = reports.map(r => {
            const ts = r.ts ? new Date(r.ts * 1000).toLocaleString() : '—';
            const sev = (r.severity || 'medium').toLowerCase();
            const sevColor = sev === 'high' ? 'bg-red-100 text-red-700'
                : sev === 'low' ? 'bg-slate-100 text-slate-500'
                : 'bg-amber-100 text-amber-700';
            const status = r.filed
                ? `<a href="${escapeHtml(r.issue_url || '#')}" target="_blank" class="text-blue-500 hover:underline">Filed ↗</a>`
                : `<span class="text-amber-600">Pending</span>`;
            return `<div onclick="showBugReport('${escapeHtml(r.id)}')" class="px-4 py-2 border-b border-slate-100 hover:bg-slate-50 cursor-pointer flex items-center gap-3">
                <span class="text-slate-400 w-44 shrink-0">${escapeHtml(ts)}</span>
                <span class="shrink-0 px-2 py-0.5 rounded text-[10px] font-bold uppercase ${sevColor}">${escapeHtml(sev)}</span>
                <span class="flex-1 truncate text-slate-700">${escapeHtml(r.summary || '(no summary)')}</span>
                <span class="shrink-0 text-[10px] text-slate-400 font-mono">${escapeHtml(r.id)}</span>
                <span class="shrink-0 w-16 text-center text-xs font-medium">${status}</span>
            </div>`;
        }).join('');
    } catch (err) {
        container.innerHTML = `<div class="py-12 text-center text-red-500 font-medium">Error loading bug reports: ${err.message}</div>`;
    }
}

async function showBugReport(rid) {
    const overlay = document.createElement('div');
    overlay.id = 'bug-detail-overlay';
    overlay.className = 'fixed inset-0 bg-black/50 flex items-center justify-center z-[100] p-4';
    overlay.innerHTML = `
        <div class="bg-white rounded-lg shadow-xl max-w-4xl w-full max-h-[90vh] overflow-hidden flex flex-col">
            <div class="px-5 py-3 border-b border-slate-200 flex justify-between items-center bg-slate-50">
                <h3 class="text-sm font-bold text-slate-700">Bug Report <span class="font-mono text-slate-400">${escapeHtml(rid)}</span></h3>
                <button onclick="document.getElementById('bug-detail-overlay').remove()" class="text-slate-400 hover:text-slate-600 text-xl">✕</button>
            </div>
            <div id="bug-detail-body" class="p-5 overflow-y-auto text-xs space-y-4">
                <div class="py-12 text-center text-slate-400 animate-pulse">Loading...</div>
            </div>
        </div>`;
    overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };
    document.body.appendChild(overlay);
    const body = overlay.querySelector('#bug-detail-body');
    try {
        const resp = await fetch(`/setup/bug-reports/${encodeURIComponent(rid)}`);
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const r = await resp.json();
        const ctx = r.context || {};
        let report = {};
        try { report = JSON.parse(r.report_json || '{}'); } catch { report = {}; }
        const consoleText = r.console || '(no console captured)';
        const domText = (r.dom || '').slice(0, 4000) || '(no HTML captured)';
        const sev = r.severity || 'medium';
        const status = r.filed
            ? `<a href="${escapeHtml(r.issue_url || '#')}" target="_blank" class="text-blue-500 hover:underline break-all">${escapeHtml(r.issue_url || 'Filed')}</a>`
            : `<span class="text-amber-600">Pending — bugfixer has not filed this yet</span>`;
        const shot = r.screenshot_b64
            ? `<img src="${escapeHtml(r.screenshot_b64)}" class="mt-2 max-w-full rounded border border-slate-200" alt="screenshot">`
            : `<span class="text-slate-400 italic">No screenshot captured</span>`;
        body.innerHTML = `
            <div>
                <div class="text-[10px] uppercase text-slate-400 font-bold tracking-widest mb-1">Status</div>
                <div class="text-sm">${status}</div>
            </div>
            <div>
                <div class="text-[10px] uppercase text-slate-400 font-bold tracking-widest mb-1">Explanation</div>
                <div class="text-sm text-slate-700 whitespace-pre-wrap">${escapeHtml(report.explanation || r.summary || '(none)')}</div>
            </div>
            <div class="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
                <div><span class="text-slate-400">Severity:</span> <span class="font-medium">${escapeHtml(sev)}</span></div>
                <div><span class="text-slate-400">View:</span> <span class="font-medium">${escapeHtml(ctx.currentView || '—')}</span></div>
                <div><span class="text-slate-400">URL:</span> <span class="font-medium break-all">${escapeHtml(ctx.url || '—')}</span></div>
                <div><span class="text-slate-400">Tenant:</span> <span class="font-medium">${escapeHtml(ctx.currentTenant || '—')}</span></div>
                <div><span class="text-slate-400">Hub:</span> <span class="font-medium">${escapeHtml(ctx.hubVersion || '—')}</span></div>
                <div><span class="text-slate-400">WebUI:</span> <span class="font-medium">${escapeHtml(ctx.webuiVersion || '—')}</span></div>
            </div>
            <div>
                <div class="text-[10px] uppercase text-slate-400 font-bold tracking-widest mb-1">Screenshot</div>
                ${shot}
            </div>
            <div>
                <div class="text-[10px] uppercase text-slate-400 font-bold tracking-widest mb-1">Console</div>
                <pre class="bg-slate-900 text-slate-100 p-3 rounded max-h-64 overflow-auto whitespace-pre-wrap">${escapeHtml(consoleText)}</pre>
            </div>
            <div>
                <div class="text-[10px] uppercase text-slate-400 font-bold tracking-widest mb-1">DOM (first 4KB)</div>
                <pre class="bg-slate-900 text-slate-100 p-3 rounded max-h-64 overflow-auto whitespace-pre-wrap break-all">${escapeHtml(domText)}</pre>
            </div>`;
    } catch (err) {
        body.innerHTML = `<div class="py-12 text-center text-red-500 font-medium">Error loading bug report: ${err.message}</div>`;
    }
}

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

    // SSO — Microsoft Entra ID (OIDC) config: enable it, set tenant/client/cert/
    // group/MFA. Drives /setup/oidc-config and the login "Sign in with Microsoft"
    // button. Global-Admin only (route is admin-gated server-side).
    if (subMenu === 'SSO') {
        _renderSettingsSsoTile(content);
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
                            <button onclick="saveRateLimit()" id="rl-save-btn" class="text-xs px-3 py-1.5 rounded-md bg-green-600 text-white hover:bg-green-700 transition-all">Save</button>
                        </div>
                        <p class="text-[10px] text-slate-400 mt-2">Applies to each spoke on its next (re)connect. Raise both for relay spokes hosting many agents / at scale.</p>
                    </div>
                </div>
                <div class="${card} p-6">
                    <div class="flex justify-between items-center mb-1">
                        <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Backpressure Tuning ${helpIcon('lm-hub', null, 'Hub help')}</h3>
                        <div class="flex items-center gap-2">
                            <button onclick="resetBackpressureConfig()" class="text-xs px-3 py-1 rounded-md border border-slate-300 text-slate-600 hover:bg-slate-50 transition-all" title="Restore recommended defaults (not yet saved)">Reset Defaults</button>
                            <button onclick="saveBackpressureConfig()" id="bp-save-btn" class="text-xs px-3 py-1.5 rounded-md bg-green-600 text-white hover:bg-green-700 transition-all">Save</button>
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
                        <div class="flex items-center gap-2">
                            <button onclick="resetUpdateGateConfig()" class="text-xs px-3 py-1 rounded-md border border-slate-300 text-slate-600 hover:bg-slate-50 transition-all" title="Restore defaults (02:00 window)">Reset Defaults</button>
                            <button onclick="saveUpdateGateConfig()" id="ug-save-btn" class="text-xs px-3 py-1.5 rounded-md bg-green-600 text-white hover:bg-green-700 transition-all">Save</button>
                        </div>
                    </div>
                    <p class="text-[10px] text-slate-400 mb-3">When AUTO-updates <b>apply</b>. The hub pulls new code anytime; the restart into it is held for this window so it never interrupts logged-in users. The footer <b>Update</b> button bypasses this and restarts immediately. <span id="ug-watchdog-status" class="font-mono ml-1"></span></p>
                    <div class="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs text-slate-500">
                        <label>Apply auto-updates<br>
                            <select id="ug-mode" class="mt-1 w-full bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                                <option value="window">When idle — else the daily window</option>
                                <option value="idle">Only when no users online</option>
                                <option value="immediate">Immediately</option>
                            </select></label>
                        <label>Window start hour (0–23, local)<br><input type="number" id="ug-window-hour" min="0" max="23" step="1" class="mt-1 w-full bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500"></label>
                        <label>Window length (hours)<br><input type="number" id="ug-window-duration" min="1" max="24" step="1" class="mt-1 w-full bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500"></label>
                    </div>
                </div>
                <div class="grid grid-cols-2 gap-4">
                    <div class="${card} p-6">
                        <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-4">Spokes (<span id="spoke-count">0</span>) ${helpIcon('lm-hub', null, 'Hub help')}</h3>
                        <div id="spoke-list" class="space-y-2"><p class="text-xs text-slate-400 italic">Loading…</p></div>
                    </div>
                    <div class="${card} p-6">
                        <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-4">Agents (<span id="agent-count">0</span>) ${helpIcon('lm-hub', null, 'Hub help')}</h3>
                        <div id="agent-list" class="space-y-2"><p class="text-xs text-slate-400 italic">Loading…</p></div>
                    </div>
                </div>
                <div class="${card} p-6">
                    <div class="flex justify-between items-center mb-4">
                        <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Active Sessions ${helpIcon('lm-hub', null, 'Hub help')}</h3>
                        <button onclick="loadActiveSessions()" class="text-xs text-slate-400 hover:text-slate-600">↻ Refresh</button>
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
        loadBackpressureConfig();
        loadUpdateGateConfig();
        loadActiveSessions();
    } else if (subMenu === 'API Tokens') {
        content.innerHTML = `
            <div class="${card} p-6 space-y-5">
                <div class="flex justify-between items-center">
                    <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">API Tokens ${helpIcon('lm-hub', null, 'Hub help')}</h3>
                    <button onclick="loadApiTokens()" class="text-xs text-slate-400 hover:text-slate-600">↻ Refresh</button>
                </div>
                <p class="text-[11px] text-slate-400 leading-relaxed">Bearer tokens for programmatic API access — they carry <b>your</b> permissions. Send <code>Authorization: Bearer &lt;access&gt;</code>. The access token expires in <b>4 hours</b>; POST the refresh token to <code>/auth/token/refresh</code> to rotate to a fresh pair with no re-login. Tokens are shown <b>once</b> — store them securely.</p>
                <div class="flex items-end gap-2">
                    <label class="text-xs text-slate-500 flex-1">Token name<br>
                        <input type="text" id="apitok-name" placeholder="e.g. ci-pipeline" class="mt-1 w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"></label>
                    <button onclick="createApiToken()" id="apitok-create-btn" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-4 py-2 rounded-md text-sm font-bold">Create token</button>
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

// Shared Tailwind class strings for every Setup tile. Hoisted to module scope
// so each _renderSetup*Tile helper below destructures the same names
// (`card`, `inputCls`, `labelCls`, `btnCls`, `btnSecCls`) that the original
// monolithic _renderSetupSection used — keeping every template byte-identical.
const _SETUP_CLS = {
    card: 'hpe-card rounded-lg p-6 shadow-sm space-y-4',
    inputCls: 'w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500 text-slate-800',
    labelCls: 'text-xs text-slate-500 uppercase font-bold',
    btnCls: 'bg-[#01A982] hover:bg-[#008c6a] text-white px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm',
    btnSecCls: 'bg-slate-100 hover:bg-slate-200 text-slate-700 px-4 py-2 rounded-md text-sm font-medium border border-slate-200',
};

// Setup → Spokes & Agents tile. Renders the spokes/agents admin cards, then
// kicks off loadSpokesAndAgents() which fans out to GET /setup/pending_spokes
// + GET /api/pxmx/agents + GET /setup/diagnostics (core/src/api.py
// get_pending_spokes / get_pxmx_agents / get_diagnostics). The diagnostics
// telemetry (heartbeat/version/recovery/events) is folded inline into the
// Spokes / Agents / Generic Agents cards; the summary bar above Spokes carries
// the Hub/WebUI version + recovery counts that used to head the standalone
// Diagnostics card (now removed).
// Bulk-remove synthetic load-test spokes (id prefix 'loadtest-') in one click —
// the loadtest harness registers hundreds; deleting them one by one is misery.
window.purgeLoadtestSpokes = async function () {
    if (!confirm("Remove ALL spokes/agents whose id starts with 'loadtest-'? "
               + "For cleaning up synthetic load-test spokes.")) return;
    try {
        const res = await setupFetch('/setup/spokes/purge-prefix?prefix=loadtest-', { method: 'POST' });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
        if (typeof showToast === 'function') showToast(`Purged ${data.removed} load-test spoke(s).`, 'success');
        loadSpokesAndAgents();
    } catch (e) {
        if (typeof showToast === 'function') showToast(`Purge failed: ${e.message}`, 'error');
        else alert(`Purge failed: ${e.message}`);
    }
};

function _renderSetupSpokesTile(content) {
    const { card, inputCls, labelCls, btnCls, btnSecCls } = _SETUP_CLS;
    // Compact card variant for this tile only — the shared _SETUP_CLS.card uses
    // p-6/space-y-4 which is generous for forms but wastes vertical space here
    // where each row is already a dense mgmt card. Don't change the shared
    // constant (it drives Tenant/User/Firewalls tiles too).
    const saCard = 'hpe-card rounded-lg p-4 shadow-sm space-y-3';
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
                    <option value="default" selected>Default</option>
                    <option value="__unassigned__">Unassigned</option>
                    <option value="__all__">All tenants</option>
                </select>
                <span class="text-[10px] text-slate-400 italic">show spokes &amp; agents for this tenant (Unassigned = not yet bound to one)</span>
            </div>
            <div class="grid grid-cols-1 xl:grid-cols-2 gap-4 items-start">
                <div class="${saCard}">
                    <div class="flex justify-between items-center mb-2">
                        <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Spokes ${helpIcon('lm-hub', null, 'Hub help')}</h3>
                        <div class="flex items-center gap-3">
                            <button onclick="loadSpokesAndAgents()" class="text-xs text-slate-400 hover:text-slate-600">↻ Refresh</button>
                        </div>
                    </div>
                    <div id="spokes-table-wrap"><p class="text-xs text-slate-400 italic animate-pulse">Loading…</p></div>
                </div>
                <div class="${saCard}">
                    <div class="flex justify-between items-center mb-2">
                        <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Agents ${helpIcon('lm-hub', null, 'Hub help')}</h3>
                    </div>
                    <div id="agents-table-wrap"><p class="text-xs text-slate-400 italic animate-pulse">Loading…</p></div>
                </div>
            </div>`;
    _populateSaTenantFilter();
    loadSpokesAndAgents();
}

// Tenant filter for the Spokes & Agents tile. Reads the tenant list from
// /setup/tenants (tenant config — objects carry ``id``/``name``, NOT
// tenant_id/tenant_name) and fills the #sa-tenant-filter dropdown: every tenant
// first, then the two sentinels Unassigned + All tenants. The initial selection
// is the system "default" tenant (guaranteed present — the backend injects it
// when absent, tenants_users.py get_tenants), pre-seeded as a static <option> so
// loadSpokesAndAgents reads the right value with no async race. A user's choice
// is preserved across refresh; if it's gone, fall back to "default" then
// Unassigned. Best-effort: on a failed fetch the static options remain usable.
async function _populateSaTenantFilter() {
    const sel = document.getElementById('sa-tenant-filter');
    if (!sel) return;
    const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    const current = sel.value || 'default';
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
        sel.value = has(current) ? current : (has('default') ? 'default' : '__unassigned__');
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
                <pre id="rc-output" class="bg-slate-900 text-slate-100 text-xs font-mono rounded-md p-3 overflow-x-auto whitespace-pre-wrap max-h-96 overflow-y-auto hidden"></pre>
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
                    <div class="flex gap-2"><button onclick="saveTenantConfig()" class="${btnCls}">Save</button><button onclick="closeTenantEditor()" class="${btnSecCls}">Cancel</button></div>
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
                        <thead class="bg-slate-100 text-slate-600 uppercase text-xs"><tr><th class="px-4 py-3">User ID</th><th class="px-4 py-3">Auth</th><th class="px-4 py-3">Tenants</th><th class="px-4 py-3">Groups</th><th class="px-4 py-3 text-center">Admin</th><th class="px-4 py-3 text-center">View</th><th class="px-4 py-3 text-center">Edit</th><th class="px-4 py-3 text-center">HV</th><th class="px-4 py-3 text-center">FW</th><th class="px-4 py-3 text-center">DNS</th><th class="px-4 py-3 text-center">NAC</th><th class="px-4 py-3 text-center">NW</th><th class="px-4 py-3 text-center">IPAM</th><th class="px-4 py-3 text-center">CS</th><th class="px-4 py-3 text-center">CON</th><th class="px-4 py-3 text-center">CW</th><th class="px-4 py-3"></th></tr></thead>
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

// Setup → Firewalls tile. GET /api/firewalls (core/src/api.py get_firewalls).
function _renderSetupFirewallsTile(content) {
    const { card, inputCls, labelCls, btnCls, btnSecCls } = _SETUP_CLS;
    content.innerHTML = `
            <div class="${card}">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Firewalls</h3>
                    <button onclick="showAddFirewallModal()" class="${btnCls}">+ Add Firewall</button>
                </div>
                <div id="firewalls-list" class="space-y-2"></div>
            </div>`;
    loadFirewallsList();
}

// Setup → Network Devices tile. GET /setup/nw-devices (core/src/api.py
// get_nw_devices). Mirrors the Firewalls tile: a fleet of switches + gateways
// (AOS-S / AOS-CX / Juniper EX / Aruba-HPE gateway) with per-row Edit/Delete
// and an "+ Add Device" modal. Creds live in runtime system.json only.
function _renderSetupNwTile(content) {
    const { card, inputCls, labelCls, btnCls, btnSecCls } = _SETUP_CLS;
    content.innerHTML = `
            <div class="${card}">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Network Devices</h3>
                    <button onclick="showAddNwDeviceModal()" class="${btnCls}">+ Add Device</button>
                </div>
                <div id="nw-devices-list" class="space-y-2"></div>
            </div>`;
    loadNwDevicesList();
}
// GET /api/instances/nac (core/src/api.py get_instances).
// The IPAM → NAC endpoint sync schedule moved to the dedicated
// System → Sync tile (_renderSetupSyncTile).
function _renderSetupNacTile(content) {
    const { card, inputCls, labelCls, btnCls, btnSecCls } = _SETUP_CLS;
    content.innerHTML = `
            <div class="${card}">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">NAC / ClearPass Instances</h3>
                    <button onclick="showAddInstanceModal('nac')" class="${btnCls}">+ Add Instance</button>
                </div>
                <div id="nac-instances-list" class="space-y-2"></div>
            </div>`;
    loadInstances('nac');
}

// System → Sync tile. The unified home for cross-system sync schedules:
//   1. IPAM → NAC endpoint sync (moved here from Setup → Security/NAC)
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
                <div class="mt-4 flex items-center gap-3">
                    <button onclick="saveSelfBackupConfig()" id="sb-save-btn" class="${btnCls}">Save Schedule</button>
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
                <div class="mt-4 flex items-center gap-3">
                    <button onclick="saveSelfBackupConfig()" id="sb-copy-save-btn" class="${btnCls}">Save Copy Config</button>
                </div>
            </div>
            <div class="${card}">
                <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-3">Status &amp; Archives</h3>
                <div id="sb-status" class="space-y-2"><p class="text-xs text-slate-400 italic">Loading…</p></div>
                <div class="mt-4">
                    <div class="text-xs font-bold text-slate-500 uppercase tracking-wider mb-2">Local archives</div>
                    <div id="sb-archives" class="space-y-1"><p class="text-xs text-slate-400 italic">Loading…</p></div>
                </div>
            </div>
        `;
    loadSelfBackupStatus();
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
        const r = await setupFetch('/setup/backup/status');
        if (!r.ok) throw new Error(`${r.status}`);
        data = await r.json();
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
                    <span class="text-slate-400 ml-3 whitespace-nowrap">${_sbFmtBytes(f.size)} · ${when}</span>
                </div>`;
            }).join('');
        }
    }
}

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
                    <button onclick="saveEndpointSyncConfig()" class="${btnCls}">Save Schedule</button>
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
                        <button onclick="saveRealtimeNacSyncConfig()" class="${btnCls}">Save</button>
                    </div>
                    <div class="mt-4">
                        <div class="text-xs font-bold text-slate-500 uppercase tracking-wider mb-2">Last reverse sync per tenant</div>
                        <div id="rt-nac-sync-status" class="space-y-2"><p class="text-xs text-slate-400 italic">Loading…</p></div>
                    </div>
                </div>
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
                    <button onclick="saveVmSyncConfig()" class="${btnCls}">Save Schedule</button>
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
                <div class="mt-4 flex items-center gap-3">
                    <button onclick="saveFwDiscoveryConfig()" class="${btnCls}">Save Schedule</button>
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
                <div class="mt-4 flex items-center gap-3">
                    <button onclick="saveNwDiscoveryConfig()" class="${btnCls}">Save Schedule</button>
                    <span class="text-xs text-slate-400">Defaults apply to newly created devices only.</span>
                </div>
                <div class="mt-4">
                    <div class="text-xs font-bold text-slate-500 uppercase tracking-wider mb-2">Last sync per tenant</div>
                    <div id="nw-sync-status" class="space-y-2"><p class="text-xs text-slate-400 italic">Loading…</p></div>
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
                    <button onclick="saveStalenessSweepConfig()" class="${btnCls}">Save</button>
                </div>
                <div class="mt-4">
                    <div class="text-xs font-bold text-slate-500 uppercase tracking-wider mb-2">Last sweep</div>
                    <div id="staleness-sweep-status" class="space-y-2"><p class="text-xs text-slate-400 italic">Loading…</p></div>
                </div>
            </div>
            <div class="${card}">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">GitHub Repo Sync ${helpIcon('lm-hub', null, 'Hub help')}</h3>
                    <button id="repo-sync-run-btn" onclick="runRepoSyncNow()" class="${btnCls}">Sync now</button>
                </div>
                <p class="text-xs text-slate-400 mb-3">Scheduled replication of <strong>all repos</strong>: pulls the hub tree + <code>provisioning_repos/*</code> locally and pushes <code>SPOKE_UPDATE</code> to every approved spoke (pxmx / opnsense / cs / cppm / netbox / ldap / nw) every <em>interval</em> (default 15 min). The hub self-restarts only when its own code changed (rolled back if it fails to boot); each spoke self-pulls and restarts only on its own version change. Replaces the old 1-hour auto-update loop — this is the single scheduled sync.</p>
                <div class="flex flex-wrap items-end gap-4">
                    <label class="flex items-center gap-2 text-sm text-slate-600 cursor-pointer"><input type="checkbox" id="repo-sync-enabled" class="w-4 h-4 text-green-600 rounded" checked>Enable scheduled sync</label>
                    <div class="space-y-1">
                        <label class="${labelCls}">Interval (minutes)</label>
                        <input type="number" id="repo-sync-interval" min="1" value="15" class="w-24 bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                    </div>
                    <button onclick="saveRepoSyncConfig()" class="${btnCls}">Save</button>
                </div>
                <div class="mt-4">
                    <div class="text-xs font-bold text-slate-500 uppercase tracking-wider mb-2">Last sync</div>
                    <div id="repo-sync-status" class="space-y-2"><p class="text-xs text-slate-400 italic">Loading…</p></div>
                </div>
            </div>
            <div class="${card}">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Spoke Out-of-Contact Alerts ${helpIcon('lm-hub', null, 'Hub help')}</h3>
                    <button onclick="saveSpokeAlertConfig()" class="${btnCls}">Save</button>
                </div>
                <p class="text-xs text-slate-400 mb-3">Forgiving liveness alerting, separate from the realtime heartbeat traffic-light. A spoke that blips for a few seconds (restart, WAN jitter) stays quiet; only once an approved spoke has been <strong>out of contact</strong> for <em>warn minutes</em> does a <strong>warning</strong> fire, and after <em>error minutes</em> it escalates to <strong>error</strong> (which also lands in the Error Log / bugfixer feed). Decoupled from the 300s recovery watchdog — that still restarts stranded spokes on its own schedule.</p>
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
                    <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Source of Truth ${helpIcon('lm-hub', null, 'Hub help')}</h3>
                    <button onclick="saveSourceOfTruthConfig()" class="${btnCls}">Save</button>
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
    loadVmSyncSources();
    loadVmSyncConfig();
    loadVmSyncStatus();
    loadFwDiscoverySources();
    loadFwDiscoveryConfig();
    loadFwDiscoveryStatus();
    loadNwDiscoverySources();
    loadNwDiscoveryConfig();
    loadNwDiscoveryStatus();
    loadStalenessSweepConfig();
    loadStalenessSweepStatus();
    loadRepoSyncConfig();
    loadRepoSyncStatus();
    loadSourceOfTruthConfig();
    loadSpokeAlertConfig();
    loadSpokeAlerts();
}

// Setup → IPAM tile. IPAM / NetBox instances only.
// GET /api/instances/ipam (core/src/api.py get_instances).
// The Hypervisor → NetBox VM sync schedule moved to the dedicated
// System → Sync tile (_renderSetupSyncTile).
function _renderSetupIpamTile(content) {
    const { card, inputCls, labelCls, btnCls, btnSecCls } = _SETUP_CLS;
    content.innerHTML = `
            <div class="${card}">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">IPAM / NetBox Instances</h3>
                    <button onclick="showAddInstanceModal('ipam')" class="${btnCls}">+ Add Instance</button>
                </div>
                <div id="ipam-instances-list" class="space-y-2"></div>
            </div>`;
    loadInstances('ipam');
}

// Setup → LDAP tile. GET /api/instances/ldap (core/src/api.py get_instances).
function _renderSetupLdapTile(content) {
    const { card, inputCls, labelCls, btnCls, btnSecCls } = _SETUP_CLS;
    content.innerHTML = `
            <div class="${card}">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Directory / LDAP Instances</h3>
                    <button onclick="showAddInstanceModal('ldap')" class="${btnCls}">+ Add Instance</button>
                </div>
                <div id="ldap-instances-list" class="space-y-2"></div>
            </div>`;
    loadInstances('ldap');
}

// Setup → DNS tile. GET /api/instances/dns (core/src/api.py get_instances).
function _renderSetupDnsTile(content) {
    const { card, inputCls, labelCls, btnCls, btnSecCls } = _SETUP_CLS;
    content.innerHTML = `
            <div class="${card}">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">DNS / Unbound Instances</h3>
                    <button onclick="showAddInstanceModal('dns')" class="${btnCls}">+ Add Instance</button>
                </div>
                <div id="dns-instances-list" class="space-y-2"></div>
            </div>`;
    loadInstances('dns');
}

// Setup → DHCP tile. GET /api/instances/dhcp (core/src/api.py get_instances).
function _renderSetupDhcpTile(content) {
    const { card, inputCls, labelCls, btnCls, btnSecCls } = _SETUP_CLS;
    content.innerHTML = `
            <div class="${card}">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">DHCP / Kea Instances</h3>
                    <button onclick="showAddInstanceModal('dhcp')" class="${btnCls}">+ Add Instance</button>
                </div>
                <div id="dhcp-instances-list" class="space-y-2"></div>
            </div>`;
    loadInstances('dhcp');
}

// Setup → Module Management tile. One unified device-management page for every
// managed module (Firewalls, Network Devices, Security/NAC, IPAM, LDAP, DNS,
// DHCP). A single "+ Add Device" button opens a modal where the admin first
// picks the module type (OPNsense, ClearPass, NetBox, …) and then fills in
// that type's specifics — the device type is determined by the module type and
// the associated spoke it is attached to. All known devices are listed in one
// table with a per-row type badge + Edit/Delete. See DEVICE_TYPES below for the
// declarative per-type schema (endpoint, fields, spoke filter, payload key).
function _renderSetupModuleMgmtTile(content) {
    const { card, btnCls } = _SETUP_CLS;
    content.innerHTML = `
            <div class="${card}">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Managed Devices ${helpIcon('lm-hub', null, 'Hub help')}</h3>
                    <button onclick="showAddDeviceModal()" class="${btnCls}">+ Add Device</button>
                </div>
                <p class="text-xs text-slate-400 mb-3">Every managed module device in one place — firewalls, network devices, NAC, IPAM, directory, DNS, and DHCP instances. Click <strong>Add Device</strong> then choose the module type to attach.</p>
                <div id="all-devices-list" class="space-y-2"><p class="text-xs text-slate-400 italic animate-pulse">Loading…</p></div>
            </div>`;
    loadAllDevices();
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
            <div class="${card}">
                <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-1">Global USB Approvals ${helpIcon('cs', null, 'Simulations help')}</h3>
                <p class="text-xs text-slate-500 mb-3">Platform-wide USB dongle approvals — applies to every tenant (merged with each tenant's own list).</p>
                <div class="space-y-6">
                    <div>
                        <p class="${labelCls} mb-1">Certified globally</p>
                        <div id="global-usb-certified" class="space-y-2 mb-2"><p class="text-xs text-slate-400 italic">Loading…</p></div>
                        <div class="flex gap-1">
                            <input id="gusbc-vp" placeholder="1a2b:3c4d" class="w-28 font-mono text-xs ${inputCls} px-2 py-1">
                            <input id="gusbc-label" placeholder="label" class="flex-1 text-xs ${inputCls} px-2 py-1">
                            <select id="gusbc-type" class="text-xs ${inputCls} px-2 py-1"><option>wireless</option><option>wired</option><option>storage</option><option>other</option></select>
                            <button onclick="addGlobalUsbCert()" class="${btnCls} text-xs px-3 py-1">+ Add</button>
                        </div>
                    </div>
                    <div>
                        <p class="${labelCls} mb-1">Ignored globally</p>
                        <div id="global-usb-ignored" class="flex flex-wrap gap-1 mb-2 min-h-[2rem]"><p class="text-xs text-slate-400 italic">Loading…</p></div>
                        <div class="flex gap-1">
                            <input id="gusbi-vp" placeholder="1a2b:3c4d" class="w-28 font-mono text-xs ${inputCls} px-2 py-1">
                            <button onclick="addGlobalUsbIgnore()" class="${btnCls} text-xs px-3 py-1">+ Add</button>
                        </div>
                    </div>
                </div>
            </div>
            <div class="${card}">
                <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-1">Global Tier PCI VID:PIDs ${helpIcon('cs', null, 'Simulations help')}</h3>
                <p class="text-xs text-slate-500 mb-3">Platform-wide PCI-passthrough device IDs that classify a VM's tier — applies to every tenant (merged with each tenant's own list). <b>T1</b> = physical / base PCI (e.g. <span class="font-mono">1912:0015</span>); <b>T3</b> = the IoT adapter (e.g. <span class="font-mono">168c:0034</span>). T2 = USB dongle (above). Only T2 is ever auto-deleted under resource pressure; T1/T3 are never torn down.</p>
                <div class="grid grid-cols-2 gap-6">
                    <div>
                        <p class="${labelCls} mb-1">T1 PCI (never torn down)</p>
                        <div id="global-t1-pci" class="flex flex-wrap gap-1 mb-2 min-h-[2rem]"><p class="text-xs text-slate-400 italic">Loading…</p></div>
                        <div class="flex gap-1">
                            <input id="gt1-vp" placeholder="1912:0015" class="w-28 font-mono text-xs ${inputCls} px-2 py-1">
                            <button onclick="addGlobalTierPci('t1')" class="${btnCls} text-xs px-3 py-1">+ Add</button>
                        </div>
                    </div>
                    <div>
                        <p class="${labelCls} mb-1">T3 PCI (never torn down)</p>
                        <div id="global-t3-pci" class="flex flex-wrap gap-1 mb-2 min-h-[2rem]"><p class="text-xs text-slate-400 italic">Loading…</p></div>
                        <div class="flex gap-1">
                            <input id="gt3-vp" placeholder="168c:0034" class="w-28 font-mono text-xs ${inputCls} px-2 py-1">
                            <button onclick="addGlobalTierPci('t3')" class="${btnCls} text-xs px-3 py-1">+ Add</button>
                        </div>
                    </div>
                </div>
            </div>
            <div class="${card}">
                <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-1">Discovered USB Devices ${helpIcon('cs', null, 'Simulations help')}</h3>
                <p class="text-xs text-slate-500 mb-3">Every USB VID:PID seen across all tenants' spokes (plus tenant-certified/ignored entries not yet in telemetry). Approve or ignore a device type globally — applies to every tenant.</p>
                <div id="global-usb-discovered" class="space-y-2"><p class="text-xs text-slate-400 italic animate-pulse">Loading…</p></div>
            </div>
            <div class="${card}">
                <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-1">Per-Tenant USB ${helpIcon('cs', null, 'Simulations help')}</h3>
                <p class="text-xs text-slate-500 mb-3">Each tenant's own certified/ignored VID:PIDs (merged with the global list when pushed to their spoke). Approve/ignore per tenant below.</p>
                <div id="tenant-usb-list" class="space-y-3"><p class="text-xs text-slate-400 italic animate-pulse">Loading…</p></div>
            </div>
            <div class="${card}">
                <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-1">DHCP Server (Kea) ${helpIcon('cs', null, 'Simulations help')}</h3>
                <p class="text-xs text-slate-500 mb-3">Isolated sim-client DHCP (Kea <span class="font-mono">kea-dhcp4-sim</span>) on each cs spoke's second NIC (provisioned by install_cs.sh). Shows whether Kea is running and how full the lease pool is. A spoke without Kea shows "Not configured".</p>
                <div id="cs-dhcp-server-status" class="space-y-3"><p class="text-xs text-slate-400 italic animate-pulse">Loading…</p></div>
            </div>`;
    loadSimAdminOverview();
    loadGlobalTierPci();
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
        const pr = await fetch(_tierPciEndpoint(tier), {
            method: 'PUT', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ vidpids: cur }),
        });
        if (!pr.ok) throw new Error(`${pr.status}`);
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

// Setup → General (default) tile. Cache config + update sources + appearance.
// GET /setup/config + /api/cache/config + /api/appearance (core/src/api.py
// get_setup_config / get_cache_config / get_appearance). When invoked from the
// System view (currentView === 'settings'), also renders the Tenant Subnet
// Filtering toggle card — a system-wide enforcement posture setting that lives
// here rather than under Setup → Simulations. The same renderer serves Setup →
// General, where the toggle is intentionally hidden.
function _renderSetupGeneralTile(content) {
    const { card, inputCls, labelCls, btnCls, btnSecCls } = _SETUP_CLS;
    const subnetFilterCard = currentView === 'settings' ? `
        <div class="${card}">
            <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-1">Tenant Subnet Filtering ${helpIcon('lm-hub', null, 'Hub help')}</h3>
            <p class="text-xs text-slate-500 mb-3">Filter each module's data by the tenant's NetBox prefixes, enforced server-side (a tenant cannot see another tenant's subnet data even via the API). Disable for modules that are scoped by tenant ID instead of subnet (e.g. Simulations).</p>
            <div id="subnet-filter-toggles" class="space-y-2"><p class="text-xs text-slate-400 italic animate-pulse">Loading…</p></div>
        </div>` : '';
    content.innerHTML = `
        ${subnetFilterCard}
        <div class="${card}">
            <div class="flex justify-between items-center">
                <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Optimization — Data Cache ${helpIcon('lm-hub', null, 'Hub help')}</h3>
                <div class="flex items-center gap-3">
                    <label class="${labelCls}">Max Concurrent Tenants</label>
                    <input type="number" id="cache-max-concurrent" min="1" max="20" value="3"
                        class="w-16 bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                    <button onclick="saveCacheConfig()" class="${btnCls}">Save</button>
                    <button onclick="purgeAllCaches()" class="${btnSecCls}">Purge All</button>
                </div>
            </div>
            <div id="cache-config-rows" class="mt-3 grid grid-cols-3 gap-x-8 text-sm">
                <p class="col-span-2 py-4 text-center text-slate-400 italic text-xs">Loading…</p>
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
            <div class="flex gap-2 pt-2">
                <button onclick="saveUpdateSources()" class="${btnCls}">Save Sources</button>
            </div>
            <div class="border-t border-slate-200 mt-4 pt-4">
                <p class="text-xs text-slate-400 mb-3">How often the hub checks GitHub and syncs: pulls the hub tree + <code>provisioning_repos/*</code> locally and pushes an update to every approved spoke. Same schedule as System → Sync's "GitHub Repo Sync" card — either one saves/shows it.</p>
                <div class="flex flex-wrap items-end gap-4">
                    <label class="flex items-center gap-2 text-sm text-slate-600 cursor-pointer"><input type="checkbox" id="repo-sync-enabled" class="w-4 h-4 text-green-600 rounded" checked>Enable scheduled sync</label>
                    <div class="space-y-1">
                        <label class="${labelCls}">Check every (minutes)</label>
                        <input type="number" id="repo-sync-interval" min="1" value="15" class="w-24 bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500">
                    </div>
                    <button onclick="saveRepoSyncConfig()" class="${btnCls}">Save</button>
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
                <button onclick="saveToastConfig()" class="${btnCls}">Save</button>
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
                <button onclick="saveRelayTimeouts()" class="${btnCls}">Save</button>
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
            <div class="flex items-center gap-3">
                <button onclick="saveAppearance()" class="${btnCls}">Save</button>
                <span id="appearance-status" class="text-xs text-slate-400"></span>
            </div>
        </div>`;
    loadSetupConfig();
    loadCacheConfig();
    loadAppearanceForm();
    loadToastConfigForm();
    loadRelayTimeoutsForm();
    loadRepoSyncConfig();
    if (currentView === 'settings') loadSubnetFilterToggles();
}

// Dispatch table: each Setup submenu → its tile renderer. The General tile is
// the fallback (run when subMenu matches none of the keys), preserving the
// original monolithic function's trailing default branch.
// ── Settings → SSO (Microsoft Entra ID / OIDC) ──────────────────────────────
// Admin config for Entra ID SSO — enable it, set tenant/client/cert/group/MFA.
// Reads/writes /setup/oidc-config (core/src/routes/oidc.py); env LM_OIDC_* wins
// over stored values. Enabling shows the "Sign in with Microsoft" login button.
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
                <label class="flex items-center gap-2 text-sm text-slate-600 cursor-pointer"><input type="checkbox" id="oidc-mfa" class="w-4 h-4 text-green-600 rounded" checked>Require MFA (reject logins without <code>amr=mfa</code>)</label>
            </div>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div class="space-y-1"><label class="${labelCls}">Directory (tenant) ID</label><input id="oidc-tenant" type="text" placeholder="xxxxxxxx-xxxx-xxxx-…" class="${inputCls}"></div>
                <div class="space-y-1"><label class="${labelCls}">Application (client) ID</label><input id="oidc-client" type="text" placeholder="xxxxxxxx-xxxx-xxxx-…" class="${inputCls}"></div>
                <div class="space-y-1"><label class="${labelCls}">Redirect URI</label><input id="oidc-redirect" type="text" placeholder="https://your-hub/auth/oidc/callback" class="${inputCls}"></div>
                <div class="space-y-1"><label class="${labelCls}">Allowed group (object ID, optional)</label><input id="oidc-group" type="text" placeholder="Entra group object ID — gate access" class="${inputCls}"></div>
                <div class="space-y-1"><label class="${labelCls}">Client certificate path (on hub)</label><input id="oidc-cert" type="text" placeholder="/etc/lm/oidc/client-cert.pem" class="${inputCls}"></div>
                <div class="space-y-1"><label class="${labelCls}">Client private-key path (on hub)</label><input id="oidc-key" type="text" placeholder="/etc/lm/oidc/client-key.pem" class="${inputCls}"></div>
            </div>
            <div class="mt-4 flex items-center gap-3">
                <button onclick="saveOidcConfig()" id="oidc-save-btn" class="${btnCls}">Save SSO Config</button>
                <span id="oidc-save-msg" class="text-xs text-slate-400"></span>
            </div>
            <p class="text-[11px] text-slate-400 mt-2">The private key is referenced by <em>path</em> only — key material is never stored or read by the WebUI. In Entra: register the app, add the redirect URI above, upload the certificate, and grant Graph <code>GroupMember.Read.All</code> for the &gt;200-group fallback.</p>
        </div>`;
    loadOidcConfig();
}

async function loadOidcConfig() {
    try {
        const res = await setupFetch('/setup/oidc-config');
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();
        const cfg = data.config || {};
        const set = (id, v) => { const el = document.getElementById(id); if (el) el.value = v || ''; };
        const chk = (id, v) => { const el = document.getElementById(id); if (el) el.checked = !!v; };
        chk('oidc-enabled', cfg.enabled);
        chk('oidc-mfa', cfg.require_mfa !== false);
        set('oidc-tenant', cfg.tenant_id); set('oidc-client', cfg.client_id);
        set('oidc-redirect', cfg.redirect_uri); set('oidc-group', cfg.allowed_group);
        set('oidc-cert', cfg.cert_path); set('oidc-key', cfg.key_path);
        const pill = document.getElementById('oidc-state-pill');
        if (pill) {
            pill.textContent = cfg.enabled ? 'ENABLED' : 'DISABLED';
            pill.className = 'text-[11px] px-2 py-0.5 rounded-full font-bold ' +
                (cfg.enabled ? 'bg-green-100 text-green-700' : 'bg-slate-100 text-slate-500');
        }
    } catch (e) { console.error('loadOidcConfig failed', e); }
}

async function saveOidcConfig() {
    const btn = document.getElementById('oidc-save-btn');
    const msg = document.getElementById('oidc-save-msg');
    const v = id => (document.getElementById(id)?.value || '').trim();
    const config = {
        enabled: !!document.getElementById('oidc-enabled')?.checked,
        require_mfa: !!document.getElementById('oidc-mfa')?.checked,
        tenant_id: v('oidc-tenant'), client_id: v('oidc-client'),
        redirect_uri: v('oidc-redirect'), allowed_group: v('oidc-group'),
        cert_path: v('oidc-cert'), key_path: v('oidc-key'),
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
        if (btn) { btn.disabled = false; btn.textContent = 'Save SSO Config'; }
    }
}

const SETUP_TILES = {
    'Spokes & Agents':  _renderSetupSpokesTile,
    'Module Management': _renderSetupModuleMgmtTile,
    'Tenant Config':    _renderSetupTenantTile,
    'User Access':      _renderSetupUserAccessTile,
    'Simulations':      _renderSetupSimulationsTile,
    'Remote Console':   _renderSetupRemoteConsoleTile,
};

// _renderSetupSection — dispatches to one of the _renderSetup*Tile helpers
// above based on the Setup submenu. Each tile renders its cards into `content`
// and triggers the matching load* fetch(es). Shared card/input/button class
// strings live in _SETUP_CLS so every tile uses identical styling. Endpoints
// cross-ref core/src/api.py (get_pending_spokes, get_tenants, get_users,
// get_firewalls, get_instances, get_endpoint_sync_*, get_vm_sync_*, get_generic_agents,
// get_setup_config, get_cache_config, get_appearance) and the Simulations
// sub-module under /sim/api/* (core/src/simulations/routes.py).
function _renderSetupSection(subMenu, container) {
    const content = container || document.getElementById('setup-content');
    if (!content) return;
    const tile = SETUP_TILES[subMenu] || _renderSetupGeneralTile;
    tile(content);
}

// ── Setup → Simulations admin overview ────────────────────────────────────
// Module subnet-filter toggles + global/per-tenant USB management. Admin-only
// (the submenu is hidden for non-admins and the backend 403s non-admins).
const _SUBNET_FILTER_MODULES = [
    { key: 'nac',       label: 'Security / NAC' },
    { key: 'firewall',   label: 'Firewall' },
    { key: 'netbox',     label: 'IPAM' },
    { key: 'dns',        label: 'DNS' },
    { key: 'dhcp',       label: 'DHCP' },
    { key: 'hypervisor', label: 'Hypervisor' },
    { key: 'cs',         label: 'Simulations (tenant-ID scoped)' },
];
let _subnetFilterState = {};

function _vpValid(v) { return /^[0-9a-f]{4}:[0-9a-f]{4}$/.test(String(v || '').trim().toLowerCase()); }

async function loadSimAdminOverview() {
    loadUsbOverview();
    loadDiscoveredUsb();
    loadDhcpServerStatus();
}

async function loadDhcpServerStatus() {
    const wrap = document.getElementById('cs-dhcp-server-status');
    if (!wrap) return;
    let data;
    try {
        const r = await fetch('/sim/api/superadmin/dhcp-status', { credentials: 'same-origin' });
        if (!r.ok) throw new Error(`${r.status}`);
        data = await r.json();
    } catch (e) {
        wrap.innerHTML = `<p class="text-xs text-red-500">Failed: ${e.message}</p>`;
        return;
    }
    const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    // Flatten tenant → spoke rows (each row carries its cached Kea status block).
    const rows = [];
    for (const t of (data.tenants || [])) {
        for (const sp of (t.spokes || [])) {
            rows.push({ tenant: t.tenant_name || t.tenant_id, spoke: sp });
        }
    }
    if (!rows.length) {
        wrap.innerHTML = '<p class="text-xs text-slate-400 italic">No cs spokes reporting.</p>';
        return;
    }
    wrap.innerHTML = rows.map(({ tenant, spoke }) => {
        const d = spoke.dhcp || {};
        const head = `<span class="text-sm font-bold text-slate-700">${esc(tenant)} <span class="text-xs font-mono text-slate-400">${esc(spoke.spoke_id)}</span></span>`;
        // Kea not installed → "Not configured" (ignore, per requirement).
        if (d.installed === false) {
            return `<div class="border border-slate-200 rounded-md p-3">
                <div class="flex items-center justify-between mb-1">${head}
                    <span class="text-xs px-2 py-0.5 rounded-full bg-slate-100 text-slate-500">Not configured</span>
                </div><p class="text-xs text-slate-400">Kea (kea-dhcp4-sim) not installed on this spoke.</p></div>`;
        }
        // No dhcp block → spoke offline / hasn't reported.
        if (d.installed !== true) {
            return `<div class="border border-slate-200 rounded-md p-3">
                <div class="flex items-center justify-between mb-1">${head}
                    <span class="text-xs px-2 py-0.5 rounded-full bg-slate-100 text-slate-400">No data</span>
                </div><p class="text-xs text-slate-400">No DHCP telemetry from this spoke (offline or not reporting).</p></div>`;
        }
        // installed === true → running pill + utilization bar.
        const running = !!d.running;
        const pill = running
            ? '<span class="text-xs px-2 py-0.5 rounded-full bg-green-100 text-green-700">● Running</span>'
            : '<span class="text-xs px-2 py-0.5 rounded-full bg-red-100 text-red-700">● Not running</span>';
        const pct = Math.max(0, Math.min(100, Number(d.utilization_pct) || 0));
        const barColor = pct > 85 ? 'bg-red-500' : pct > 60 ? 'bg-amber-400' : 'bg-green-500';
        const used = Number(d.leases_used) || 0;
        const size = Number(d.pool_size) || 0;
        const iface = d.iface ? `iface <span class="font-mono">${esc(d.iface)}</span>` : 'iface <span class="text-slate-400">—</span>';
        const subnet = d.subnet ? ` · <span class="font-mono">${esc(d.subnet)}</span>` : '';
        const pool = (d.pool_start && d.pool_end)
            ? `pool <span class="font-mono">${esc(d.pool_start)}–${esc(d.pool_end)}</span> (${size})`
            : (size ? `pool size ${size}` : 'pool <span class="text-slate-400">—</span>');
        return `<div class="border border-slate-200 rounded-md p-3">
            <div class="flex items-center justify-between mb-2">${head}${pill}</div>
            <p class="text-xs text-slate-500 mb-2">${iface}${subnet} · ${pool}</p>
            <div class="flex items-center gap-2">
                <div class="flex-1 bg-slate-200 rounded-full h-2 overflow-hidden">
                    <div class="${barColor} h-2 rounded-full" style="width:${pct}%"></div>
                </div>
                <span class="text-xs font-mono text-slate-600 whitespace-nowrap">leases ${used} / ${size} (${pct.toFixed(1)}%)</span>
            </div></div>`;
    }).join('');
}

// ── IPAM → NAC endpoint sync (System → Sync) ───────────────────────
async function loadEndpointSyncSources() {
    // Populate the IPAM source dropdown from the hub's IPAM_SOURCES registry
    // (data-driven: a new product added on the hub appears here with no UI
    // change) and mark each source's connected state.
    const sel = document.getElementById('ep-sync-source');
    if (!sel) return;
    try {
        const r = await setupFetch('/setup/endpoint-sync/sources');
        if (!r.ok) return;
        const data = await r.json();
        const cur = sel.value;
        sel.innerHTML = (data.sources || []).map(s =>
            `<option value="${s.name}">${s.label}${s.connected ? '' : ' (not connected)'}</option>`
        ).join('');
        if (cur) sel.value = cur;
    } catch (e) { console.error('loadEndpointSyncSources failed', e); }
}

async function loadEndpointSyncConfig() {
    // Populate the enable/source/mode/interval/time inputs from global_config.
    // (loadSetupConfig runs once at setup init, before this card exists, so
    // we fetch fresh when the Sync card renders.)
    try {
        const r = await setupFetch('/setup/config');
        if (!r.ok) return;
        const data = await r.json();
        const epSync = (data.global_config || {}).netbox_cppm_sync || {};
        const epChk = document.getElementById('ep-sync-enabled');
        const epSrc = document.getElementById('ep-sync-source');
        const epMode = document.getElementById('ep-sync-mode');
        const epInt = document.getElementById('ep-sync-interval');
        const epTime = document.getElementById('ep-sync-time');
        if (epChk) epChk.checked = epSync.enabled === true;
        if (epSrc && epSync.source) epSrc.value = epSync.source;
        if (epMode) epMode.value = epSync.mode === 'daily' ? 'daily' : 'interval';
        if (epInt) epInt.value = Math.max(1, Math.round((epSync.interval_seconds || 3600) / 60));
        if (epTime) epTime.value = epSync.daily_time || '02:00';
    } catch (e) { console.error('loadEndpointSyncConfig failed', e); }
}

async function loadEndpointSyncStatus() {
    const wrap = document.getElementById('endpoint-sync-status');
    if (!wrap) return;
    let data;
    try {
        const r = await setupFetch('/setup/endpoint-sync/status');
        if (!r.ok) throw new Error(`${r.status}`);
        data = await r.json();
    } catch (e) {
        wrap.innerHTML = `<p class="text-xs text-red-500">Failed: ${e.message}</p>`;
        return;
    }
    const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    const rows = data.tenants || [];
    if (!rows.length) {
        wrap.innerHTML = '<p class="text-xs text-slate-400 italic">No syncs recorded yet. Click “Sync now” to run one.</p>';
        return;
    }
    wrap.innerHTML = rows.map(t => {
        const st = String(t.status || '');
        const pill = st === 'success' ? 'bg-green-100 text-green-700'
            : st === 'error' ? 'bg-red-100 text-red-700'
            : st === 'skipped' ? 'bg-slate-100 text-slate-500' : 'bg-slate-100 text-slate-400';
        const pushed = Number(t.pushed) || 0;
        const errors = Number(t.errors) || 0;
        const total = Number(t.endpoints_total) || 0;
        const skipped = Number(t.skipped) || 0;
        const skipDetails = Array.isArray(t.skipped_details) ? t.skipped_details : [];
        // Dedupe the CPPM spoke's per-record skip reasons into reason→count so
        // the operator sees WHY records were dropped, not just that they were.
        const skipReasons = {};
        for (const s of skipDetails) {
            const r = s && s.reason ? String(s.reason) : 'skipped';
            skipReasons[r] = (skipReasons[r] || 0) + 1;
        }
        const skipLine = skipped > 0
            ? ` · <span class="text-amber-600">skipped ${skipped}</span>`
            : '';
        const skipReasonHtml = Object.keys(skipReasons).length
            ? `<p class="text-xs text-amber-600 mt-1">Skipped: ${esc(Object.entries(skipReasons).map(([r, c]) => `${r} (${c})`).join('; '))}</p>`
            : '';
        return `<div class="border border-slate-200 rounded-md p-3">
            <div class="flex items-center justify-between mb-1">
                <span class="text-sm font-bold text-slate-700">${esc(t.tenant_name || t.tenant_id)} <span class="text-xs font-mono text-slate-400">${esc(t.tenant_id)}</span></span>
                <span class="text-xs px-2 py-0.5 rounded-full ${pill}">${esc(st || '—')}</span>
            </div>
            <p class="text-xs text-slate-500">pushed ${pushed} · errors ${errors} · endpoints ${total}${skipLine} <span class="text-slate-400">· last ${fmtDate(t.last_sync_ts)}</span></p>
            ${t.message ? `<p class="text-xs text-slate-400 mt-1">${esc(t.message)}</p>` : ''}
            ${skipReasonHtml}
        </div>`;
    }).join('');
}

async function runEndpointSyncNow() {
    const btn = document.getElementById('ep-sync-run-btn');
    const orig = btn ? btn.textContent : '';
    if (btn) { btn.disabled = true; btn.textContent = 'Syncing…'; }
    try {
        const r = await setupFetch('/setup/endpoint-sync/run', {
            method: 'POST',
            body: JSON.stringify({})
        });
        if (!r.ok) throw new Error(`${r.status}`);
        const data = await r.json();
        const s = data.summary || {};
        showToast(`Synced ${s.tenants || 0} tenant(s): ${s.pushed || 0} pushed, ${s.errors || 0} errors.`, (s.errors || 0) ? 'info' : 'success');
        await loadEndpointSyncStatus();
    } catch (e) {
        showToast('Sync failed: ' + e.message, 'error');
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = orig; }
    }
}

async function saveEndpointSyncConfig() {
    const enabled = document.getElementById('ep-sync-enabled')?.checked ? true : false;
    const source = document.getElementById('ep-sync-source')?.value || 'netbox';
    const mode = document.getElementById('ep-sync-mode')?.value || 'interval';
    const intervalMin = Math.max(1, parseInt(document.getElementById('ep-sync-interval')?.value, 10) || 60);
    const dailyTime = document.getElementById('ep-sync-time')?.value || '02:00';
    try {
        const r = await setupFetch('/setup/config', {
            method: 'POST',
            body: JSON.stringify({ config: { netbox_cppm_sync: {
                enabled, source, mode, interval_seconds: intervalMin * 60, daily_time: dailyTime
            } } })
        });
        if (r.ok) showToast('Endpoint sync schedule saved.', 'success');
        else showToast('Failed to save schedule.', 'error');
    } catch (e) {
        showToast('Error saving schedule: ' + e.message, 'error');
    }
}

// ── Realtime NAC → IPAM reverse sync (System → Sync, same "IPAM ↔ NAC" card) ──
async function loadRealtimeNacSyncConfig() {
    // Populate the enable/interval/lookback inputs from global_config.
    try {
        const r = await setupFetch('/setup/config');
        if (!r.ok) return;
        const data = await r.json();
        const cfg = (data.global_config || {}).realtime_ipam_nac_sync || {};
        const en = document.getElementById('rt-nac-sync-enabled');
        const intv = document.getElementById('rt-nac-sync-interval');
        const lb = document.getElementById('rt-nac-sync-lookback');
        if (en) en.checked = cfg.enabled === true;
        if (intv) intv.value = Math.max(1, Math.round((cfg.interval_seconds || 60) / 60));
        if (lb) lb.value = Math.max(1, cfg.lookback_minutes || 2);
    } catch (e) { console.error('loadRealtimeNacSyncConfig failed', e); }
}

async function loadRealtimeNacSyncStatus() {
    const wrap = document.getElementById('rt-nac-sync-status');
    if (!wrap) return;
    let data;
    try {
        const r = await setupFetch('/setup/realtime-nac-sync/status');
        if (!r.ok) throw new Error(`${r.status}`);
        data = await r.json();
    } catch (e) {
        wrap.innerHTML = `<p class="text-xs text-red-500">Failed: ${e.message}</p>`;
        return;
    }
    const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    const rows = data.tenants || [];
    if (!rows.length) {
        wrap.innerHTML = '<p class="text-xs text-slate-400 italic">No syncs recorded yet. Click “Sync now” to run one.</p>';
        return;
    }
    wrap.innerHTML = rows.map(t => {
        const st = String(t.status || '');
        const pill = st === 'success' ? 'bg-green-100 text-green-700'
            : st === 'error' ? 'bg-red-100 text-red-700'
            : st === 'skipped' ? 'bg-slate-100 text-slate-500' : 'bg-slate-100 text-slate-400';
        const pushed = Number(t.pushed) || 0;
        const errors = Number(t.errors) || 0;
        const skipped = Number(t.skipped) || 0;
        const total = Number(t.sessions_total) || 0;
        const skipLine = skipped > 0 ? ` · <span class="text-amber-600">skipped ${skipped}</span>` : '';
        return `<div class="border border-slate-200 rounded-md p-3">
            <div class="flex items-center justify-between mb-1">
                <span class="text-sm font-bold text-slate-700">${esc(t.tenant_name || t.tenant_id)} <span class="text-xs font-mono text-slate-400">${esc(t.tenant_id)}</span></span>
                <span class="text-xs px-2 py-0.5 rounded-full ${pill}">${esc(st || '—')}</span>
            </div>
            <p class="text-xs text-slate-500">added ${pushed} · already-present ${skipped} · errors ${errors} · sessions ${total}${skipLine} <span class="text-slate-400">· last ${fmtDate(t.last_sync_ts)}</span></p>
            ${t.message ? `<p class="text-xs text-slate-400 mt-1">${esc(t.message)}</p>` : ''}
        </div>`;
    }).join('');
}

async function runRealtimeNacNow() {
    const btn = document.getElementById('rt-nac-sync-run-btn');
    const orig = btn ? btn.textContent : '';
    if (btn) { btn.disabled = true; btn.textContent = 'Syncing…'; }
    try {
        const r = await setupFetch('/setup/realtime-nac-sync/run', {
            method: 'POST',
            body: JSON.stringify({})
        });
        if (!r.ok) throw new Error(`${r.status}`);
        const data = await r.json();
        const s = data.summary || {};
        showToast(`Synced ${s.tenants || 0} tenant(s): ${s.pushed || 0} added, ${s.errors || 0} errors.`, (s.errors || 0) ? 'info' : 'success');
        await loadRealtimeNacSyncStatus();
    } catch (e) {
        showToast('Sync failed: ' + e.message, 'error');
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = orig; }
    }
}

async function saveRealtimeNacSyncConfig() {
    const enabled = document.getElementById('rt-nac-sync-enabled')?.checked ? true : false;
    const intervalMin = Math.max(1, parseInt(document.getElementById('rt-nac-sync-interval')?.value, 10) || 1);
    const lookback = Math.max(1, parseInt(document.getElementById('rt-nac-sync-lookback')?.value, 10) || 2);
    try {
        const r = await setupFetch('/setup/config', {
            method: 'POST',
            body: JSON.stringify({ config: { realtime_ipam_nac_sync: {
                enabled, interval_seconds: intervalMin * 60, lookback_minutes: lookback
            } } })
        });
        if (r.ok) showToast('Realtime reverse sync saved.', 'success');
        else showToast('Failed to save.', 'error');
    } catch (e) {
        showToast('Error saving: ' + e.message, 'error');
    }
}

// ── NetBox staleness sweep (System → Sync, cluster-wide) ────────────────
async function loadStalenessSweepConfig() {
    // Populate enable/interval/stale-days/delete-days from global_config.
    try {
        const r = await setupFetch('/setup/config');
        if (!r.ok) return;
        const data = await r.json();
        const cfg = (data.global_config || {}).staleness_sweep || {};
        const en = document.getElementById('staleness-sweep-enabled');
        const intv = document.getElementById('staleness-sweep-interval');
        const sd = document.getElementById('staleness-sweep-stale-days');
        const dd = document.getElementById('staleness-sweep-delete-days');
        if (en) en.checked = cfg.enabled === true;
        if (intv) intv.value = Math.max(1, Math.round((cfg.interval_seconds || 3600) / 60));
        if (sd) sd.value = Math.max(1, cfg.stale_days || 7);
        if (dd) dd.value = Math.max(1, cfg.delete_days || 30);
    } catch (e) { console.error('loadStalenessSweepConfig failed', e); }
}

async function loadStalenessSweepStatus() {
    const wrap = document.getElementById('staleness-sweep-status');
    if (!wrap) return;
    let data;
    try {
        const r = await setupFetch('/setup/staleness-sweep/status');
        if (!r.ok) throw new Error(`${r.status}`);
        data = await r.json();
    } catch (e) {
        wrap.innerHTML = `<p class="text-xs text-red-500">Failed: ${e.message}</p>`;
        return;
    }
    if (!data || !data.last_sync_ts) {
        wrap.innerHTML = '<p class="text-xs text-slate-400 italic">No sweep recorded yet. Click “Sweep now” to run one.</p>';
        return;
    }
    const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    const st = String(data.status || '');
    const pill = st === 'success' ? 'bg-green-100 text-green-700'
        : st === 'error' ? 'bg-red-100 text-red-700' : 'bg-slate-100 text-slate-500';
    wrap.innerHTML = `<div class="border border-slate-200 rounded-md p-3">
        <div class="flex items-center justify-between mb-1">
            <span class="text-sm font-bold text-slate-700">Cluster-wide</span>
            <span class="text-xs px-2 py-0.5 rounded-full ${pill}">${esc(st || '—')}</span>
        </div>
        <p class="text-xs text-slate-500">scanned ${Number(data.scanned) || 0} · decommissioned ${Number(data.decommissioned) || 0} · deleted ${Number(data.deleted) || 0} · IPs freed ${Number(data.ip_freed) || 0} · errors ${Number(data.errors) || 0} <span class="text-slate-400">· last ${fmtDate(data.last_sync_ts)}</span></p>
        ${data.message ? `<p class="text-xs text-slate-400 mt-1">${esc(data.message)}</p>` : ''}
    </div>`;
}

async function runStalenessSweepNow() {
    const btn = document.getElementById('staleness-sweep-run-btn');
    const orig = btn ? btn.textContent : '';
    if (btn) { btn.disabled = true; btn.textContent = 'Sweeping…'; }
    try {
        const r = await setupFetch('/setup/staleness-sweep/run', {
            method: 'POST',
            body: JSON.stringify({})
        });
        if (!r.ok) throw new Error(`${r.status}`);
        const data = await r.json();
        const s = data.summary || {};
        showToast(`Sweep: ${s.decommissioned || 0} decommissioned, ${s.deleted || 0} deleted, ${s.ip_freed || 0} IPs freed${(s.errors || 0) ? `, ${s.errors} errors` : ''}.`,
                  (s.errors || 0) ? 'info' : 'success');
        await loadStalenessSweepStatus();
    } catch (e) {
        showToast('Sweep failed: ' + e.message, 'error');
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = orig; }
    }
}

async function saveStalenessSweepConfig() {
    const enabled = document.getElementById('staleness-sweep-enabled')?.checked ? true : false;
    const intervalMin = Math.max(1, parseInt(document.getElementById('staleness-sweep-interval')?.value, 10) || 60);
    const staleDays = Math.max(1, parseInt(document.getElementById('staleness-sweep-stale-days')?.value, 10) || 7);
    const deleteDays = Math.max(1, parseInt(document.getElementById('staleness-sweep-delete-days')?.value, 10) || 30);
    try {
        const r = await setupFetch('/setup/config', {
            method: 'POST',
            body: JSON.stringify({ config: { staleness_sweep: {
                enabled, interval_seconds: intervalMin * 60,
                stale_days: staleDays, delete_days: deleteDays
            } } })
        });
        if (r.ok) showToast('Staleness sweep saved.', 'success');
        else showToast('Failed to save.', 'error');
    } catch (e) {
        showToast('Error saving: ' + e.message, 'error');
    }
}

// ── GitHub repo sync (System → Sync; replaces the old auto-update loop) ───
// Pulls the hub tree + provisioning_repos/* locally and fans SPOKE_UPDATE out
// to every approved spoke every interval (default 15 min). Saved via /setup/config
// under global_config.repo_sync. Status from GET /setup/repo-sync/status,
// on-demand run from POST /setup/repo-sync/run.
async function loadRepoSyncConfig() {
    try {
        const r = await setupFetch('/setup/config');
        if (!r.ok) return;
        const data = await r.json();
        const cfg = (data.global_config || {}).repo_sync || {};
        const en = document.getElementById('repo-sync-enabled');
        const intv = document.getElementById('repo-sync-interval');
        // Default: enabled, 15-minute interval.
        if (en) en.checked = cfg.enabled !== false;
        if (intv) intv.value = Math.max(1, Math.round((cfg.interval_seconds || 900) / 60));
    } catch (e) { console.error('loadRepoSyncConfig failed', e); }
}

async function loadRepoSyncStatus() {
    const wrap = document.getElementById('repo-sync-status');
    if (!wrap) return;
    let data;
    try {
        const r = await setupFetch('/setup/repo-sync/status');
        if (!r.ok) throw new Error(`${r.status}`);
        data = await r.json();
    } catch (e) {
        wrap.innerHTML = `<p class="text-xs text-red-500">Failed: ${e.message}</p>`;
        return;
    }
    if (!data || !data.last_sync_ts) {
        wrap.innerHTML = '<p class="text-xs text-slate-400 italic">No sync recorded yet. Click “Sync now” to run one.</p>';
        return;
    }
    const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    const hub = data.hub || {};
    const hs = String(hub.status || '');
    const pill = hs === 'success' ? 'bg-green-100 text-green-700'
        : hs === 'error' ? 'bg-red-100 text-red-700' : 'bg-slate-100 text-slate-500';
    const prov = Array.isArray(data.provisioning_repos) ? data.provisioning_repos : [];
    const okN = prov.filter(r => r.status === 'ok').length;
    const errN = prov.filter(r => r.status === 'error').length;
    const skipN = prov.filter(r => r.status === 'skipped').length;
    const changed = prov.filter(r => r.changed).map(r => r.name);
    const provRows = prov.length ? prov.map(r => {
        const dot = r.status === 'ok' ? 'bg-green-500'
            : r.status === 'error' ? 'bg-red-500' : 'bg-slate-300';
        return `<div class="flex items-center gap-2"><span class="w-2 h-2 rounded-full ${dot}"></span>
            <span class="text-xs text-slate-600">${esc(r.name)}</span>
            <span class="text-xs text-slate-400">${esc(r.message || r.status)}</span></div>`;
    }).join('') : '<p class="text-xs text-slate-400 italic">No provisioning_repos present.</p>';
    wrap.innerHTML = `<div class="border border-slate-200 rounded-md p-3">
        <div class="flex items-center justify-between mb-1">
            <span class="text-sm font-bold text-slate-700">Hub update</span>
            <span class="text-xs px-2 py-0.5 rounded-full ${pill}">${esc(hs || '—')}</span>
        </div>
        <p class="text-xs text-slate-500">provisioning_repos: ${okN} ok · ${errN} error · ${skipN} skipped <span class="text-slate-400">· last ${fmtDate(data.last_sync_ts)}</span></p>
        ${changed.length ? `<p class="text-xs text-slate-500 mt-1">changed: ${esc(changed.join(', '))}</p>` : ''}
        ${data.message ? `<p class="text-xs text-slate-400 mt-1">${esc(data.message)}</p>` : ''}
        ${hub.message ? `<p class="text-xs text-slate-400 mt-1">${esc(hub.message)}</p>` : ''}
        <div class="mt-2 space-y-1">${provRows}</div>
    </div>`;
}

async function runRepoSyncNow() {
    const btn = document.getElementById('repo-sync-run-btn');
    const orig = btn ? btn.textContent : '';
    if (btn) { btn.disabled = true; btn.textContent = 'Syncing…'; }
    try {
        const r = await setupFetch('/setup/repo-sync/run', {
            method: 'POST',
            body: JSON.stringify({})
        });
        if (!r.ok) throw new Error(`${r.status}`);
        const data = await r.json();
        const s = data.summary || {};
        const restarting = /restart/i.test(String((data.result || {}).message || ''));
        showToast(`Repo sync: ${s.provisioning_repos_ok || 0} repos ok, ${s.provisioning_repos_error || 0} errors${restarting ? ' — hub restarting' : ''}.`,
                  (s.provisioning_repos_error || 0) ? 'info' : 'success');
        await loadRepoSyncStatus();
    } catch (e) {
        showToast('Repo sync failed: ' + e.message, 'error');
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = orig; }
    }
}

async function saveRepoSyncConfig() {
    const enabled = document.getElementById('repo-sync-enabled')?.checked ? true : false;
    const intervalMin = Math.max(1, parseInt(document.getElementById('repo-sync-interval')?.value, 10) || 15);
    try {
        const r = await setupFetch('/setup/config', {
            method: 'POST',
            body: JSON.stringify({ config: { repo_sync: {
                enabled, interval_seconds: intervalMin * 60
            } } })
        });
        if (r.ok) showToast('Repo sync schedule saved.', 'success');
        else showToast('Failed to save.', 'error');
    } catch (e) {
        showToast('Error saving: ' + e.message, 'error');
    }
}

// ── Source of Truth per module (System → Sync; saved via /setup/config) ──
const _SOT_DEFAULTS = { vm_sync: 'external', device_sync: 'netbox',
                        access_tracker: 'netbox', endpoint_sync: 'netbox' };

async function loadSourceOfTruthConfig() {
    try {
        const r = await setupFetch('/setup/config');
        if (!r.ok) return;
        const data = await r.json();
        const sot = (data.global_config || {}).source_of_truth || {};
        for (const k of Object.keys(_SOT_DEFAULTS)) {
            const el = document.getElementById('sot-' + k.replace(/_/g, '-'));
            if (el) el.value = sot[k] || _SOT_DEFAULTS[k];
        }
    } catch (e) { console.error('loadSourceOfTruthConfig failed', e); }
}

async function saveSourceOfTruthConfig() {
    const sot = {};
    for (const k of Object.keys(_SOT_DEFAULTS)) {
        const el = document.getElementById('sot-' + k.replace(/_/g, '-'));
        sot[k] = el ? (el.value || _SOT_DEFAULTS[k]) : _SOT_DEFAULTS[k];
    }
    try {
        const r = await setupFetch('/setup/config', {
            method: 'POST',
            body: JSON.stringify({ config: { source_of_truth: sot } })
        });
        if (r.ok) showToast('Source-of-truth saved.', 'success');
        else showToast('Failed to save.', 'error');
    } catch (e) {
        showToast('Error saving: ' + e.message, 'error');
    }
}

// ── Spoke out-of-contact alerts (System → Sync; saved via /setup/config) ──
// global_config["spoke_alert"] = {enabled, warn_s, error_s}. The loop
// (core/src/spoke_alert_sync.py run_spoke_alert_loop) reads it fresh each cycle.
async function loadSpokeAlertConfig() {
    try {
        const r = await setupFetch('/setup/config');
        if (!r.ok) return;
        const data = await r.json();
        const cfg = (data.global_config || {}).spoke_alert || {};
        const en = document.getElementById('spoke-alert-enabled');
        const wmin = document.getElementById('spoke-alert-warn-min');
        const emin = document.getElementById('spoke-alert-error-min');
        if (en) en.checked = cfg.enabled === true;
        if (wmin) wmin.value = Math.max(1, Math.round((cfg.warn_s || 300) / 60));
        if (emin) emin.value = Math.max(1, Math.round((cfg.error_s || 1800) / 60));
    } catch (e) { console.error('loadSpokeAlertConfig failed', e); }
}

async function saveSpokeAlertConfig() {
    const enabled = document.getElementById('spoke-alert-enabled')?.checked ? true : false;
    const warnMin = Math.max(1, parseInt(document.getElementById('spoke-alert-warn-min')?.value, 10) || 5);
    const errorMin = Math.max(1, parseInt(document.getElementById('spoke-alert-error-min')?.value, 10) || 30);
    try {
        const r = await setupFetch('/setup/config', {
            method: 'POST',
            body: JSON.stringify({ config: { spoke_alert: {
                enabled, warn_s: warnMin * 60, error_s: errorMin * 60
            } } })
        });
        if (r.ok) showToast('Spoke alert config saved.', 'success');
        else showToast('Failed to save.', 'error');
    } catch (e) {
        showToast('Error saving: ' + e.message, 'error');
    }
}

async function loadSpokeAlerts() {
    const wrap = document.getElementById('spoke-alerts-status');
    if (!wrap) return;
    let data;
    try {
        const r = await setupFetch('/setup/spoke-alerts');
        if (!r.ok) throw new Error(`${r.status}`);
        data = await r.json();
    } catch (e) {
        wrap.innerHTML = `<p class="text-xs text-red-500">Failed: ${e.message}</p>`;
        return;
    }
    const alerts = (data && data.active_alerts) || [];
    if (!alerts.length) {
        wrap.innerHTML = '<p class="text-xs text-slate-400 italic">No active alerts — every approved spoke is in contact.</p>';
        return;
    }
    const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    wrap.innerHTML = alerts.map(a => {
        const isErr = String(a.tier) === 'error';
        const pill = isErr ? 'bg-red-100 text-red-700' : 'bg-amber-100 text-amber-700';
        const mins = Math.max(0, Math.round((a.duration_s || 0) / 60));
        return `<div class="border border-slate-200 rounded-md p-3">
            <div class="flex items-center justify-between mb-1">
                <span class="text-sm font-mono text-slate-700">${esc(a.spoke_id)}</span>
                <span class="text-xs px-2 py-0.5 rounded-full ${pill}">${esc(a.tier)}</span>
            </div>
            <p class="text-xs text-slate-500">out of contact ${mins}m <span class="text-slate-400">· since ${fmtDate(a.since_ts)}</span></p>
            ${a.detail ? `<p class="text-xs text-slate-400 mt-1">${esc(a.detail)}</p>` : ''}
        </div>`;
    }).join('');
}

// ── Hypervisor → NetBox VM sync (System → Sync) ──────────────────────────
async function loadVmSyncSources() {
    // Populate the hypervisor source dropdown from the hub's HYPERVISOR_SOURCES
    // registry (data-driven) and mark each source's connected state. Also list
    // the connected pxmx agents (the real Proxmox servers) in the "Sync from
    // server" dropdown so the admin can scope the sync to one server.
    const sel = document.getElementById('vm-sync-source');
    const agSel = document.getElementById('vm-sync-agent');
    if (!sel) return;
    let savedAgent = '';
    if (agSel) savedAgent = agSel.value;
    try {
        const r = await setupFetch('/setup/vm-sync/sources');
        if (!r.ok) return;
        const data = await r.json();
        const cur = sel.value;
        sel.innerHTML = (data.sources || []).map(s =>
            `<option value="${s.name}">${s.label}${s.connected ? '' : ' (not connected)'}</option>`
        ).join('');
        if (cur) sel.value = cur;
        if (agSel) {
            const agents = data.agents || [];
            agSel.innerHTML = '<option value="">All connected servers</option>'
                + agents.map(a => {
                    const nodes = (a.nodes || []).join(', ');
                    const label = `${a.cluster || a.hostname || a.agent_id}${nodes ? ' [' + nodes + ']' : ''} · ${a.vm_count || 0} VMs`;
                    return `<option value="${escapeHtml(a.agent_id)}">${escapeHtml(label)}</option>`;
                }).join('');
            if (!agents.length) {
                agSel.innerHTML = '<option value="">No servers connected</option>';
            }
            if (savedAgent) agSel.value = savedAgent;
        }
    } catch (e) { console.error('loadVmSyncSources failed', e); }
}

async function loadVmSyncConfig() {
    try {
        const r = await setupFetch('/setup/config');
        if (!r.ok) return;
        const data = await r.json();
        const vmSync = (data.global_config || {}).pxmx_netbox_vm_sync || {};
        const chk = document.getElementById('vm-sync-enabled');
        const src = document.getElementById('vm-sync-source');
        const mode = document.getElementById('vm-sync-mode');
        const intv = document.getElementById('vm-sync-interval');
        const time = document.getElementById('vm-sync-time');
        const agSel = document.getElementById('vm-sync-agent');
        if (chk) chk.checked = vmSync.enabled === true;
        if (src && vmSync.source) src.value = vmSync.source;
        if (mode) mode.value = vmSync.mode === 'daily' ? 'daily' : 'interval';
        if (intv) intv.value = Math.max(1, Math.round((vmSync.interval_seconds || 3600) / 60));
        if (time) time.value = vmSync.daily_time || '03:00';
        // Restore the pinned server (agent_id) — sources may load after config;
        // re-apply once both have run.
        if (agSel && vmSync.agent_id) agSel.value = vmSync.agent_id;
    } catch (e) { console.error('loadVmSyncConfig failed', e); }
}

async function loadVmSyncStatus() {
    const wrap = document.getElementById('vm-sync-status');
    if (!wrap) return;
    let data;
    try {
        const r = await setupFetch('/setup/vm-sync/status');
        if (!r.ok) throw new Error(`${r.status}`);
        data = await r.json();
    } catch (e) {
        wrap.innerHTML = `<p class="text-xs text-red-500">Failed: ${e.message}</p>`;
        return;
    }
    const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    const rows = data.tenants || [];
    if (!rows.length) {
        wrap.innerHTML = '<p class="text-xs text-slate-400 italic">No syncs recorded yet. Click “Sync now” to run one.</p>';
        return;
    }
    wrap.innerHTML = rows.map(t => {
        const st = String(t.status || '');
        const pill = st === 'success' ? 'bg-green-100 text-green-700'
            : st === 'error' ? 'bg-red-100 text-red-700'
            : st === 'skipped' ? 'bg-slate-100 text-slate-500' : 'bg-slate-100 text-slate-400';
        const pushed = Number(t.pushed) || 0;
        const errors = Number(t.errors) || 0;
        const deleted = Number(t.deleted) || 0;
        const total = Number(t.vms_total) || 0;
        const skipped = Number(t.skipped) || 0;
        const skipLine = skipped > 0
            ? ` · <span class="text-amber-600">skipped ${skipped}</span>`
            : '';
        return `<div class="border border-slate-200 rounded-md p-3">
            <div class="flex items-center justify-between mb-1">
                <span class="text-sm font-bold text-slate-700">${esc(t.tenant_name || t.tenant_id)} <span class="text-xs font-mono text-slate-400">${esc(t.tenant_id)}</span></span>
                <span class="text-xs px-2 py-0.5 rounded-full ${pill}">${esc(st || '—')}</span>
            </div>
            <p class="text-xs text-slate-500">pushed ${pushed} · deleted ${deleted} · errors ${errors} · vms ${total}${skipLine} <span class="text-slate-400">· last ${fmtDate(t.last_sync_ts)}</span></p>
            ${t.message ? `<p class="text-xs text-slate-400 mt-1">${esc(t.message)}</p>` : ''}
        </div>`;
    }).join('');
}

async function runVmSyncNow() {
    const btn = document.getElementById('vm-sync-run-btn');
    const orig = btn ? btn.textContent : '';
    if (btn) { btn.disabled = true; btn.textContent = 'Syncing…'; }
    try {
        const r = await setupFetch('/setup/vm-sync/run', {
            method: 'POST',
            body: JSON.stringify({})
        });
        if (!r.ok) throw new Error(`${r.status}`);
        const data = await r.json();
        const s = data.summary || {};
        showToast(`Synced ${s.tenants || 0} tenant(s): ${s.pushed || 0} pushed, ${s.deleted || 0} deleted, ${s.errors || 0} errors.`, (s.errors || 0) ? 'info' : 'success');
        await loadVmSyncStatus();
    } catch (e) {
        showToast('Sync failed: ' + e.message, 'error');
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = orig; }
    }
}

async function saveVmSyncConfig() {
    const enabled = document.getElementById('vm-sync-enabled')?.checked ? true : false;
    const source = document.getElementById('vm-sync-source')?.value || 'proxmox';
    const mode = document.getElementById('vm-sync-mode')?.value || 'interval';
    const intervalMin = Math.max(1, parseInt(document.getElementById('vm-sync-interval')?.value, 10) || 60);
    const dailyTime = document.getElementById('vm-sync-time')?.value || '03:00';
    const agentId = document.getElementById('vm-sync-agent')?.value || '';
    try {
        const r = await setupFetch('/setup/config', {
            method: 'POST',
            body: JSON.stringify({ config: { pxmx_netbox_vm_sync: {
                enabled, source, mode, interval_seconds: intervalMin * 60, daily_time: dailyTime,
                agent_id: agentId
            } } })
        });
        if (r.ok) showToast('VM sync schedule saved.', 'success');
        else showToast('Failed to save schedule.', 'error');
    } catch (e) {
        showToast('Error saving schedule: ' + e.message, 'error');
    }
}

// ── Firewall → IPAM device-discovery sync (System → Sync third card) ──
// Backing routes: /setup/fw-discovery-sync/{sources,status,run} + shared
// /setup/config (saved under global_config.opnsense_netbox_device_sync).
async function loadFwDiscoverySources() {
    // Populate the firewall-source dropdown from FIREWALL_DISCOVERY_SOURCES and
    // the firewall picker from global_config["firewalls"] (each marked with its
    // connected state). NetBox-down is flagged separately by the status card.
    const sel = document.getElementById('fw-sync-source');
    const fwSel = document.getElementById('fw-sync-firewall');
    if (!sel) return;
    let savedFw = '';
    if (fwSel) savedFw = fwSel.value;
    try {
        const r = await setupFetch('/setup/fw-discovery-sync/sources');
        if (!r.ok) return;
        const data = await r.json();
        const cur = sel.value;
        sel.innerHTML = (data.sources || []).map(s =>
            `<option value="${s.name}">${s.label}${s.connected ? '' : ' (not connected)'}</option>`
        ).join('');
        if (cur) sel.value = cur;
        if (fwSel) {
            const fws = data.firewalls || [];
            fwSel.innerHTML = '<option value="">All connected firewalls</option>'
                + fws.map(f => `<option value="${escapeHtml(f.id)}">${escapeHtml(f.name)}${f.connected ? '' : ' (not connected)'}</option>`).join('');
            if (!fws.length) {
                fwSel.innerHTML = '<option value="">No firewalls configured</option>';
            }
            if (savedFw) fwSel.value = savedFw;
        }
    } catch (e) { console.error('loadFwDiscoverySources failed', e); }
}

async function loadFwDiscoveryConfig() {
    try {
        const r = await setupFetch('/setup/config');
        if (!r.ok) return;
        const data = await r.json();
        const cfg = (data.global_config || {}).opnsense_netbox_device_sync || {};
        const set = (id, v) => { const el = document.getElementById(id); if (el) el.value = v; };
        const chk = document.getElementById('fw-sync-enabled');
        if (chk) chk.checked = cfg.enabled === true;
        set('fw-sync-source', cfg.source || 'opnsense');
        set('fw-sync-data', cfg.source_data || 'both');
        set('fw-sync-firewall', cfg.firewall_id || '');
        set('fw-sync-mode', cfg.mode === 'daily' ? 'daily' : 'interval');
        set('fw-sync-interval', Math.max(1, Math.round((cfg.interval_seconds || 3600) / 60)));
        set('fw-sync-time', cfg.daily_time || '02:00');
        const d = cfg.defaults || {};
        set('fw-sync-role', d.role || '');
        set('fw-sync-type', d.device_type || '');
        set('fw-sync-site', d.site || '');
    } catch (e) { console.error('loadFwDiscoveryConfig failed', e); }
}

async function loadFwDiscoveryStatus() {
    const wrap = document.getElementById('fw-sync-status');
    if (!wrap) return;
    let data;
    try {
        const r = await setupFetch('/setup/fw-discovery-sync/status');
        if (!r.ok) throw new Error(`${r.status}`);
        data = await r.json();
    } catch (e) {
        wrap.innerHTML = `<p class="text-xs text-red-500">Failed: ${e.message}</p>`;
        return;
    }
    const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    const rows = data.tenants || [];
    if (!rows.length) {
        wrap.innerHTML = '<p class="text-xs text-slate-400 italic">No syncs recorded yet. Click “Sync now” to run one.</p>';
        return;
    }
    wrap.innerHTML = rows.map(t => {
        const st = String(t.status || '');
        const pill = st === 'success' ? 'bg-green-100 text-green-700'
            : st === 'error' ? 'bg-red-100 text-red-700'
            : st === 'skipped' ? 'bg-slate-100 text-slate-500' : 'bg-slate-100 text-slate-400';
        const pushed = Number(t.pushed) || 0;
        const errors = Number(t.errors) || 0;
        const deleted = Number(t.deleted) || 0;
        const skipped = Number(t.skipped) || 0;
        const total = Number(t.discovered_total) || 0;
        const skipLine = skipped > 0 ? ` · <span class="text-amber-600">skipped ${skipped}</span>` : '';
        return `<div class="border border-slate-200 rounded-md p-3">
            <div class="flex items-center justify-between mb-1">
                <span class="text-sm font-bold text-slate-700">${esc(t.tenant_name || t.tenant_id)} <span class="text-xs font-mono text-slate-400">${esc(t.tenant_id)}</span></span>
                <span class="text-xs px-2 py-0.5 rounded-full ${pill}">${esc(st || '—')}</span>
            </div>
            <p class="text-xs text-slate-500">pushed ${pushed} · deleted ${deleted} · errors ${errors} · discovered ${total}${skipLine} <span class="text-slate-400">· last ${fmtDate(t.last_sync_ts)}</span></p>
            ${t.message ? `<p class="text-xs text-slate-400 mt-1">${esc(t.message)}</p>` : ''}
        </div>`;
    }).join('');
}

async function runFwDiscoveryNow() {
    const btn = document.getElementById('fw-sync-run-btn');
    const orig = btn ? btn.textContent : '';
    if (btn) { btn.disabled = true; btn.textContent = 'Syncing…'; }
    try {
        const r = await setupFetch('/setup/fw-discovery-sync/run', {
            method: 'POST',
            body: JSON.stringify({})
        });
        if (!r.ok) throw new Error(`${r.status}`);
        const data = await r.json();
        const s = data.summary || {};
        showToast(`Synced ${s.tenants || 0} tenant(s): ${s.pushed || 0} pushed, ${s.deleted || 0} deleted, ${s.dropped_unattributed || 0} dropped, ${s.errors || 0} errors.`, (s.errors || 0) ? 'info' : 'success');
        await loadFwDiscoveryStatus();
    } catch (e) {
        showToast('Sync failed: ' + e.message, 'error');
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = orig; }
    }
}

async function saveFwDiscoveryConfig() {
    const enabled = document.getElementById('fw-sync-enabled')?.checked ? true : false;
    const source = document.getElementById('fw-sync-source')?.value || 'opnsense';
    const sourceData = document.getElementById('fw-sync-data')?.value || 'both';
    const firewallId = document.getElementById('fw-sync-firewall')?.value || '';
    const mode = document.getElementById('fw-sync-mode')?.value || 'interval';
    const intervalMin = Math.max(1, parseInt(document.getElementById('fw-sync-interval')?.value, 10) || 60);
    const dailyTime = document.getElementById('fw-sync-time')?.value || '02:00';
    const defaults = {
        role: (document.getElementById('fw-sync-role')?.value || '').trim(),
        device_type: (document.getElementById('fw-sync-type')?.value || '').trim(),
        site: (document.getElementById('fw-sync-site')?.value || '').trim(),
    };
    try {
        const r = await setupFetch('/setup/config', {
            method: 'POST',
            body: JSON.stringify({ config: { opnsense_netbox_device_sync: {
                enabled, source, source_data: sourceData, firewall_id: firewallId,
                mode, interval_seconds: intervalMin * 60, daily_time: dailyTime,
                defaults
            } } })
        });
        if (r.ok) showToast('Firewall discovery sync schedule saved.', 'success');
        else showToast('Failed to save schedule.', 'error');
    } catch (e) {
        showToast('Error saving schedule: ' + e.message, 'error');
    }
}

// Network Devices → IPAM discovery sync (System → Sync, 4th card).
// Backing routes: /setup/nw-discovery-sync/{sources,status,run} + shared
// /setup/config (saved under global_config.nw_netbox_device_sync). Mirrors the
// firewall-discovery card; the nw source pulls ARP from switches + gateways.
async function loadNwDiscoverySources() {
    const sel = document.getElementById('nw-sync-source');
    if (!sel) return;
    try {
        const r = await setupFetch('/setup/nw-discovery-sync/sources');
        if (!r.ok) return;
        const data = await r.json();
        const cur = sel.value;
        sel.innerHTML = (data.sources || []).map(s =>
            `<option value="${s.name}">${s.label}${s.connected ? '' : ' (not connected)'}</option>`
        ).join('');
        if (cur) sel.value = cur;
    } catch (e) { console.error('loadNwDiscoverySources failed', e); }
}

async function loadNwDiscoveryConfig() {
    try {
        const r = await setupFetch('/setup/config');
        if (!r.ok) return;
        const data = await r.json();
        const cfg = (data.global_config || {}).nw_netbox_device_sync || {};
        const set = (id, v) => { const el = document.getElementById(id); if (el) el.value = v; };
        const chk = document.getElementById('nw-sync-enabled');
        if (chk) chk.checked = cfg.enabled === true;
        set('nw-sync-source', cfg.source || 'nw');
        set('nw-sync-mode', cfg.mode === 'daily' ? 'daily' : 'interval');
        set('nw-sync-interval', Math.max(1, Math.round((cfg.interval_seconds || 3600) / 60)));
        set('nw-sync-time', cfg.daily_time || '02:30');
        const d = cfg.defaults || {};
        set('nw-sync-role', d.role || '');
        set('nw-sync-type', d.device_type || '');
        set('nw-sync-site', d.site || '');
    } catch (e) { console.error('loadNwDiscoveryConfig failed', e); }
}

async function loadNwDiscoveryStatus() {
    const wrap = document.getElementById('nw-sync-status');
    if (!wrap) return;
    let data;
    try {
        const r = await setupFetch('/setup/nw-discovery-sync/status');
        if (!r.ok) throw new Error(`${r.status}`);
        data = await r.json();
    } catch (e) {
        wrap.innerHTML = `<p class="text-xs text-red-500">Failed: ${e.message}</p>`;
        return;
    }
    const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    const rows = data.tenants || [];
    if (!rows.length) {
        wrap.innerHTML = '<p class="text-xs text-slate-400 italic">No syncs recorded yet. Click “Sync now” to run one.</p>';
        return;
    }
    wrap.innerHTML = rows.map(t => {
        const st = String(t.status || '');
        const pill = st === 'success' ? 'bg-green-100 text-green-700'
            : st === 'error' ? 'bg-red-100 text-red-700'
            : st === 'skipped' ? 'bg-slate-100 text-slate-500' : 'bg-slate-100 text-slate-400';
        const pushed = Number(t.pushed) || 0;
        const errors = Number(t.errors) || 0;
        const deleted = Number(t.deleted) || 0;
        const skipped = Number(t.skipped) || 0;
        const total = Number(t.discovered_total) || 0;
        const skipLine = skipped > 0 ? ` · <span class="text-amber-600">skipped ${skipped}</span>` : '';
        return `<div class="border border-slate-200 rounded-md p-3">
            <div class="flex items-center justify-between mb-1">
                <span class="text-sm font-bold text-slate-700">${esc(t.tenant_name || t.tenant_id)} <span class="text-xs font-mono text-slate-400">${esc(t.tenant_id)}</span></span>
                <span class="text-xs px-2 py-0.5 rounded-full ${pill}">${esc(st || '—')}</span>
            </div>
            <p class="text-xs text-slate-500">pushed ${pushed} · deleted ${deleted} · errors ${errors} · discovered ${total}${skipLine} <span class="text-slate-400">· last ${fmtDate(t.last_sync_ts)}</span></p>
            ${t.message ? `<p class="text-xs text-slate-400 mt-1">${esc(t.message)}</p>` : ''}
        </div>`;
    }).join('');
}

async function runNwDiscoveryNow() {
    const btn = document.getElementById('nw-sync-run-btn');
    const orig = btn ? btn.textContent : '';
    if (btn) { btn.disabled = true; btn.textContent = 'Syncing…'; }
    try {
        const r = await setupFetch('/setup/nw-discovery-sync/run', {
            method: 'POST',
            body: JSON.stringify({})
        });
        if (!r.ok) throw new Error(`${r.status}`);
        const data = await r.json();
        const s = data.summary || {};
        showToast(`Synced ${s.tenants || 0} tenant(s): ${s.pushed || 0} pushed, ${s.deleted || 0} deleted, ${s.dropped_unattributed || 0} dropped, ${s.errors || 0} errors.`, (s.errors || 0) ? 'info' : 'success');
        await loadNwDiscoveryStatus();
    } catch (e) {
        showToast('Sync failed: ' + e.message, 'error');
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = orig; }
    }
}

async function pollNwDevice(deviceId, name, btn) {
    // POLL NOW: full probe+info+interfaces+arp+mac poll on the spoke, then upsert
    // the device + interfaces into NetBox. Admin-only route. Refreshes the active
    // nw sub-view afterward so live data appears.
    const orig = btn ? btn.textContent : '';
    if (btn) { btn.disabled = true; btn.textContent = 'Polling…'; }
    try {
        const r = await setupFetch(`/api/nw/${encodeURIComponent(deviceId)}/poll`, {
            method: 'POST',
            body: JSON.stringify({})
        });
        if (!r.ok) throw new Error(`${r.status}`);
        const d = await r.json();
        const up = d.reachable ? 'up' : 'down';
        const nif = Array.isArray(d.interfaces) ? d.interfaces.length : 0;
        const narp = Array.isArray(d.arp) ? d.arp.length : 0;
        const nmac = Array.isArray(d.mac_table) ? d.mac_table.length : 0;
        const push = d.netbox_push || {};
        const pushTxt = push && push.status
            ? ` · NetBox: ${push.status === 'ERROR' ? 'errors=' + (push.errors || 0) : 'pushed=' + (push.pushed || 0) + ', ifaces=' + (push.interfaces_total || 0)}`
            : '';
        const errs = Array.isArray(d.errors) ? d.errors.length : 0;
        showToast(`Poll ${name}: reachable ${up} · ${nif} iface(s) · ${narp} arp · ${nmac} mac${pushTxt}${errs ? ` · ${errs} error(s)` : ''}`,
            d.reachable ? 'success' : 'error');
        // Refresh whatever nw sub-view is active (Devices shows new reachability;
        // ARP/Interfaces/MAC reload the live rows).
        await loadNwData(currentSubView);
    } catch (e) {
        showToast('Poll failed: ' + e.message, 'error');
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = orig; }
    }
}

async function saveNwDiscoveryConfig() {
    const enabled = document.getElementById('nw-sync-enabled')?.checked ? true : false;
    const source = document.getElementById('nw-sync-source')?.value || 'nw';
    const mode = document.getElementById('nw-sync-mode')?.value || 'interval';
    const intervalMin = Math.max(1, parseInt(document.getElementById('nw-sync-interval')?.value, 10) || 60);
    const dailyTime = document.getElementById('nw-sync-time')?.value || '02:30';
    const defaults = {
        role: (document.getElementById('nw-sync-role')?.value || '').trim(),
        device_type: (document.getElementById('nw-sync-type')?.value || '').trim(),
        site: (document.getElementById('nw-sync-site')?.value || '').trim(),
    };
    try {
        const r = await setupFetch('/setup/config', {
            method: 'POST',
            body: JSON.stringify({ config: { nw_netbox_device_sync: {
                enabled, source, mode, interval_seconds: intervalMin * 60,
                daily_time: dailyTime, defaults
            } } })
        });
        if (r.ok) showToast('Network Devices discovery sync schedule saved.', 'success');
        else showToast('Failed to save schedule.', 'error');
    } catch (e) {
        showToast('Error saving schedule: ' + e.message, 'error');
    }
}

async function loadSubnetFilterToggles() {
    const wrap = document.getElementById('subnet-filter-toggles');
    if (!wrap) return;
    try {
        const r = await fetch('/admin/subnet-filter-config', { credentials: 'same-origin' });
        if (!r.ok) throw new Error(`${r.status}`);
        const d = await r.json();
        _subnetFilterState = d.modules || {};
        wrap.innerHTML = _SUBNET_FILTER_MODULES.map(m => {
            const on = !!_subnetFilterState[m.key];
            return `<div class="flex items-center justify-between py-1.5 border-b border-slate-100 last:border-0">
                <span class="text-sm text-slate-700">${m.label}</span>
                <button onclick="toggleSubnetFilter('${m.key}')" class="relative inline-flex h-5 w-10 items-center rounded-full transition-colors ${on ? 'bg-[#01A982]' : 'bg-slate-300'}">
                    <span class="inline-block h-4 w-4 transform rounded-full bg-white shadow transition-transform ${on ? 'translate-x-5' : 'translate-x-1'}"></span>
                </button>
            </div>`;
        }).join('');
    } catch (e) {
        wrap.innerHTML = `<p class="text-xs text-red-500">Failed to load: ${e.message}</p>`;
    }
}

async function toggleSubnetFilter(module) {
    const next = !(_subnetFilterState[module] || false);
    _subnetFilterState[module] = next;
    try {
        const r = await fetch('/admin/subnet-filter-config', {
            method: 'PUT', credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ modules: _subnetFilterState }),
        });
        if (!r.ok) throw new Error(`${r.status}`);
        if (typeof showToast === 'function') showToast(`${module} subnet filter ${next ? 'enabled' : 'disabled'}`, 'success');
    } catch (e) {
        if (typeof showToast === 'function') showToast('Failed to update: ' + e.message, 'error');
        _subnetFilterState[module] = !next;
    }
    loadSubnetFilterToggles();
}

function _usbChip(vp, label, onRemove, extra) {
    return `<span class="inline-flex items-center gap-1 bg-slate-100 rounded-full pl-2 pr-1 py-0.5 text-xs font-mono text-slate-700">${label || vp}${extra || ''}<button onclick="${onRemove}" class="text-slate-400 hover:text-red-500 font-bold">&times;</button></span>`;
}

async function loadUsbOverview() {
    let data;
    try {
        const r = await fetch('/sim/api/superadmin/tenants/usb', { credentials: 'same-origin' });
        if (!r.ok) throw new Error(`${r.status}`);
        data = await r.json();
    } catch (e) {
        document.getElementById('global-usb-certified').innerHTML = `<span class="text-xs text-red-500">Failed: ${e.message}</span>`;
        return;
    }
    const g = data.global || {};
    const certWrap = document.getElementById('global-usb-certified');
    const ignWrap = document.getElementById('global-usb-ignored');
    // Rendered as full-width bordered rows to match the Discovered-devices list
    // below, each with an Un-approve / Un-ignore action.
    certWrap.innerHTML = (g.certified || []).length
        ? (g.certified || []).map(d => `<div class="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 border border-slate-200 rounded-md">
            <span class="font-mono text-xs text-slate-700 w-28">${escapeHtml(d.vidpid)}</span>
            <span class="text-xs text-slate-600 flex-1 min-w-[8rem]">${escapeHtml(d.label || '—')}</span>
            <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-green-100 text-green-700">Certified globally</span>
            <button onclick="removeGlobalUsbCert('${d.vidpid}')" class="bg-slate-200 text-slate-600 hover:bg-red-100 hover:text-red-600 px-2 py-1 rounded text-xs font-bold">Un-approve</button>
          </div>`).join('')
        : '<p class="text-xs text-slate-400 italic">None certified.</p>';
    ignWrap.innerHTML = (g.ignored || []).length
        ? (g.ignored || []).map(vp => `<div class="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 border border-slate-200 rounded-md">
            <span class="font-mono text-xs text-slate-700 w-28">${escapeHtml(vp)}</span>
            <span class="text-xs text-slate-600 flex-1 min-w-[8rem]">—</span>
            <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-slate-200 text-slate-600">Ignored globally</span>
            <button onclick="removeGlobalUsbIgnore('${vp}')" class="bg-slate-200 text-slate-600 hover:bg-red-100 hover:text-red-600 px-2 py-1 rounded text-xs font-bold">Un-ignore</button>
          </div>`).join('')
        : '<p class="text-xs text-slate-400 italic">None ignored.</p>';

    const list = document.getElementById('tenant-usb-list');
    const tenants = data.tenants || [];
    if (!tenants.length) { list.innerHTML = '<p class="text-xs text-slate-400 italic">No tenants configured.</p>'; return; }
    list.innerHTML = tenants.map(t => {
        const cert = (t.certified || []).map(d => _usbChip(d.vidpid, `${d.vidpid} <span class="text-slate-400">${d.type || ''}</span>`, `tenantUsbRemove('${t.id}','${d.vidpid}')`)).join('') || '<span class="text-xs text-slate-400 italic">none</span>';
        const ign = (t.ignored || []).map(vp => _usbChip(vp, vp, `tenantUsbRemove('${t.id}','${vp}')`)).join('') || '<span class="text-xs text-slate-400 italic">none</span>';
        return `<div class="border border-slate-200 rounded-md p-3">
            <div class="flex items-center justify-between mb-2">
                <span class="text-sm font-bold text-slate-700">${t.name} <span class="text-xs font-mono text-slate-400">${t.id}</span></span>
            </div>
            <div class="grid grid-cols-2 gap-3 text-xs">
                <div><p class="text-[10px] uppercase font-bold text-slate-400 mb-1">Certified (local)</p><div class="flex flex-wrap gap-1 min-h-[1.5rem]">${cert}</div></div>
                <div><p class="text-[10px] uppercase font-bold text-slate-400 mb-1">Ignored (local)</p><div class="flex flex-wrap gap-1 min-h-[1.5rem]">${ign}</div></div>
            </div>
            <div class="flex gap-1 mt-2">
                <input id="tusbc-${t.id}" placeholder="1a2b:3c4d" class="w-28 font-mono text-xs ${'w-full bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500 text-slate-800'}" onkeydown="if(event.key==='Enter')tenantUsbAdd('${t.id}','certify')">
                <select id="tusbt-${t.id}" title="Dongle type" class="text-xs ${'w-full bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500 text-slate-800'}"><option>wireless</option><option>wired</option><option>storage</option><option>other</option></select>
                <button onclick="tenantUsbAdd('${t.id}','certify')" class="bg-green-100 text-green-700 px-2 py-1 rounded text-xs font-bold">Certify</button>
                <button onclick="tenantUsbAdd('${t.id}','ignore')" class="bg-slate-200 text-slate-600 px-2 py-1 rounded text-xs font-bold">Ignore</button>
            </div>
        </div>`;
    }).join('');
}

// vidpid → display name for the discovered list, so the Approve action can label
// the new certified entry without embedding free-text in an onclick attribute.
let _discoveredUsbByName = {};

async function loadDiscoveredUsb() {
    const wrap = document.getElementById('global-usb-discovered');
    if (!wrap) return;
    let data;
    try {
        const r = await fetch('/sim/api/superadmin/discovered-usb-vidpids', { credentials: 'same-origin' });
        if (!r.ok) throw new Error(`${r.status}`);
        data = await r.json();
    } catch (e) {
        wrap.innerHTML = `<p class="text-xs text-red-500">Failed: ${e.message}</p>`;
        return;
    }
    const devs = data.devices || [];
    if (!devs.length) {
        wrap.innerHTML = '<p class="text-xs text-slate-400 italic">No USB devices discovered yet.</p>';
        return;
    }
    const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    _discoveredUsbByName = {};
    wrap.innerHTML = devs.map(d => {
        const vp = d.vidpid;
        _discoveredUsbByName[vp] = d.name || vp;
        const seen = (d.seen_on || []).map(s => `${esc(s.tenant_name)} / ${esc(s.spoke_name)}`).join(', ') || '—';
        let badge;
        if (d.is_global) badge = '<span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-green-100 text-green-700">Certified globally</span>';
        else if (d.is_global_ignored) badge = '<span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-slate-200 text-slate-600">Ignored globally</span>';
        else if (d.locally_ignored) badge = '<span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-amber-100 text-amber-700">Locally ignored</span>';
        else badge = '<span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-slate-100 text-slate-500">Unapproved</span>';
        // Dongle-type picker paired with the approve button — the chosen type
        // becomes the device's certified `type` (wireless/wired/…), which the
        // pxmx agent uses as each provisioned VM's sim_phy. Defaults to
        // wireless (the agent's own default); hidden once already global.
        const approveBtn = d.is_global
            ? `<button onclick="removeGlobalUsbCert('${vp}')" class="bg-slate-200 text-slate-600 hover:bg-red-100 hover:text-red-600 px-2 py-1 rounded text-xs font-bold">Un-approve globally</button>`
            : `<select id="gusbt-${esc(vp)}" title="Dongle type" class="text-xs bg-white border border-slate-300 rounded-md px-2 py-1 outline-none focus:ring-2 focus:ring-green-500 text-slate-800"><option>wireless</option><option>wired</option><option>storage</option><option>other</option></select>
               <button onclick="approveGlobalUsb('${vp}')" class="bg-green-100 text-green-700 px-2 py-1 rounded text-xs font-bold">Approve globally</button>`;
        const ignoreBtn = d.is_global_ignored
            ? `<button onclick="removeGlobalUsbIgnore('${vp}')" class="bg-slate-200 text-slate-600 hover:bg-red-100 hover:text-red-600 px-2 py-1 rounded text-xs font-bold">Un-ignore globally</button>`
            : `<button onclick="ignoreGlobalUsb('${vp}')" class="bg-slate-200 text-slate-600 px-2 py-1 rounded text-xs font-bold">Ignore globally</button>`;
        // Per-tenant LOCAL un-approve — one button per tenant that certified this
        // device locally (drops it from that tenant's usb_vidpids).
        const localBtns = (d.locally_certified || []).map(c =>
            `<button onclick="tenantUsbRemove('${esc(c.tenant_id)}','${vp}')" title="Un-approve locally for ${esc(c.tenant_name)}" class="bg-amber-50 text-amber-700 border border-amber-200 hover:bg-amber-100 px-2 py-1 rounded text-[11px] font-bold">Un-approve @${esc(c.tenant_name)}</button>`
        ).join('');
        return `<div class="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 border border-slate-200 rounded-md">
            <span class="font-mono text-xs text-slate-700 w-28">${esc(vp)}</span>
            <span class="text-xs text-slate-600 flex-1 min-w-[8rem]">${esc(d.name || '—')}</span>
            <span class="text-[11px] text-slate-400 flex-1 min-w-[10rem]">${seen}</span>
            ${badge}
            <span class="flex flex-wrap gap-1">${approveBtn}${ignoreBtn}${localBtns}</span>
        </div>`;
    }).join('');
}

async function addGlobalUsbCert() {
    const vp = (document.getElementById('gusbc-vp').value || '').trim().toLowerCase();
    const label = (document.getElementById('gusbc-label').value || '').trim();
    const type = document.getElementById('gusbc-type').value;
    if (!_vpValid(vp)) { if (typeof showToast === 'function') showToast('VID:PID must be 4-hex:4-hex (e.g. 1a2b:3c4d)', 'error'); return; }
    try {
        const r = await fetch('/sim/api/superadmin/global-usb-vidpids', { credentials: 'same-origin' });
        const cur = r.ok ? (await r.json()).usb_vidpids || [] : [];
        const next = [...cur.filter(d => d.vidpid !== vp), { vidpid: vp, type, label: label || vp }];
        const pr = await fetch('/sim/api/superadmin/global-usb-vidpids', {
            method: 'PUT', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ usb_vidpids: next }),
        });
        if (!pr.ok) throw new Error(`${pr.status}`);
        document.getElementById('gusbc-vp').value = ''; document.getElementById('gusbc-label').value = '';
        loadUsbOverview();
    } catch (e) { if (typeof showToast === 'function') showToast('Failed: ' + e.message, 'error'); }
}

async function removeGlobalUsbCert(vp) {
    try {
        const r = await fetch('/sim/api/superadmin/global-usb-vidpids', { credentials: 'same-origin' });
        const cur = r.ok ? (await r.json()).usb_vidpids || [] : [];
        const next = cur.filter(d => d.vidpid !== vp);
        await fetch('/sim/api/superadmin/global-usb-vidpids', {
            method: 'PUT', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ usb_vidpids: next }),
        });
        loadUsbOverview();
    } catch (e) { if (typeof showToast === 'function') showToast('Failed: ' + e.message, 'error'); }
}

async function addGlobalUsbIgnore() {
    const vp = (document.getElementById('gusbi-vp').value || '').trim().toLowerCase();
    if (!_vpValid(vp)) { if (typeof showToast === 'function') showToast('VID:PID must be 4-hex:4-hex (e.g. 1a2b:3c4d)', 'error'); return; }
    try {
        const r = await fetch('/sim/api/superadmin/global-usb-ignored-vidpids', { credentials: 'same-origin' });
        const cur = r.ok ? (await r.json()).usb_vidpids || [] : [];
        if (!cur.includes(vp)) cur.push(vp);
        await fetch('/sim/api/superadmin/global-usb-ignored-vidpids', {
            method: 'PUT', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ usb_vidpids: cur }),
        });
        document.getElementById('gusbi-vp').value = '';
        loadUsbOverview();
    } catch (e) { if (typeof showToast === 'function') showToast('Failed: ' + e.message, 'error'); }
}

async function removeGlobalUsbIgnore(vp) {
    try {
        const r = await fetch('/sim/api/superadmin/global-usb-ignored-vidpids', { credentials: 'same-origin' });
        const cur = r.ok ? (await r.json()).usb_vidpids || [] : [];
        const next = cur.filter(x => x !== vp);
        await fetch('/sim/api/superadmin/global-usb-ignored-vidpids', {
            method: 'PUT', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ usb_vidpids: next }),
        });
        loadUsbOverview();
    } catch (e) { if (typeof showToast === 'function') showToast('Failed: ' + e.message, 'error'); }
}

// Approve a discovered VID:PID globally: add to the global certified list and
// remove it from the global ignored list (mutually exclusive, matching the
// per-tenant cs_usb_vidpids semantics), then push to every tenant's spoke.
async function approveGlobalUsb(vp) {
    if (!_vpValid(vp)) { if (typeof showToast === 'function') showToast('Bad VID:PID', 'error'); return; }
    const label = _discoveredUsbByName[vp] || vp;
    // Read the per-row dongle-type picker (wireless/wired/…); default wireless
    // to match the pxmx agent's own default when a type is unset.
    const type = document.getElementById(`gusbt-${vp}`)?.value || 'wireless';
    try {
        const rc = await fetch('/sim/api/superadmin/global-usb-vidpids', { credentials: 'same-origin' });
        const cert = rc.ok ? (await rc.json()).usb_vidpids || [] : [];
        const next = [...cert.filter(d => d.vidpid !== vp), { vidpid: vp, type, label: label || vp }];
        const pc = await fetch('/sim/api/superadmin/global-usb-vidpids', {
            method: 'PUT', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ usb_vidpids: next }),
        });
        if (!pc.ok) throw new Error(`${pc.status}`);
        const ri = await fetch('/sim/api/superadmin/global-usb-ignored-vidpids', { credentials: 'same-origin' });
        const ign = ri.ok ? (await ri.json()).usb_vidpids || [] : [];
        const ignNext = ign.filter(x => x !== vp);
        if (ignNext.length !== ign.length) {
            await fetch('/sim/api/superadmin/global-usb-ignored-vidpids', {
                method: 'PUT', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ usb_vidpids: ignNext }),
            });
        }
        if (typeof showToast === 'function') showToast(`Approved ${vp} globally`, 'success');
        loadUsbOverview();
        loadDiscoveredUsb();
    } catch (e) { if (typeof showToast === 'function') showToast('Failed: ' + e.message, 'error'); }
}

// Ignore a discovered VID:PID globally: add to the global ignored list and
// remove it from the global certified list, then push to every tenant's spoke.
async function ignoreGlobalUsb(vp) {
    if (!_vpValid(vp)) { if (typeof showToast === 'function') showToast('Bad VID:PID', 'error'); return; }
    try {
        const ri = await fetch('/sim/api/superadmin/global-usb-ignored-vidpids', { credentials: 'same-origin' });
        const ign = ri.ok ? (await ri.json()).usb_vidpids || [] : [];
        const ignNext = ign.includes(vp) ? ign : [...ign, vp];
        const pi = await fetch('/sim/api/superadmin/global-usb-ignored-vidpids', {
            method: 'PUT', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ usb_vidpids: ignNext }),
        });
        if (!pi.ok) throw new Error(`${pi.status}`);
        const rc = await fetch('/sim/api/superadmin/global-usb-vidpids', { credentials: 'same-origin' });
        const cert = rc.ok ? (await rc.json()).usb_vidpids || [] : [];
        const certNext = cert.filter(d => d.vidpid !== vp);
        if (certNext.length !== cert.length) {
            await fetch('/sim/api/superadmin/global-usb-vidpids', {
                method: 'PUT', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ usb_vidpids: certNext }),
            });
        }
        if (typeof showToast === 'function') showToast(`Ignored ${vp} globally`, 'success');
        loadUsbOverview();
        loadDiscoveredUsb();
    } catch (e) { if (typeof showToast === 'function') showToast('Failed: ' + e.message, 'error'); }
}

async function tenantUsbAdd(tid, action) {
    const inp = document.getElementById(`tusbc-${tid}`);
    const full = (inp?.value || '').trim().toLowerCase();
    if (!_vpValid(full)) { if (typeof showToast === 'function') showToast('VID:PID must be 4-hex:4-hex', 'error'); return; }
    const [vid, pid] = full.split(':');
    const type = document.getElementById(`tusbt-${tid}`)?.value || 'wireless';
    await _tenantUsbPost(tid, vid, pid, action, inp, type);
}

async function tenantUsbRemove(tid, vp) {
    const [vid, pid] = vp.split(':');
    await _tenantUsbPost(tid, vid, pid, 'remove', null);
}

async function _tenantUsbPost(tid, vid, pid, action, inp, type) {
    try {
        const body = { vid, pid, action };
        if (action === 'certify' && type) body.type = type;
        const r = await fetch(`/sim/api/${tid}/usb-vidpids?tenant_id=${tid}`, {
            method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        if (!r.ok) throw new Error(`${r.status}`);
        if (inp) inp.value = '';
        if (typeof showToast === 'function') showToast(`${action} queued for ${vid}:${pid}`, 'success');
        loadUsbOverview();
        loadDiscoveredUsb();  // keep the discovered list's local-cert badges/buttons in sync
    } catch (e) { if (typeof showToast === 'function') showToast('Failed: ' + e.message, 'error'); }
}

async function loadCacheConfig() {
    const container = document.getElementById('cache-config-rows');
    if (!container) return;
    try {
        const r = await fetch('/admin/cache/config', { credentials: 'same-origin' });
        if (!r.ok) { container.innerHTML = '<p class="col-span-2 py-3 text-center text-xs text-red-400">Not available</p>'; return; }
        const d = await r.json();
        const cfg = d.config || {};
        const labels = d.labels || {};
        const inputCls = 'w-20 bg-white border border-slate-300 rounded-md px-2 py-1 text-sm outline-none focus:ring-2 focus:ring-green-500 text-center';
        container.innerHTML = Object.entries(cfg).map(([key, val]) => `
            <div class="flex items-center gap-3 py-2 border-b border-slate-100">
                <span class="flex-1 text-slate-700">${labels[key] || key}</span>
                <input type="checkbox" data-cache-key="${key}" data-cache-field="enabled" class="w-4 h-4 text-green-600 rounded" ${val.enabled !== false ? 'checked' : ''}>
                <input type="number" data-cache-key="${key}" data-cache-field="interval" min="30" max="3600"
                    value="${Math.round((val.interval || 300) / 60)}" class="${inputCls}">
                <span class="text-xs text-slate-400">min</span>
            </div>`).join('');
        const maxEl = document.getElementById('cache-max-concurrent');
        if (maxEl) maxEl.value = d.max_concurrent_tenants || 3;
    } catch (e) {
        if (container) container.innerHTML = `<p class="col-span-2 py-3 text-center text-xs text-red-400">${e.message}</p>`;
    }
}

async function saveCacheConfig() {
    const configPayload = {};
    document.querySelectorAll('[data-cache-key]').forEach(el => {
        const key = el.dataset.cacheKey;
        const field = el.dataset.cacheField;
        if (!configPayload[key]) configPayload[key] = {};
        if (field === 'enabled') configPayload[key].enabled = el.checked;
        if (field === 'interval') configPayload[key].interval = parseInt(el.value, 10) * 60;
    });
    const maxConcurrent = parseInt(document.getElementById('cache-max-concurrent')?.value || '3', 10);
    try {
        const r = await fetch('/admin/cache/config', {
            method: 'PUT', credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ config: configPayload, max_concurrent_tenants: maxConcurrent }),
        });
        if (!r.ok) throw new Error(await r.text());
        showToast('Cache configuration saved', 'success');
    } catch (e) {
        showToast('Save failed: ' + e.message, 'error');
    }
}

async function purgeAllCaches() {
    if (!await showConfirmToast('Purge all tenant caches and re-warm from live data?')) return;
    try {
        const r = await fetch('/admin/cache/purge', { method: 'POST', credentials: 'same-origin' });
        if (!r.ok) throw new Error(await r.text());
        showToast('Cache purged — re-warming in background', 'success');
    } catch (e) {
        showToast('Purge failed: ' + e.message, 'error');
    }
}

async function loadFirewallsList() {
    const listEl = document.getElementById('firewalls-list');
    if (!listEl) return;
    try {
        const firewalls = await loadFirewalls();
        if (firewalls.length === 0) {
            listEl.innerHTML = '<p class="text-xs text-slate-400 italic">No firewalls configured.</p>';
            return;
        }
        listEl.innerHTML = firewalls.map(fw => `
            <div class="flex items-center justify-between p-3 rounded-md bg-slate-50 border border-slate-200">
                <div><span class="text-sm font-medium text-slate-700">${fw.name || fw.id}</span><span class="ml-2 text-xs text-slate-400">${fw.model} · ${fw.host || ''}:${fw.port || ''}</span></div>
                <div class="flex gap-2">
                    <button onclick="editFirewall('${fw.id}')" class="text-xs text-blue-500 hover:text-blue-700 font-medium">Edit</button>
                    <button onclick="deleteFirewallEntry('${fw.id}')" class="text-xs text-red-400 hover:text-red-600 font-medium">Delete</button>
                </div>
            </div>`).join('');
    } catch (e) {
        listEl.innerHTML = `<p class="text-xs text-red-500">Error loading firewalls: ${e.message}</p>`;
    }
}

async function deleteFirewallEntry(id) {
    if (!await showConfirmToast(`Delete firewall ${id}?`)) return;
    try {
        const r = await setupFetch(`/setup/firewalls/${id}`, { method: 'DELETE' });
        if (!r.ok) throw new Error(await r.text());
        loadFirewallsList();
        loadFirewalls();
    } catch (e) {
        alert('Error: ' + e.message);
    }
}

// Network Devices fleet list (Setup → Network Devices). Mirrors loadFirewallsList
// but reads /setup/nw-devices. Cache so the add/edit modal's editNwDevice can
// resolve a device without a second fetch.
let _nwDevicesCache = [];
async function loadNwDevices() {
    try {
        const r = await setupFetch('/setup/nw-devices');
        if (!r.ok) throw new Error(`${r.status}`);
        const data = await r.json();
        _nwDevicesCache = Array.isArray(data.nw_devices) ? data.nw_devices : [];
        return _nwDevicesCache;
    } catch (e) {
        _nwDevicesCache = [];
        return [];
    }
}

const _NW_OBJECT_TYPES = {
    aos_switch: 'AOS Switch',
    cx_switch:  'CX Switch',
    ex_switch:  'EX Switch',
    gateway:    'Gateway',
};
const _NW_TRANSPORTS = { ssh: 'SSH/CLI', rest: 'REST API', snmp: 'SNMP', auto: 'Auto' };

async function loadNwDevicesList() {
    const listEl = document.getElementById('nw-devices-list');
    if (!listEl) return;
    try {
        const devices = await loadNwDevices();
        if (devices.length === 0) {
            listEl.innerHTML = '<p class="text-xs text-slate-400 italic">No network devices configured.</p>';
            return;
        }
        listEl.innerHTML = devices.map(d => {
            const typeLabel = _NW_OBJECT_TYPES[d.object_type] || d.object_type || '—';
            const transport = _NW_TRANSPORTS[d.transport] || d.transport || 'auto';
            return `<div class="flex items-center justify-between p-3 rounded-md bg-slate-50 border border-slate-200">
                <div><span class="text-sm font-medium text-slate-700">${escapeHtml(d.name || d.id)}</span><span class="ml-2 text-xs text-slate-400">${escapeHtml(typeLabel)} · ${escapeHtml(transport)} · ${escapeHtml(d.address || '')}${d.port ? ':' + escapeHtml(String(d.port)) : ''}</span></div>
                <div class="flex gap-2">
                    <button onclick="editNwDevice('${escapeHtml(d.id)}')" class="text-xs text-blue-500 hover:text-blue-700 font-medium">Edit</button>
                    <button onclick="deleteNwDeviceEntry('${escapeHtml(d.id)}')" class="text-xs text-red-400 hover:text-red-600 font-medium">Delete</button>
                </div>
            </div>`;
        }).join('');
    } catch (e) {
        listEl.innerHTML = `<p class="text-xs text-red-500">Error loading network devices: ${e.message}</p>`;
    }
}

async function deleteNwDeviceEntry(id) {
    if (!await showConfirmToast(`Delete network device ${id}?`)) return;
    try {
        const r = await setupFetch(`/setup/nw-devices/${id}`, { method: 'DELETE' });
        if (!r.ok) throw new Error(await r.text());
        loadNwDevicesList();
    } catch (e) {
        alert('Error: ' + e.message);
    }
}

// loadSpokesAndAgents() — renders the Setup → Spokes & Agents admin TABLES
// (GET /setup/pending_spokes + GET /api/pxmx/agents; see core/src/api.py
// get_pending_spokes). This is the admin management view, distinct from the
// dashboard sidebar lists rendered by _renderDashboardLists() above. The rows
// here are full <table> rows with Approve/Remove action buttons and a DIFFERENT
// status-dot color scheme (bg-yellow-400 for pending, green dot without the
// 8px glow) than the sidebar cards, so they intentionally do NOT share the
// _renderSpokeAgentRow() helper — preserving exact output here matters more
// than de-duplicating the dot markup.
// Shared table-class bundle for the Spokes & Agents admin tables (mirrors the
// _SETUP_CLS pattern used by the Setup tiles). Kept as a const so the two
// render helpers below produce byte-identical output to the pre-split body.
const _SPOKES_TBL_CLS = {
    btnCls: 'px-3 py-1 rounded text-xs font-bold transition-colors',
    tblCls: 'overflow-hidden rounded-md border border-slate-200 bg-white',
    thCls:  'px-4 py-3 font-bold',
    tdCls:  'px-4 py-3',
};

// _identityChangeBanner(ic, clickExpr) — renders the amber "renamed/reimaged"
// banner surfaced when the hub's install-UUID correlation detected that this
// spoke/agent was cloned+renamed, hostname-renamed (pinned id), or reimaged.
// `ic` is the raw {event, ts, detail} from the spokes/agents API; `clickExpr`
// is the JS for the dismiss button's onclick (already escaped), which POSTs to
// the matching ack-change endpoint so the banner clears once an admin sees it.
function _identityChangeBanner(ic, clickExpr) {
    if (!ic || !ic.event) return '';
    const label = ic.event === 'identity_changed' ? 'Renamed'
                : ic.event === 'hostname_changed' ? 'Hostname changed'
                : ic.event === 'reimaged'         ? 'Re-imaged'
                : ic.event;
    const detail = (ic.detail || '').replace(/'/g, "\\'");
    return `<div class="mt-1 flex items-center gap-2 px-2 py-1 rounded bg-amber-50 border border-amber-200 text-amber-700">
                <span class="text-[10px] font-bold uppercase tracking-wide">${label}</span>
                ${detail ? `<span class="text-[10px] text-amber-600 truncate" title="${detail}">${detail}</span>` : ''}
                <button onclick="${clickExpr}" class="ml-auto text-[10px] font-bold text-amber-700 hover:text-amber-900 underline">Dismiss</button>
            </div>`;
}

// _ackIdentityChange(endpoint) — POST to a spoke/agent ack-change endpoint and
// reload the Spokes & Agents tile so the dismissed banner clears. Best-effort:
// on failure we surface the error but still refresh so the UI doesn't hang.
async function _ackIdentityChange(endpoint) {
    try {
        const res = await fetch(endpoint, { method: 'POST' });
        if (!res.ok) {
            const body = await res.text().catch(() => '');
            console.error('ack-change failed:', res.status, body);
        }
    } catch (err) {
        console.error('ack-change request failed:', err);
    } finally {
        if (typeof loadSpokesAndAgents === 'function') loadSpokesAndAgents();
    }
}

// _mgmtBtn(label, onclick, extraCls) — one action button for a management card
// row. Keeps the btn base class + per-button color consistent across the
// Spokes / Agents / Generic Agents tiles.
function _mgmtBtn(label, onclick, extraCls) {
    return `<button onclick="${onclick}" class="${_SPOKES_TBL_CLS.btnCls} ${extraCls || ''}">${label}</button>`;
}

// _mgmtEntryCard(o) — a multi-line stacked card row for the Setup → Spokes &
// Agents tiles. Replaces the cramped fixed-width <table table-fixed> layout
// whose narrow columns wrapped text and stacked buttons awkwardly. Each entry
// is a vertical card: a header line (status dot + name/id + badges), optional
// meta lines (hostname, roles), and an actions row that wraps freely. Shared
// by _renderSpokesTable and _renderAgentsTable.
//
// o = { dot, name, sid, identityBanner, metaLines: [html], badges: [html],
//       actions: [html] }
function _mgmtEntryCard(o) {
    const badges  = (o.badges || []).filter(Boolean).join(' ');
    const meta    = (o.metaLines || []).filter(Boolean).join('');
    const actions = (o.actions || []).filter(Boolean).join('');
    // Corner actions (e.g. Events / Copy) pin to the top-right of the header row,
    // across from the name/ID.
    const corner  = (o.cornerActions || []).filter(Boolean).join(' ');
    // Layout (deterministic — same for Spokes and Agents): name/ID top-left with
    // Events/Copy top-right; then the badges (SPOKE/module/status/version…) on
    // their OWN line, LEFT-aligned + indented (pl-6) under the name — not
    // right-floated, which wrapped inconsistently by content width; then the
    // host/tenant/status meta line; then the action buttons.
    return `<div class="lm-mgmt-card border border-slate-200 rounded-md bg-white p-2.5 hover:bg-slate-50 space-y-1.5">
        <div class="flex items-start justify-between gap-3">
            <div class="flex items-start gap-2.5 min-w-0">
                <div class="w-2 h-2 mt-1.5 rounded-full ${o.dot} shrink-0"></div>
                <div class="min-w-0">
                    <div class="font-medium text-slate-700 break-words">${o.name}</div>
                    <div class="text-[10px] font-mono text-slate-400 break-all">${escapeHtml(o.sid)}</div>
                    ${o.identityBanner || ''}
                </div>
            </div>
            ${corner ? `<div class="flex items-center gap-2 shrink-0">${corner}</div>` : ''}
        </div>
        ${badges ? `<div class="flex items-center gap-1.5 flex-wrap pl-4">${badges}</div>` : ''}
        ${meta}
        ${actions ? `<div class="flex items-center gap-2 flex-wrap pl-6">${actions}</div>` : ''}
    </div>`;
}

// _renderSpokesTable() — renders the Spokes half of the Setup → Spokes & Agents
// admin view. Extracted from loadSpokesAndAgents; the fetch + split preamble
// stays in the caller. `diagBy` (Map<spoke_id, /setup/diagnostics entry>) folds
// the former Diagnostics tile's telemetry into each row — heartbeat/version/
// skew/recovery/alert badges, the status-text + last-error lines, Reset Secret
// / Delete / Recovery Pause / Events actions, and the expandable events panel —
// via _diagTelemetryExtras. Missing telemetry (diag fetch failed for this id)
// degrades gracefully to the approval-only row.
function _renderSpokesTable(spokesWrap, trueSpokes, diagBy) {
    if (!spokesWrap) return;
    const { btnCls, tblCls, thCls, tdCls } = _SPOKES_TBL_CLS;

    // LDAP (directory), DNS, and DHCP are lightweight service modules rather
    // than full infrastructure products — surface them as Type "Module" in the
    // table; everything else stays "Spoke".
    const MODULE_KIND_TYPES = new Set(['directory', 'dns', 'dhcp']);
    const spokeKind = mt => MODULE_KIND_TYPES.has(mt) ? 'Module' : 'Spoke';

    try {
        if (trueSpokes.length === 0) {
            spokesWrap.innerHTML = `<p class="py-8 text-center text-slate-400 italic text-xs">No spokes have connected yet.</p>`;
        } else {
            spokesWrap.innerHTML = `<div class="space-y-1.5">${trueSpokes.map(s => {
                const sid = s.spoke_id;
                const name = s.display_name || sid;
                const approved = s.approved;
                const mtRaw = String(s.module_type || '').toLowerCase();
                const modLabel = moduleLabel(mtRaw);
                const kindLabel = spokeKind(mtRaw);
                const hostname = s.hostname || '';
                const ic = s.identity_change;
                const eSid = sid.replace(/'/g, "\\'");
                const eName = escJsAttr(name);
                const ackClick = `_ackIdentityChange('/setup/spokes/${encodeURIComponent(sid)}/ack-change')`;
                // Telemetry extras from the diagnostics endpoint. The heartbeat-
                // aware dot overrides the approval dot ONLY when the spoke is
                // approved (a pending spoke keeps amber; an approved-but-silent
                // spoke goes red). No diag entry → null → approval-only row.
                const extras = diagBy && diagBy.has(sid) ? _diagTelemetryExtras(diagBy.get(sid)) : null;
                const dot = (extras && approved) ? extras.dot
                          : (approved ? 'bg-green-500' : 'bg-yellow-400');
                // Tenant binding: any spoke can be assigned to a tenant (not just
                // cs, and not just from Simulations → Spoke Management, which only
                // ever surfaced this for cs spokes). Agent-hosting spokes (cs/pxmx)
                // seed newly-approved agents from this binding — see
                // approve_agent_under_spoke in api.py.
                const tenantId = s.tenant_id || '';
                const eTenant = tenantId.replace(/'/g, "\\'");
                // Role sub-spoke → its own row carries an "Unload Role" action
                // that removes the role from the parent agent (annotated in
                // loadSpokesAndAgents). Uniform with "Add role" on the agent.
                const eRoleParent = (s._roleParent || '').replace(/'/g, "\\'");
                const eRoleName = (s._roleName || '').replace(/'/g, "\\'");
                return _mgmtEntryCard({
                    dot,
                    name: escapeHtml(name), sid,
                    identityBanner: _identityChangeBanner(ic, ackClick),
                    metaLines: [
                        // host + tenant + Online/Offline status on ONE flex-wrap
                        // line (was three stacked divs) to save vertical space.
                        `<div class="flex items-center gap-x-3 gap-y-0.5 flex-wrap text-xs pl-6">`
                          + (hostname ? `<span class="font-mono text-slate-500">host: ${escapeHtml(hostname)}</span>` : '')
                          + `<span class="text-slate-500">tenant: ${tenantId ? `<span class="font-mono text-slate-700">${escapeHtml(tenantId)}</span>` : '<span class="italic text-slate-400">unassigned</span>'}</span>`
                          + (extras && extras.status ? `<span class="font-bold ${extras.status.tone}">${escapeHtml(extras.status.text)}</span>` : '')
                          + `</div>`,
                        ...(extras ? extras.metaLines : []),
                    ],
                    badges: [
                        `<span class="text-[10px] px-2 py-0.5 rounded-full font-bold uppercase ${kindLabel === 'Module' ? 'bg-indigo-50 text-indigo-700' : 'bg-slate-100 text-slate-600'}">${kindLabel}</span>`,
                        `<span class="text-[10px] px-2 py-0.5 rounded-full font-bold uppercase bg-slate-200 text-slate-700">${modLabel}</span>`,
                        `<span class="text-[10px] px-2 py-0.5 rounded-full font-bold uppercase ${approved ? 'bg-green-100 text-green-700' : 'bg-yellow-100 text-yellow-700'}">${approved ? 'Approved' : 'Pending'}</span>`,
                        ...(extras ? extras.badges : []),
                    ],
                    actions: [
                        // Edit now hosts Reset Secret + Un-approve (moved off the
                        // row to declutter); pass `approved` so the modal shows
                        // Un-approve only for an already-approved spoke.
                        _mgmtBtn('Edit', `openSpokeMetadataModal('${eSid}','${eName}',${approved})`, 'bg-[#01A982] hover:bg-[#008c6a] text-white'),
                        _mgmtBtn('Tenant', `openSpokeAssignModal('${eSid}','${eTenant}')`, 'bg-white hover:bg-slate-50 text-[#01A982] border border-[#01A982]'),
                        // Approve stays on the row (primary action for a pending
                        // spoke); Un-approve lives inside Edit for approved ones.
                        ...(approved ? [] : [_mgmtBtn('Approve', `approveSpoke('${eSid}')`, 'bg-blue-600 hover:bg-blue-700 text-white')]),
                        ...(s._roleName ? [_mgmtBtn('Unload Role', `unloadRole('${eRoleParent}','${eRoleName}')`, 'bg-amber-50 hover:bg-amber-100 text-amber-700 border border-amber-200')] : []),
                        ...(extras ? extras.actions : []),
                    ],
                    cornerActions: extras ? extras.eventsActions : [],
                }) + (extras ? extras.eventsPanel : '');
            }).join('')}</div>`;
        }
    } catch (err) {
        spokesWrap.innerHTML = `<p class="py-6 text-center text-red-400 italic text-xs">Error: ${err.message}</p>`;
    }
}

// _renderAgentsTable() — renders the Agents half (generic Hub-direct agents +
// Proxmox node agents). Extracted from loadSpokesAndAgents; pxmxAgents are
// fetched by the caller and passed in. The Active Role column + Load Role
// action for generic agents were folded in from the former Setup → Generic
// Nodes tile so generic nodes are managed entirely from Spokes & Agents.
async function _renderAgentsTable(agentsWrap, genericAgents, pxmxAgents, diagBy) {
    if (!agentsWrap) return;
    const { btnCls, tblCls, thCls, tdCls } = _SPOKES_TBL_CLS;

    // Generic Hub-direct agents come from /setup/pending_spokes (module_type
    // "agent"); they approve through the standard spoke-approval path.
    const hubAgents = genericAgents.map(s => {
        const sid = s.spoke_id;
        const dn = s.display_name || sid;
        // The Module column names the product the agent runs. BugFixer is the
        // canonical generic hub agent; any other generic agent falls back to
        // its display name so the column still shows something meaningful.
        const module = /bugfixer/i.test(sid) || /bugfixer/i.test(dn) ? 'BugFixer' : dn;
        return {
            agent_id: sid,
            display_name: dn,
            hostname: s.hostname || '',
            identity_change: s.identity_change || null,
            tenant_id: s.tenant_id || '',
            _status: s.approved ? 'connected' : 'pending',
            _kind: 'spoke',
            _module_type: String(s.module_type || '').toLowerCase(),
            _module: module,
        };
    });

    // pxmxAgents were fetched up front (to scope the Spokes table); reuse
    // them here rather than re-fetching.
    const all = [...hubAgents, ...pxmxAgents];
    // Sort the Agents tile by display name (case-insensitive) so generic
    // Hub-direct agents and Proxmox node agents interleave by name, not by
    // fetch order. Falls back to hostname, then agent_id.
    all.sort((a, b) =>
        (a.display_name || a.hostname || a.agent_id || '').localeCompare(
            (b.display_name || b.hostname || b.agent_id || ''), undefined, { sensitivity: 'base' }));

    // Active Role column (folded in from the former Generic Nodes tile):
    // each connected generic agent hosts 0..N role sub-spokes, surfaced via
    // GET_AVAILABLE_ROLES on the generic relay. We paint the table immediately
    // with a per-row "loading roles…" placeholder, then fill each agent's cell
    // as its round-trip resolves — NO Promise.all barrier, so one sluggish
    // agent can't stall the rest (mirrors the progressive-render approach the
    // standalone Generic Nodes tile used). The role cell is keyed by agent_id;
    // a reload that rebuilt the table while a fetch was outstanding still
    // writes to the right cell if the agent is still listed, and silently
    // skips (querySelector returns null) if it has since dropped off.

    if (all.length === 0) {
        agentsWrap.innerHTML = `<p class="py-6 text-center text-slate-400 italic text-xs">No agents connected yet. Install the generic agent on a node (it appears here to be approved, then load a role) or install the agent on a Proxmox node to begin.</p>`;
    } else {
        agentsWrap.innerHTML = `<div class="space-y-1.5">${all.map(a => {
            const aid = a.agent_id;
            const label = a.display_name || a.hostname || aid;
            const isPending = a._status === 'pending';
            const isSpokeKind = a._kind === 'spoke';
            // Every card here is an agent. Type distinguishes the two flavors:
            // generic Hub-direct agents (module_type "agent", now shown here
            // only once they have a role loaded — idle ones sit in the Generic
            // Agents tile) vs Proxmox node agents relayed through the pxmx
            // spoke. The Module badge names what each one runs.
            const typeLabel = isSpokeKind ? 'Generic Agent' : 'PXMX AGENT';
            const moduleLabelCell = a._module || '—';
            const statusLabel = isPending ? 'Pending' : (isSpokeKind ? 'Approved' : 'Connected');
            const eAid = aid.replace(/'/g, "\\'");
            const eLabel = label.replace(/'/g, "\\'");
            // Tenant binding, surfaced + editable per agent to mirror the Spokes
            // table. Generic agents ARE agent-type spokes so their binding lives
            // on tenant_id (set via the same approve_spoke path); Proxmox node
            // agents carry it in client_simulation.tenant_id (per-agent config).
            const rowTenant = isSpokeKind ? (a.tenant_id || '') : (a.client_simulation?.tenant_id || '');
            const eTenant = rowTenant.replace(/'/g, "\\'");
            // Active Role line: a keyed placeholder for connected generic agents
            // that is filled async after paint (no barrier). Proxmox node agents
            // have no roles; pending generic agents show an em-dash.
            let rolesLine;
            if (!isSpokeKind) {
                rolesLine = '';
            } else if (isPending) {
                rolesLine = `<div class="text-xs text-slate-500 pl-6">roles: <span class="text-slate-400 italic">—</span></div>`;
            } else {
                rolesLine = `<div class="text-xs text-slate-500 pl-6">roles: <span class="lm-agent-role-cell text-slate-400 italic" data-role-cell="${escapeHtml(aid)}">loading…</span></div>`;
            }
            // Telemetry extras folded in from the former Diagnostics tile.
            // Generic Hub-direct agents pull their entry from diagBy (the
            // /setup/diagnostics map); Proxmox node agents are normalized into
            // the same shape from the pxmx agent object itself (they connect
            // through the pxmx spoke, so the hub has no direct diag entry).
            // pxmx agents suppress Reset Secret (revokeAgent is already the
            // Un-approve button here) and Recovery Pause (watchdog is spoke-
            // scoped). The heartbeat dot overrides the approval dot only when
            // the agent is connected/approved — pending keeps amber.
            const extras = isSpokeKind
                ? (diagBy && diagBy.has(aid) ? _diagTelemetryExtras(diagBy.get(aid)) : null)
                : _diagTelemetryExtras(_normalizePxmxAgent(a), { resetFn: 'revokeAgent', deleteFn: 'deleteAgent', allowRecoveryPause: false, allowReset: false });
            const editFn = isSpokeKind ? 'openSpokeMetadataModal' : 'openAgentConfigModal';
            const approveFnName = isSpokeKind ? 'approveSpoke' : 'approveAgent';
            const unapproveFnName = isSpokeKind ? 'unapproveSpoke' : 'revokeAgent';
            const ic = a.identity_change || null;
            const ackEndpoint = isSpokeKind
                ? `/setup/spokes/${encodeURIComponent(aid)}/ack-change`
                : `/api/pxmx/agents/${encodeURIComponent(aid)}/ack-change`;
            const ackClick = `_ackIdentityChange('${ackEndpoint}')`;
            const nameWithCs = `${escapeHtml(label)}${a.client_simulation?.enabled ? ' <span class="ml-1 px-1.5 py-0.5 rounded-full text-[9px] font-bold uppercase bg-green-100 text-green-700 align-middle" title="Client Simulation mode">CS</span>' : ''}`;
            const dot = (extras && !isPending) ? extras.dot
                      : (isPending ? 'bg-amber-400' : 'bg-green-500 shadow-[0_0_6px_rgba(34,197,94,0.5)]');
            return _mgmtEntryCard({
                dot,
                name: nameWithCs, sid: aid,
                identityBanner: _identityChangeBanner(ic, ackClick),
                metaLines: [
                    // host + tenant + Online/Offline status on ONE flex-wrap line
                    // (was three stacked divs) to save vertical space. rolesLine
                    // stays its own line below it.
                    `<div class="flex items-center gap-x-3 gap-y-0.5 flex-wrap text-xs pl-6">`
                      + (a.hostname ? `<span class="font-mono text-slate-500">host: ${escapeHtml(a.hostname)}</span>` : '')
                      + `<span class="text-slate-500">tenant: ${rowTenant ? `<span class="font-mono text-slate-700">${escapeHtml(rowTenant)}</span>` : '<span class="italic text-slate-400">unassigned</span>'}</span>`
                      + (extras && extras.status ? `<span class="font-bold ${extras.status.tone}">${escapeHtml(extras.status.text)}</span>` : '')
                      + `</div>`,
                    rolesLine,
                    ...(extras ? extras.metaLines : []),
                ],
                badges: [
                    `<span class="text-[10px] px-2 py-0.5 rounded-full font-bold uppercase bg-slate-100 text-slate-600">${typeLabel}</span>`,
                    `<span class="text-[10px] px-2 py-0.5 rounded-full font-bold uppercase bg-slate-200 text-slate-700">${moduleLabelCell}</span>`,
                    `<span class="text-[10px] px-2 py-0.5 rounded-full font-bold uppercase ${isPending ? 'bg-amber-100 text-amber-700' : 'bg-green-100 text-green-700'}">${statusLabel}</span>`,
                    ...(extras ? extras.badges : []),
                ],
                actions: [
                    // Spoke-kind agents route Edit → openSpokeMetadataModal, which
                    // now hosts Reset Secret + Un-approve; pass approved (=!isPending)
                    // so the modal shows Un-approve. pxmx Edit (openAgentConfigModal)
                    // ignores the extra arg.
                    _mgmtBtn('Edit', `${editFn}('${eAid}','${eLabel}'${isSpokeKind ? ',' + (!isPending) : ''})`, 'bg-[#01A982] hover:bg-[#008c6a] text-white'),
                    // Dedicated Tenant button, mirroring the Spokes table. Generic
                    // agents reuse the spoke assign modal (they bind via
                    // approve_spoke); Proxmox node agents get their own modal that
                    // writes client_simulation.tenant_id via the agent config API.
                    _mgmtBtn('Tenant',
                        isSpokeKind ? `openSpokeAssignModal('${eAid}','${eTenant}','Agent')` : `openAgentAssignModal('${eAid}','${eTenant}')`,
                        'bg-white hover:bg-slate-50 text-[#01A982] border border-[#01A982]'),
                    (isSpokeKind && !isPending)
                        ? _mgmtBtn('Load Role', `showLoadRoleModal('${eAid}')`, 'bg-white hover:bg-slate-50 text-[#01A982] border border-[#01A982]')
                        : '',
                    isPending
                        ? _mgmtBtn('Approve', `${approveFnName}('${eAid}')`, 'bg-blue-600 hover:bg-blue-700 text-white')
                        // Spoke-kind agents move Un-approve into Edit; pxmx agents
                        // keep revoke on the row (its Edit is a separate config modal).
                        : (isSpokeKind ? '' : _mgmtBtn('Un-approve', `${unapproveFnName}('${eAid}')`, 'bg-red-50 hover:bg-red-100 text-red-600 border border-red-200')),
                    ...(extras ? extras.actions : []),
                ],
                cornerActions: extras ? extras.eventsActions : [],
            }) + (extras ? extras.eventsPanel : '');
        }).join('')}</div>`;
        // Trickle: fill each connected generic agent's Active Role line as its
        // GET_AVAILABLE_ROLES resolves. No barrier, so a slow agent never delays
        // the others. Looks the cell up by data-role-cell each time so a reload
        // that rebuilt the tile mid-flight still targets the right agent (and
        // silently skips one that has since dropped off the list).
        all.forEach(a => {
            if (a._kind !== 'spoke' || a._status !== 'connected') return;
            const aid = a.agent_id;
            // Fetch hosted roles AND deploy status together so the cell reflects
            // both (a deploy role like netbox-server hosts NO sub-role, so without
            // this it always read "none (idle)" with no sign it deployed anything).
            Promise.all([fetchLoadedRoles(aid), fetchDeployStatus(aid)]).then(([active, ds]) => {
                const cell = agentsWrap.querySelector(`.lm-agent-role-cell[data-role-cell="${CSS.escape(aid)}"]`);
                if (!cell) return;
                const parts = [];
                if (Array.isArray(active) && active.length > 0) {
                    parts.push(...active.map(r => `<span class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-blue-100 text-blue-700" title="${escapeHtml(r.sub_spoke_id || '')}">${escapeHtml((AGENT_ROLES[r.role] || {}).name || r.role)}</span>`));
                }
                // Live deploy-role badge (ephemeral — cleared on agent reload).
                const dep = ds && ds.deploy;
                if (dep && dep.role && dep.state) {
                    const st = dep.state;
                    const cls = st === 'completed' ? 'bg-green-100 text-green-700'
                              : st === 'failed' || st === 'error' ? 'bg-red-100 text-red-700'
                              : 'bg-amber-100 text-amber-700';
                    const word = st === 'running' ? 'deploying…' : st;
                    parts.push(`<span class="px-2 py-0.5 rounded-full text-[10px] font-bold ${cls}" title="deploy role">${escapeHtml((AGENT_ROLES[dep.role] || {}).name || dep.role)}: ${escapeHtml(word)}</span>`);
                }
                // Durable NetBox-server marker + reset-admin-password knob.
                if (ds && ds.netbox_installed) {
                    parts.push(`<span class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-slate-100 text-slate-600" title="NetBox application deployed on this node">NetBox</span>`);
                    parts.push(`<button onclick="resetNetboxAdmin('${escapeHtml(aid)}')" class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-white text-[#01A982] border border-[#01A982] hover:bg-green-50 transition-colors" title="Reset the NetBox admin password">Reset admin pw</button>`);
                }
                cell.outerHTML = parts.length
                    ? `<span class="inline-flex flex-wrap items-center gap-1">${parts.join(' ')}</span>`
                    : '<span class="text-slate-400 italic">none (idle)</span>';
            });
        });
    }
}


async function loadSpokesAndAgents() {
    const spokesWrap = document.getElementById('spokes-table-wrap');
    const agentsWrap = document.getElementById('agents-table-wrap');

    // Fetch the full known-module list once and split it by module_type.
    // Treated as agents (shown in the Agents/Generic Agents sections, not
    // Spokes):
    //   - module_type "agent"  : generic Hub-direct agents (e.g. bugfixer)
    // The pxmx "hypervisor" spoke is itself a spoke, so it is shown in the
    // Spokes section (its Proxmox node agents are fetched separately into the
    // Agents section).
    let spokes = [];
    let pxmxAgents = [];
    const pxmxAgentIds = new Set();
    let diagBy = null;
    let diagData = null;

    // Three independent fetches (pending spokes, pxmx agents, diagnostics) were
    // sequential — each awaited before the next started. Fan them out
    // concurrently with Promise.all so the Spokes & Agents view resolves in one
    // round-trip instead of three; each branch keeps its own try/catch so a
    // single failure degrades the same as before (best-effort).
    const [spokesRes, agentsRes, diagRes] = await Promise.allSettled([
        (async () => setupFetch('/setup/pending_spokes'))(),
        (async () => fetch('/api/pxmx/agents', { credentials: 'same-origin' }))(),
        (async () => setupFetch('/setup/diagnostics'))(),
    ]);

    if (spokesRes.status === 'fulfilled') {
        try {
            const res = spokesRes.value;
            if (res.ok) spokes = (await res.json()).spokes || [];
        } catch (err) {
            if (spokesWrap) spokesWrap.innerHTML = `<p class="py-6 text-center text-red-400 italic text-xs">Error: ${err.message}</p>`;
        }
    } else if (spokesWrap) {
        spokesWrap.innerHTML = `<p class="py-6 text-center text-red-400 italic text-xs">Error: ${spokesRes.reason?.message || spokesRes.reason}</p>`;
    }

    // Proxmox node agents are relayed through the pxmx hypervisor spoke. Fetch
    // them up front so we can (a) exclude their ids from the Spokes table — an
    // older approval leaked them into known_modules and rendered a bogus
    // spoke row, since the hub has no direct WebSocket for them — and (b)
    // render them in the Agents table below.
    if (agentsRes.status === 'fulfilled') {
        try {
            const res = agentsRes.value;
            if (res.ok) {
                const agentsData = await res.json();
                const connected = (agentsData.agents || []).map(a => ({ ...a, _status: 'connected', _kind: 'pxmx', _module: 'Proxmox' }));
                const pending   = (agentsData.pending_agents || []).map(a => ({ ...a, _status: 'pending', _kind: 'pxmx', _module: 'Proxmox' }));
                pxmxAgents = [...connected, ...pending];
                pxmxAgents.forEach(a => pxmxAgentIds.add(a.agent_id));
            }
        } catch (err) { console.error('loadSpokesAndAgents: pxmx agents fetch failed — generic agents still render', err); }
    }

    // Diagnostics telemetry (the former standalone Diagnostics tile, now folded
    // into the three management cards). Fetched once here and keyed by spoke_id
    // so each renderer can merge heartbeat/version/recovery/events into its row
    // via _diagTelemetryExtras. Best-effort: a failed/non-admin fetch leaves
    // diagBy empty and the tiles degrade to their approval-only rows. The same
    // response drives the summary bar (Hub/WebUI version + recovery counts).
    if (diagRes.status === 'fulfilled') {
        try {
            const res = diagRes.value;
            if (res.ok) {
                diagData = await res.json();
                diagBy = new Map((diagData.spokes || []).map(s => [s.spoke_id, s]));
            }
        } catch (err) { console.error('loadSpokesAndAgents: diagnostics fetch failed — telemetry badges skipped', err); }
    }
    _renderSpokesSummary(diagData);

    // A loaded role registers a sub-spoke "{agentBase}-{role}", so a spoke that
    // is the BASE of one is a generic agent hosting roles. Recognise it as an
    // agent even when its own module_type didn't round-trip (a disconnected or
    // pre-role agent can report module_type ""), so the AGENT itself lands in
    // the Agents area instead of being double-listed as a plain spoke. Each
    // role sub-spoke still keeps its OWN row in the Spokes table (its
    // module_type is the role's, not "agent") — the intended model is one entry
    // per role spoke plus one for the agent.
    const hasRole = baseId => spokes.some(o => o.spoke_id !== baseId && o.spoke_id.startsWith(baseId + '-'));
    const isAgent = s => String(s.module_type || '').toLowerCase() === 'agent' || hasRole(s.spoke_id);
    const trueSpokes    = spokes.filter(s => !isAgent(s) && !pxmxAgentIds.has(s.spoke_id));
    const genericAgents = spokes.filter(isAgent);

    // Annotate each role sub-spoke ("{agentBase}-{role}") with its parent agent
    // + role name, so the Spokes table can offer a per-role "Unload" action
    // (remove a role directly from its own spoke entry). The longest matching
    // agent-id prefix is the closest parent; the suffix after it is the role
    // name (== the _ROLE_MAP key the agent's UNLOAD_ROLE expects).
    const _agentIds = genericAgents.map(a => a.spoke_id);
    // Known role suffixes ("{agentBase}-{role}") from the role registry, longest
    // first so e.g. a compound key wins over a shorter prefix of it.
    const _roleKeys = Object.keys(AGENT_ROLES).sort((a, b) => b.length - a.length);
    trueSpokes.forEach(s => {
        // Primary: the closest CURRENTLY-CONNECTED generic agent whose id is a
        // prefix of this sub-spoke id.
        let parent = _agentIds
            .filter(aid => s.spoke_id !== aid && s.spoke_id.startsWith(aid + '-'))
            .sort((a, b) => b.length - a.length)[0];
        let roleName = parent ? s.spoke_id.slice(parent.length + 1) : '';
        // Fallback: identify a role sub-spoke by a trailing "-<knownRole>" even
        // when its parent agent isn't in the connected list right now (agent
        // flapping / not yet re-approved). This keeps "Unload Role" available on
        // the role's own row regardless of the parent's live state.
        if (!roleName) {
            const match = _roleKeys.find(role =>
                s.spoke_id.endsWith('-' + role) && s.spoke_id.length > role.length + 1);
            if (match) {
                roleName = match;
                parent = s.spoke_id.slice(0, s.spoke_id.length - match.length - 1);
            }
        }
        if (parent && roleName) {
            s._roleParent = parent;
            s._roleName = roleName;
        }
    });

    // Split generic agents by whether they host a role yet. A loaded role
    // registers a sub-spoke "{base}-{role}" (module_type = the role's), so a
    // generic agent is "active" iff some known spoke id starts with
    // "{base}-". Idle generic agents (no sub-spoke) go in the Generic Agents
    // tile until a role is loaded; active ones move to the Agents tile
    // alongside the Proxmox node agents. This needs no per-agent
    // GET_AVAILABLE_ROLES round-trip — the sub-spoke presence in the already-
    // fetched known-modules list is the signal (mirrors how the multi-role
    // design registers each role as its own spoke). hasRole is defined above.
    // Sort the Spokes tile by display name (case-insensitive) so the admin
    // view is browsable by name regardless of connect/approval order. Falls
    // back to spoke_id when no display_name is set.
    trueSpokes.sort((a, b) =>
        (a.display_name || a.spoke_id || '').localeCompare(
            (b.display_name || b.spoke_id || ''), undefined, { sensitivity: 'base' }));

    // Tenant filter (Setup → Spokes & Agents dropdown). Applied LAST — after the
    // role-annotation pass above has run against the full set — so a role
    // sub-spoke's parent lookup is never broken by a filtered-out peer. Spokes
    // and generic agents carry tenant_id directly; a pxmx node agent carries its
    // owning spoke_id, so its tenant is that spoke's tenant_id. "__unassigned__"
    // (the default) matches anything with no tenant binding — the freshly
    // onboarded spokes/agents an admin triages first; "__all__" disables the
    // filter.
    const _saFilter = document.getElementById('sa-tenant-filter')?.value || '__unassigned__';
    const _spokeTenantById = new Map(spokes.map(s => [s.spoke_id, (s.tenant_id || '').trim()]));
    const _saMatch = (tid) => {
        tid = (tid || '').trim();
        if (_saFilter === '__all__') return true;
        if (_saFilter === '__unassigned__') return !tid;
        return tid === _saFilter;
    };
    const trueSpokesF    = trueSpokes.filter(s => _saMatch(s.tenant_id));
    const genericAgentsF = genericAgents.filter(s => _saMatch(s.tenant_id));
    const pxmxAgentsF    = pxmxAgents.filter(a => _saMatch(_spokeTenantById.get(a.spoke_id) ?? a.tenant_id));

    _renderSpokesTable(spokesWrap, trueSpokesF, diagBy);
    // An agent is an agent — idle (no role yet) and active (role-loaded) generic
    // agents both render in the single Agents table alongside the Proxmox node
    // agents. (The former separate "Generic Agents" tile was removed — splitting
    // by idle/active gave no useful signal and just hid freshly-onboarded agents
    // in a second card.) Load Role + Approve affordances live in _renderAgentsTable.
    await _renderAgentsTable(agentsWrap, genericAgentsF, pxmxAgentsF, diagBy);
}

// _renderSpokesSummary(diagData) — the spoke-update recovery-count bar that sat
// at the top of the former Diagnostics tile, hoisted above the Spokes card now
// that the diagnostics telemetry lives inline in the management cards. The bar
// shows Recovering/Gave up/Paused pills only when there are recovery events and
// hides otherwise (the Hub/WebUI version pills + Heartbeat/SKEW/ALERT legend
// were removed by request). `diagData` is the /setup/diagnostics JSON (or null
// when the fetch failed / viewer is non-admin — bar clears so a broken telemetry
// fetch doesn't leave a stale summary). Stashes hub/webui version on window for
// File-a-Bug context.
function _renderSpokesSummary(diagData) {
    const el = document.getElementById('spokes-summary');
    if (!el) return;
    if (!diagData) { el.innerHTML = ''; return; }
    const hubVersion = diagData.hub_version || 'unknown';
    const webuiVersion = diagData.webui_version || 'unknown';
    window.__lmHubVersion = hubVersion;
    window.__lmWebuiVersion = webuiVersion;
    let recovering = 0, gaveUp = 0, paused = 0;
    for (const s of (diagData.spokes || [])) {
        const r = s.recovery || {};
        if (r.manual_pause) paused++;
        else if (r.gave_up) gaveUp++;
        else if (r.in_progress) recovering++;
    }
    // The Hub/WebUI version pills + the Heartbeat/SKEW/ALERT legend were removed
    // by request — the bar now surfaces only spoke-update recovery counts and
    // hides entirely when nothing is recovering/gave-up/paused. hub/webui version
    // is still stashed on window above for File-a-Bug context.
    if (!recovering && !gaveUp && !paused) {
        el.innerHTML = '';
        return;
    }
    el.innerHTML = `
        ${recovering ? `<span class="px-2 py-1 rounded-md bg-amber-100 text-amber-700 font-medium">Recovering: ${recovering}</span>` : ''}
        ${gaveUp ? `<span class="px-2 py-1 rounded-md bg-red-100 text-red-700 font-medium">Gave up: ${gaveUp}</span>` : ''}
        ${paused ? `<span class="px-2 py-1 rounded-md bg-slate-200 text-slate-600 font-medium">Paused: ${paused}</span>` : ''}
    `;
}

async function approveAgent(agentId) {
    // Resolve the spoke that actually owns this agent from the same
    // aggregated list the Agents tile renders from (now tagged with
    // spoke_id — see get_pxmx_agents in api.py), rather than assuming a
    // hypervisor (pxmx) spoke: a cs-dialed agent in the split-topology case
    // is not on pxmx at all, and hardcoding that lookup either routed the
    // approval to the wrong spoke (silently no-op — the agent stays pending
    // forever) or blocked approval outright when no pxmx spoke was connected.
    let spokeId = null;
    try {
        const res = await fetch('/api/pxmx/agents', { credentials: 'same-origin' });
        const data = res.ok ? await res.json() : {};
        const all = [...(data.agents || []), ...(data.pending_agents || [])];
        const found = all.find(a => a.agent_id === agentId);
        spokeId = found && found.spoke_id;
    } catch (e) { console.error('approveAgent: could not resolve owning spoke', e); }
    if (!spokeId) { showToast('Could not determine which spoke owns this agent', 'error'); return; }
    try {
        const res = await setupFetch(`/setup/spokes/${encodeURIComponent(spokeId)}/agents/${encodeURIComponent(agentId)}/approve`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}),
        });
        const d = await res.json();
        if (res.ok) { showToast(`Agent '${agentId}' approved`, 'success'); _reloadActiveMgmtView(); }
        else showToast(d.detail || 'Approval failed', 'error');
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

async function revokeAgent(agentId) {
    if (!await showConfirmToast(`Disconnect agent '${agentId}'? It will auto-reconnect and require re-approval.`)) return;
    try {
        const res = await fetch(`/api/pxmx/agents/${encodeURIComponent(agentId)}/revoke`, {
            method: 'POST', credentials: 'same-origin',
        });
        const d = await res.json();
        if (res.ok) { showToast(d.message || 'Agent disconnected', 'success'); _reloadActiveMgmtView(); }
        else showToast(d.detail || 'Revoke failed', 'error');
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

async function editAgentName(agentId, currentLabel) {
    const name = prompt(`Display name for agent '${agentId}':`, currentLabel === agentId ? '' : currentLabel);
    if (name === null) return;
    try {
        const res = await fetch(`/api/pxmx/agents/${encodeURIComponent(agentId)}/rename`, {
            method: 'POST', credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ display_name: name.trim() || agentId }),
        });
        const d = await res.json();
        if (res.ok) { showToast('Agent renamed', 'success'); loadSpokesAndAgents(); }
        else showToast(d.detail || 'Rename failed', 'error');
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

// Agent Configuration modal for Proxmox node agents — display name + Client
// Simulation mode toggle + tenant. Supersedes the editAgentName prompt; the
// row's Edit button (loadSpokesAndAgents) now opens this. Models on
// openSpokeMetadataModal / saveSpokeMetadata above.
async function openAgentConfigModal(agentId, currentLabel) {
    const modal = document.createElement('div');
    modal.id = 'agent-config-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm';

    // Load the stored config. Tenant binding is NOT edited here — it has its own
    // "Tenant" button on the row (openAgentAssignModal), matching the Spokes
    // table where Edit is metadata-only and tenant is a separate action. The
    // current tenant is still read so we can show it read-only and preserve it
    // on save (Edit must never silently drop the binding).
    let displayName = (currentLabel && currentLabel !== agentId) ? currentLabel : '';
    let csEnabled = false;
    let tenantId = '';
    try {
        const res = await fetch(`/api/pxmx/agents/${encodeURIComponent(agentId)}/config`, { credentials: 'same-origin' });
        if (res.ok) {
            const data = await res.json();
            const cfg = data.config || {};
            if (cfg.display_name) displayName = cfg.display_name;
            const cs = cfg.client_simulation || {};
            csEnabled = !!cs.enabled;
            tenantId = cs.tenant_id || '';
        }
    } catch (e) { console.error('Error fetching agent config:', e); }

    const safeName = (displayName || '').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const safeTenant = (tenantId || '').replace(/"/g, '&quot;');

    modal.innerHTML = `
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-md overflow-hidden">
            <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50">
                <h3 class="text-lg font-bold text-[#263040]">Agent Configuration</h3>
                <button onclick="this.closest('#agent-config-modal').remove()" class="text-slate-400 hover:text-slate-600 transition-colors">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                </button>
            </div>
            <div class="p-6 space-y-4">
                <div class="text-xs text-slate-400 font-mono mb-2">ID: ${agentId}</div>
                <div class="space-y-2">
                    <label class="text-xs text-slate-500 uppercase font-bold">Display Name</label>
                    <input type="text" id="agent-cfg-display-name" value="${safeName}" placeholder="${agentId}" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                </div>
                <div class="space-y-2">
                    <label class="text-xs text-slate-500 uppercase font-bold">Client Simulation</label>
                    <div class="flex items-center gap-2">
                        <input type="checkbox" id="agent-cfg-cs-enabled" ${csEnabled ? 'checked' : ''} class="rounded border-slate-300 text-[#01A982] focus:ring-green-500">
                        <label for="agent-cfg-cs-enabled" class="text-sm text-slate-600">Enable Client Simulation mode on this host</label>
                    </div>
                    <p class="text-[11px] text-slate-400">When enabled, this Proxmox agent activates the Client-Sim feature set (USB provisioning, VM clone/reclone, watchdogs, backup, reseed). Features are ported in incrementally.</p>
                </div>
                <div class="space-y-2">
                    <label class="text-xs text-slate-500 uppercase font-bold">Tenant</label>
                    <input type="hidden" id="agent-cfg-tenant" value="${safeTenant}">
                    <p class="text-sm text-slate-700">${tenantId ? `<span class="font-mono">${tenantId.replace(/</g, '&lt;')}</span>` : '<span class="italic text-slate-400">(unbound)</span>'}</p>
                    <p class="text-[11px] text-slate-400">Use the <b>Tenant</b> button on the agent row to change this binding.</p>
                </div>
                <div class="pt-4 flex justify-end gap-3">
                    <button onclick="this.closest('#agent-config-modal').remove()" class="px-4 py-2 text-sm font-medium text-slate-600 hover:text-slate-800">Cancel</button>
                    <button onclick="saveAgentConfig('${agentId.replace(/'/g, "\\'")}')" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm">Save Changes</button>
                </div>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
}

async function saveAgentConfig(agentId) {
    const displayName = document.getElementById('agent-cfg-display-name').value.trim();
    const csEnabled = document.getElementById('agent-cfg-cs-enabled').checked;
    const tenantId = document.getElementById('agent-cfg-tenant').value;
    try {
        const res = await fetch(`/api/pxmx/agents/${encodeURIComponent(agentId)}/config`, {
            method: 'POST', credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                display_name: displayName || agentId,
                client_simulation: { enabled: csEnabled, tenant_id: tenantId },
            }),
        });
        const d = await res.json().catch(() => ({}));
        if (res.ok) {
            // d.queued: the owning spoke was momentarily unreachable and this
            // was queued via the Mailbox instead of dropped — surface that as
            // a distinct tone from an already-live push (see push_or_queue_to_spoke).
            showToast(d.message || 'Agent config saved', d.queued ? 'info' : 'success');
            document.getElementById('agent-config-modal')?.remove();
            loadSpokesAndAgents();
        } else {
            showToast(d.detail || 'Save failed', 'error');
        }
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

/* Dedicated "Tenant" modal for Proxmox node agents — the agent-side counterpart
 * to openSpokeAssignModal, so every agent row has the same tenant action a spoke
 * row does. A Proxmox agent's binding lives in client_simulation.tenant_id (per-
 * agent config), not on a spoke approval, so this writes via the agent config
 * API rather than /setup/approve_spoke. Generic (agent-type spoke) agents use
 * openSpokeAssignModal directly. We read the current config first so saving the
 * tenant preserves display_name + the CS-enabled flag (stashed in hidden inputs)
 * — changing the tenant must never wipe the other config. */
async function openAgentAssignModal(agentId, currentTenantId) {
    const modal = document.createElement('div');
    modal.id = 'agent-assign-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm';

    let displayName = '';
    let csEnabled = false;
    let tenantId = currentTenantId || '';
    try {
        const res = await fetch(`/api/pxmx/agents/${encodeURIComponent(agentId)}/config`, { credentials: 'same-origin' });
        if (res.ok) {
            const cfg = (await res.json()).config || {};
            displayName = cfg.display_name || '';
            const cs = cfg.client_simulation || {};
            csEnabled = !!cs.enabled;
            tenantId = cs.tenant_id || tenantId;
        }
    } catch (e) { console.error('Error fetching agent config for tenant assign:', e); }

    let tenantOptions = '';
    try {
        const res = await setupFetch('/setup/tenants');
        if (res.ok) {
            const tenants = (await res.json()).tenants || [];
            const sel = tenantId || currentTenant || 'default';
            tenantOptions = tenants.map(t =>
                `<option value="${t.id}" ${t.id === sel ? 'selected' : ''}>${t.name}</option>`).join('');
        }
    } catch (e) { console.error('Error fetching tenants for agent assign:', e); }

    const safeDn = (displayName || '').replace(/"/g, '&quot;');

    modal.innerHTML = `
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-md overflow-hidden">
            <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50">
                <h3 class="text-lg font-bold text-[#263040]">Assign Agent to Tenant</h3>
                <button onclick="this.closest('#agent-assign-modal').remove()" class="text-slate-400 hover:text-slate-600 transition-colors">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                </button>
            </div>
            <div class="p-6 space-y-4">
                <div class="text-xs text-slate-400 font-mono mb-2">Agent: ${agentId}</div>
                <input type="hidden" id="agent-assign-dn" value="${safeDn}">
                <input type="hidden" id="agent-assign-cs" value="${csEnabled ? '1' : '0'}">
                <p class="text-[11px] text-slate-400">Binds this Proxmox node agent to a tenant so its telemetry appears in that tenant's VM Server. The agent's display name and Client-Simulation setting are preserved.</p>
                <div class="space-y-2">
                    <label class="text-xs text-slate-500 uppercase font-bold">Tenant</label>
                    <select id="agent-assign-tenant" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                        <option value="" ${!tenantId ? 'selected' : ''}>(unbound)</option>
                        ${tenantOptions}
                    </select>
                </div>
                <div class="pt-4 flex justify-end gap-3">
                    <button onclick="this.closest('#agent-assign-modal').remove()" class="px-4 py-2 text-sm font-medium text-slate-600 hover:text-slate-800">Cancel</button>
                    <button onclick="saveAgentTenant('${agentId.replace(/'/g, "\\'")}')" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm">Assign</button>
                </div>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
}

async function saveAgentTenant(agentId) {
    const tenantId = document.getElementById('agent-assign-tenant').value;
    const displayName = document.getElementById('agent-assign-dn').value;
    const csEnabled = document.getElementById('agent-assign-cs').value === '1';
    try {
        const res = await fetch(`/api/pxmx/agents/${encodeURIComponent(agentId)}/config`, {
            method: 'POST', credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                display_name: displayName || agentId,
                client_simulation: { enabled: csEnabled, tenant_id: tenantId },
            }),
        });
        const d = await res.json().catch(() => ({}));
        if (res.ok) {
            showToast(d.message || 'Agent tenant updated', d.queued ? 'info' : 'success');
            document.getElementById('agent-assign-modal')?.remove();
            loadSpokesAndAgents();
        } else {
            showToast(d.detail || 'Save failed', 'error');
        }
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

/* Admin assigns/rebinds ANY spoke to a tenant — a "Tenant" button on every row
 * in Setup → Spokes & Agents (_renderSpokesTable), plus Simulations → Spoke
 * Management for cs spokes specifically. Mirrors openAgentConfigModal but
 * talks to the existing admin /setup/approve_spoke route (idempotent
 * re-approve + tenant binding). Agent-hosting spokes (cs/pxmx) seed any newly
 * approved agent's tenant from this binding (approve_agent_under_spoke in
 * api.py), so an agent connecting to a tenant-bound spoke inherits it without
 * per-agent configuration. Only the admin UI renders the button that opens
 * this, so /setup/tenants (admin-only) is safe to call here. */
async function openSpokeAssignModal(spokeId, currentTenantId, noun = 'Spoke') {
    const modal = document.createElement('div');
    modal.id = 'spoke-assign-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm';

    let tenantOptions = '';
    try {
        const res = await setupFetch('/setup/tenants');
        if (res.ok) {
            const tenants = (await res.json()).tenants || [];
            const sel = currentTenantId || currentTenant || 'default';
            tenantOptions = tenants.map(t =>
                `<option value="${t.id}" ${t.id === sel ? 'selected' : ''}>${t.name}</option>`).join('');
        }
    } catch (e) { console.error('Error fetching tenants for spoke assign:', e); }

    modal.innerHTML = `
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-md overflow-hidden">
            <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50">
                <h3 class="text-lg font-bold text-[#263040]">Assign ${noun} to Tenant</h3>
                <button onclick="this.closest('#spoke-assign-modal').remove()" class="text-slate-400 hover:text-slate-600 transition-colors">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                </button>
            </div>
            <div class="p-6 space-y-4">
                <div class="text-xs text-slate-400 font-mono mb-2">${noun}: ${spokeId}</div>
                <p class="text-[11px] text-slate-400">Approving (re-approving) this ${noun.toLowerCase()} with a tenant binds it so its telemetry appears in that tenant's VM Server. Idempotent — the session secret is preserved.</p>
                <div class="space-y-2">
                    <label class="text-xs text-slate-500 uppercase font-bold">Tenant</label>
                    <select id="spoke-assign-tenant" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                        <option value="" ${!currentTenantId ? 'selected' : ''}>(unbound)</option>
                        ${tenantOptions}
                    </select>
                </div>
                <div class="pt-4 flex justify-end gap-3">
                    <button onclick="this.closest('#spoke-assign-modal').remove()" class="px-4 py-2 text-sm font-medium text-slate-600 hover:text-slate-800">Cancel</button>
                    <button onclick="saveSpokeAssign('${spokeId.replace(/'/g, "\\'")}')" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm">Assign</button>
                </div>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
}

async function saveSpokeAssign(spokeId) {
    const tenantId = document.getElementById('spoke-assign-tenant').value;
    try {
        const res = await setupFetch('/setup/approve_spoke', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ spoke_id: spokeId, action: 'approve', tenant_id: tenantId }),
        });
        const d = await res.json().catch(() => ({}));
        if (res.ok) {
            showToast(d.message || 'Spoke assigned', 'success');
            document.getElementById('spoke-assign-modal')?.remove();
            // Now opened from two contexts: Simulations → Spoke Management
            // (cs spokes only) and Setup → Spokes & Agents (any spoke) — reload
            // whichever is actually on screen.
            if (currentView === 'setup') loadSpokesAndAgents();
            else if (typeof loadCSData === 'function') loadCSData('Spoke Management');
        } else {
            showToast(d.detail || 'Assign failed', 'error');
        }
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

async function deleteSpoke(spokeId, label) {
    const name = label || spokeId;
    if (!await showConfirmToast(`Delete '${name}'?\n\nThis permanently removes the registration and its secret. ` +
                 `If it is currently connected it will be disconnected and must fully re-onboard to return. ` +
                 `This cannot be undone.`)) return;
    try {
        const res = await setupFetch(`/setup/spokes/${encodeURIComponent(spokeId)}`, { method: 'DELETE' });
        const d = await res.json().catch(() => ({}));
        if (res.ok) { showToast(d.message || 'Removed', 'success'); _reloadActiveMgmtView(); }
        else showToast(d.detail || 'Delete failed', 'error');
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

async function deleteAgent(agentId) {
    if (!await showConfirmToast(`Delete agent '${agentId}'?\n\nThis disconnects it if connected and removes its display-name ` +
                 `override. It will need re-approval to reconnect. This cannot be undone.`)) return;
    try {
        const res = await fetch(`/api/pxmx/agents/${encodeURIComponent(agentId)}`, {
            method: 'DELETE', credentials: 'same-origin',
        });
        const d = await res.json().catch(() => ({}));
        if (res.ok) { showToast(d.message || 'Agent removed', 'success'); _reloadActiveMgmtView(); }
        else showToast(d.detail || 'Delete failed', 'error');
    } catch (e) { showToast('Error: ' + e.message, 'error'); }
}

async function openSpokeMetadataModal(spokeId, currentName, approved) {
    const modal = document.createElement('div');
    modal.id = 'spoke-metadata-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm';

    let description = '';
    try {
        const res = await setupFetch(`/setup/spoke-metadata/${spokeId}`);
        if (res.ok) {
            const data = await res.json();
            description = data.metadata.description || '';
            currentName = data.metadata.display_name || currentName;
        }
    } catch (e) {
        console.error('Error fetching spoke metadata:', e);
    }

    const safeName = (currentName || '').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const safeDesc = description.replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const eId = spokeId.replace(/'/g, "\\'");

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
                    <input type="text" id="meta-display-name" value="${safeName}" placeholder="e.g. Core Firewall" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                </div>
                <div class="space-y-2">
                    <label class="text-xs text-slate-500 uppercase font-bold">Description</label>
                    <textarea id="meta-description" rows="3" placeholder="Describe the purpose of this spoke..." class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">${safeDesc}</textarea>
                </div>
                <div class="space-y-2">
                    <label class="text-xs text-slate-500 uppercase font-bold">System Hostname (Optional)</label>
                    <input type="text" id="meta-hostname" placeholder="e.g. opnsense-core" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                </div>
                <div class="pt-4 border-t border-slate-200 space-y-2">
                    <label class="text-xs text-slate-500 uppercase font-bold">Spoke Actions</label>
                    <div class="flex flex-wrap gap-2">
                        <button onclick="resetSpokeSecret('${eId}'); this.closest('#spoke-metadata-modal').remove()" class="px-3 py-1.5 text-xs font-medium rounded-md bg-slate-100 hover:bg-slate-200 text-slate-600 border border-slate-300 transition-colors">Reset Secret</button>
                        ${approved ? `<button onclick="unapproveSpoke('${eId}'); this.closest('#spoke-metadata-modal').remove()" class="px-3 py-1.5 text-xs font-medium rounded-md bg-red-50 hover:bg-red-100 text-red-600 border border-red-200 transition-colors">Un-approve</button>` : ''}
                    </div>
                    <p class="text-[11px] text-slate-400">Reset Secret wipes stored keys and forces re-onboarding. Un-approve revokes access until re-approved.</p>
                </div>
                <div class="pt-4 flex justify-end gap-3">
                    <button onclick="this.closest('#spoke-metadata-modal').remove()" class="px-4 py-2 text-sm font-medium text-slate-600 hover:text-slate-800">Cancel</button>
                    <button onclick="saveSpokeMetadata('${spokeId.replace(/'/g, "\\'")}')" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm">Save Changes</button>
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
        const response = await setupFetch('/setup/spoke-metadata', {
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
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            const errorMsg = errorData.detail || `HTTP ${response.status}: ${response.statusText}`;
            throw new Error(errorMsg);
        }

        if (hostname) {
            await setupFetch('/setup/spoke-name', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    spoke_id: spokeId,
                    display_name: displayName,
                    hostname: hostname
                })
            });
        }

        showToast('Spoke metadata updated successfully.', 'success');
        const modal = document.getElementById('spoke-metadata-modal');
        if (modal) modal.remove();
        await loadSpokesAndAgents();
        updateStatus();
    } catch (err) {
        showToast('Error updating metadata: ' + err.message, 'error');
    }
}

// Reload the active management surface after a spoke/agent state change
// (approve / un-approve / reset-secret / delete). The Setup > Spokes & Agents
// page now hosts the admin cards AND the folded-in diagnostics telemetry in
// one loadSpokesAndAgents() pass, so a single call repopulates both — a spoke
// state change surfaces in the telemetry badges too.
function _reloadActiveMgmtView() {
    loadSpokesAndAgents();
}

async function approveSpoke(spokeId) {
    try {
        const response = await setupFetch('/setup/approve_spoke', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ spoke_id: spokeId, action: 'approve' })
        });
        if (!response.ok) throw new Error('Approval failed');

        _reloadActiveMgmtView();
        updateStatus();
    } catch (err) {
        showToast('Error approving spoke: ' + err.message, 'error');
    }
}

async function unapproveSpoke(spokeId) {
    try {
        const response = await setupFetch('/setup/approve_spoke', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ spoke_id: spokeId, action: 'unapprove' })
        });
        if (!response.ok) throw new Error('Un-approval failed');

        _reloadActiveMgmtView();
        updateStatus();
    } catch (err) {
        showToast('Error un-approving spoke: ' + err.message, 'error');
    }
}

async function resetSpokeSecret(spokeId) {
    if (!await showConfirmToast(`Are you sure you want to reset the secret for ${spokeId}? This will wipe all stored keys and force the spoke to re-onboard using a new first-secret.`)) {
        return;
    }
    try {
        const response = await setupFetch(`/setup/spokes/${spokeId}/reset-secret`, { method: 'POST' });
        if (!response.ok) throw new Error('Secret reset failed');

        showToast(`Secret for ${spokeId} has been reset. Restart the agent install or trigger a new handshake.`, 'success');
        _reloadActiveMgmtView();
    } catch (err) {
        showToast('Error resetting secret: ' + err.message, 'error');
    }
}

async function loadUsers() {
    const bodyEl = document.getElementById('user-permissions-body');
    if (!bodyEl) return;

    try {
        // Tenant Admins manage their CURRENT tenant's users via the tenant-
        // scoped route; Global Admins see the whole fleet via /setup/users.
        const base = _taUsersBase();
        const response = await setupFetch(base ? base : '/setup/users');
        if (!response.ok) throw new Error('Failed to fetch users');
        const data = await response.json();
        const users = data.users || {};
        const viewerIsTadm = !!isTenantAdmin();

        if (Object.keys(users).length === 0) {
            bodyEl.innerHTML = `<tr class="text-center py-8 text-slate-400 italic"><td colspan="17">No users configured.</td></tr>`;
            return;
        }

        // Cache group id→name for the Groups column badges.
        window._permGroupNames = window._permGroupNames || {};
        bodyEl.innerHTML = Object.entries(users).map(([userId, user]) => {
            // Show EFFECTIVE access (groups ∪ per-user) so the table reflects
            // what the user actually gets; fall back to per-user perms if the
            // backend predates RBAC enrichment.
            const perms = user.effective_permissions || user.permissions || {};
            // Admin is stored in two equivalent forms (permissions.admin boolean
            // and permissions.role == "admin"); honor both so a role-only admin
            // (e.g. the first-run bootstrap admin) renders as checked.
            const adminCell = (perms.admin === true || perms.role === 'admin')
                ? `<svg class="w-4 h-4 text-green-500 mx-auto" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"></path></svg>`
                : (perms.role === 'tenant_admin')
                    ? `<span class="text-[10px] bg-amber-100 text-amber-800 border border-amber-200 px-1.5 py-0.5 rounded font-bold" title="Tenant-level Admin">Admin</span>`
                    : `<div class="w-4 h-4 rounded-full border-2 border-slate-200 mx-auto"></div>`;
            const check = (key) => perms[key] ?
                `<svg class="w-4 h-4 text-green-500 mx-auto" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"></path></svg>` :
                `<div class="w-4 h-4 rounded-full border-2 border-slate-200 mx-auto"></div>`;
            const authBadge = (user.auth_type === 'ldap')
                ? `<span class="text-[10px] bg-blue-100 text-blue-700 px-1.5 py-0.5 rounded font-medium">LDAP</span>`
                : `<span class="text-[10px] bg-slate-100 text-slate-600 px-1.5 py-0.5 rounded font-medium">Local</span>`;
            const tenantBadges = (user.tenants || []).map(t =>
                `<span class="text-[10px] bg-green-50 text-green-700 border border-green-200 px-1.5 py-0.5 rounded font-mono cursor-pointer hover:bg-green-100" onclick="viewAsTenant('${t}')">${t}</span>`
            ).join(' ') || '<span class="text-[10px] text-slate-300 italic">none</span>';
            const groupBadges = (user.groups || []).map(g =>
                `<span class="text-[10px] bg-indigo-50 text-indigo-700 border border-indigo-200 px-1.5 py-0.5 rounded font-medium">${window._permGroupNames[g] || g}</span>`
            ).join(' ') || '<span class="text-[10px] text-slate-300 italic">none</span>';

            const isProtected = !!user.protected;
            const lockIcon = `<svg class="w-3 h-3 inline-block text-slate-400 ml-1" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clip-rule="evenodd"/></svg>`;
            // A tenant Admin may not edit/remove protected OR admin-tier users
            // (the backend 403s; hide the buttons so the UI matches). Global
            // Admins see the full action set for non-protected users.
            const lockedForTadm = viewerIsTadm && (isProtected || _isPermsAdminTier(perms));
            const actions = isProtected
                ? `<span class="text-slate-300 text-xs italic select-none">Protected${lockIcon}</span>`
                : lockedForTadm
                    ? `<span class="text-slate-300 text-xs italic select-none">Admin${lockIcon}</span>`
                    : `<button onclick="editUser('${userId}')" class="text-blue-400 hover:text-blue-600 text-xs font-bold mr-3">Edit</button>
                       <button onclick="deleteUser('${userId}')" class="text-red-400 hover:text-red-600 text-xs font-bold">Delete</button>`;

            return `
                <tr class="hover:bg-slate-50 transition-colors">
                    <td class="px-4 py-3 font-mono text-xs font-medium text-slate-700">${userId}${isProtected ? lockIcon : ''}</td>
                    <td class="px-4 py-3">${authBadge}</td>
                    <td class="px-4 py-3 max-w-[140px]"><div class="flex flex-wrap gap-1">${tenantBadges}</div></td>
                    <td class="px-4 py-3 max-w-[140px]"><div class="flex flex-wrap gap-1">${groupBadges}</div></td>
                    <td class="px-4 py-3 text-center">${adminCell}</td>
                    <td class="px-4 py-3 text-center">${check('view')}</td>
                    <td class="px-4 py-3 text-center">${check('edit')}</td>
                    <td class="px-4 py-3 text-center">${check('pxmx')}</td>
                    <td class="px-4 py-3 text-center">${check('firewall')}</td>
                    <td class="px-4 py-3 text-center">${check('dns')}</td>
                    <td class="px-4 py-3 text-center">${check('security')}</td>
                    <td class="px-4 py-3 text-center">${check('nw')}</td>
                    <td class="px-4 py-3 text-center">${check('ipam')}</td>
                    <td class="px-4 py-3 text-center">${check('cs')}</td>
                    <td class="px-4 py-3 text-center">${check('console')}</td>
                    <td class="px-4 py-3 text-center">${check('console_write')}</td>
                    <td class="px-4 py-3 text-right whitespace-nowrap">${actions}</td>
                </tr>
            `;
        }).join('');
    } catch (err) {
        console.error('Error loading users:', err);
        bodyEl.innerHTML = `<tr class="text-center py-8 text-red-500 text-xs">Error loading users: ${err.message}</tr>`;
    }
}

async function deleteUser(userId) {
    const base = _taUsersBase();
    const verb = base ? `remove user ${userId} from tenant ${currentTenant}` : `delete user ${userId}`;
    if (!await showConfirmToast(`Are you sure you want to ${verb}?`)) return;
    try {
        const url = base ? `${base}/${encodeURIComponent(userId)}` : `/setup/users/${encodeURIComponent(userId)}`;
        const response = await setupFetch(url, { method: 'DELETE' });
        if (response.ok) {
            alert(base ? 'User removed from tenant' : 'User deleted');
            await loadUsers();
        } else {
            const d = await response.json().catch(() => ({}));
            alert(d.detail || 'Failed to delete user');
        }
    } catch (err) {
        alert('Error deleting user: ' + err.message);
    }
}

// ── Permission Groups (RBAC) ───────────────────────────────────────────────
// Right-key → display label for the group editor + user-assignment checklists.
// Kept in sync with access.ENFORCED_RIGHTS on the backend.
const _RBAC_RIGHT_LABELS = {
    admin: 'Global Admin',
    tenant_admin: 'Admin (tenant)',
    edit: 'Edit (write user)',
    firewall: 'Firewall',
    nw: 'Network Devices',
    ipam: 'IPAM',
    nac: 'Security / NAC',
    dns: 'DNS',
    dhcp: 'DHCP',
    ldap: 'Directory / LDAP',
    pxmx: 'Hypervisors',
    le: 'Certificates',
    console: 'Console',
    console_write: 'Console Write',
    cs: 'Simulations',
};

async function loadGroups() {
    const bodyEl = document.getElementById('permission-groups-body');
    try {
        const resp = await setupFetch('/setup/groups');
        if (!resp.ok) throw new Error('Failed to fetch groups');
        const data = await resp.json();
        const groups = data.groups || {};
        // Cache for the users table Groups column + the modal checklists.
        window._permGroups = groups;
        window._permGroupNames = Object.fromEntries(
            Object.entries(groups).map(([gid, g]) => [gid, g.name || gid]));
        // Tenant names for the group-table scope badges + the modal checklist.
        await ensureTenants();
        if (!bodyEl) return;
        if (Object.keys(groups).length === 0) {
            bodyEl.innerHTML = `<tr><td colspan="5" class="px-4 py-6 text-center text-slate-400 italic">No groups yet — create one to bundle module access.</td></tr>`;
            return;
        }
        bodyEl.innerHTML = Object.entries(groups).map(([gid, g]) => {
            const perms = g.permissions || {};
            const isAdmin = perms.admin === true || perms.role === 'admin';
            const isTenantAdmin = perms.role === 'tenant_admin';
            const permBadges = isAdmin
                ? `<span class="text-[10px] bg-amber-100 text-amber-800 border border-amber-200 px-1.5 py-0.5 rounded font-bold">Global Admin</span>`
                : isTenantAdmin
                    ? `<span class="text-[10px] bg-amber-50 text-amber-700 border border-amber-200 px-1.5 py-0.5 rounded font-bold">Admin (tenant)</span>`
                    : (Object.keys(perms).filter(k => k !== 'role' && k !== 'tenant_admin' && perms[k]).map(k =>
                        `<span class="text-[10px] bg-slate-100 text-slate-600 px-1.5 py-0.5 rounded font-medium">${_RBAC_RIGHT_LABELS[k] || k}</span>`
                      ).join(' ') || '<span class="text-[10px] text-slate-300 italic">none</span>');
            const ldap = g.ldap_group
                ? `<span class="font-mono text-xs text-blue-600">${g.ldap_group}</span>`
                : '<span class="text-[10px] text-slate-300 italic">—</span>';
            // Granted tenant scope: a group may carry a ``tenants`` list so a
            // single Entra/LDAP group grants BOTH RBAC permissions AND tenant
            // scope. Show the tenant names (ids fall back when names unresolved).
            const tNames = (window._allTenantsName || {});
            const scopeBadges = (g.tenants && g.tenants.length)
                ? `<div class="mt-1 flex flex-wrap gap-1">${g.tenants.map(tid =>
                    `<span class="text-[10px] bg-indigo-50 text-indigo-700 border border-indigo-100 px-1.5 py-0.5 rounded font-medium">${tNames[tid] || tid}</span>`).join('')}</div>`
                : '';
            return `
                <tr class="hover:bg-slate-50 transition-colors">
                    <td class="px-4 py-3"><div class="font-medium text-slate-700 text-sm">${g.name || gid}</div><div class="text-[11px] text-slate-400">${g.description || ''}</div>${scopeBadges}</td>
                    <td class="px-4 py-3"><div class="flex flex-wrap gap-1">${permBadges}</div></td>
                    <td class="px-4 py-3">${ldap}</td>
                    <td class="px-4 py-3 text-center text-slate-600">${g.member_count || 0}</td>
                    <td class="px-4 py-3 text-right whitespace-nowrap">
                        <button onclick="showGroupModal('${gid}')" class="text-blue-400 hover:text-blue-600 text-xs font-bold mr-3">Edit</button>
                        <button onclick="deleteGroup('${gid}')" class="text-red-400 hover:text-red-600 text-xs font-bold">Delete</button>
                    </td>
                </tr>`;
        }).join('');
    } catch (err) {
        console.error('Error loading groups:', err);
        if (bodyEl) bodyEl.innerHTML = `<tr><td colspan="5" class="px-4 py-6 text-center text-red-500 text-xs">Error loading groups: ${err.message}</td></tr>`;
    }
}

// Fetch + cache the tenant list (id + name) for the group-modal tenant
// checklist and the group-table scope badges. /setup/tenants is admin-only;
// the group editor is itself admin-only, so this is safe to call here.
async function ensureTenants() {
    if (window._allTenants) return window._allTenants;
    try {
        const res = await setupFetch('/setup/tenants');
        if (!res.ok) return [];
        const data = await res.json();
        const tenants = data.tenants || [];
        window._allTenants = tenants;
        window._allTenantsName = Object.fromEntries(
            tenants.map(t => [t.id, t.name || t.id]));
        return tenants;
    } catch (_e) {
        window._allTenants = [];
        window._allTenantsName = {};
        return [];
    }
}

async function showGroupModal(groupId) {
    const groups = window._permGroups || {};
    const g = groupId ? (groups[groupId] || {}) : {};
    const perms = g.permissions || {};
    const isAdmin = perms.admin === true || perms.role === 'admin';
    const isTenantAdminGroup = perms.role === 'tenant_admin';
    const rightRows = Object.entries(_RBAC_RIGHT_LABELS).map(([key, label]) => {
        // admin/tenant_admin are stored as role, not a flag — check from the role.
        const checked = key === 'admin' ? isAdmin
            : key === 'tenant_admin' ? isTenantAdminGroup
            : !!perms[key];
        // Compact inline cell (checkbox + label on one line) so the grid packs
        // into 4 columns without the stacked label-above-checkbox making the
        // modal tall — matches the Tenant Scope row style below.
        return `<label class="flex items-center gap-2 text-xs text-slate-600 py-1"><input type="checkbox" id="grp-perm-${key}" ${checked ? 'checked' : ''} class="w-4 h-4 text-indigo-600 border-slate-300 rounded focus:ring-indigo-500">${label}</label>`;
    }).join('');
    // Tenant scope checklist — a group may carry a ``tenants`` list so a single
    // Entra/LDAP group grants BOTH RBAC permissions AND tenant scope. The backend
    // validates each id is a real tenant (drops unknowns), so we list only known
    // tenants here; an id no longer in tenant_state is silently dropped on save.
    await ensureTenants();
    const tenants = window._allTenants || [];
    const granted = new Set(g.tenants || []);
    const tenantRows = tenants.length
        ? tenants.map(t => `<label class="flex items-center gap-2 text-sm text-slate-600 py-1"><input type="checkbox" id="grp-tenant-${t.id}" ${granted.has(t.id) ? 'checked' : ''} class="w-4 h-4 text-indigo-600 border-slate-300 rounded focus:ring-indigo-500"> ${t.name || t.id}</label>`).join('')
        : '<span class="text-[11px] text-slate-400 italic">No tenants defined yet.</span>';
    const modal = document.createElement('div');
    modal.id = 'group-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm';
    modal.innerHTML = `
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-2xl overflow-hidden">
            <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50">
                <h3 class="text-lg font-bold text-[#263040]">${groupId ? 'Edit' : 'New'} Permission Group</h3>
                <button onclick="closeGroupModal()" class="text-slate-400 hover:text-slate-600 transition-colors"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg></button>
            </div>
            <div class="p-6 space-y-4">
                <input type="hidden" id="grp-id" value="${groupId || ''}">
                <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Group Name</label><input type="text" id="grp-name" value="${g.name || ''}" placeholder="e.g. NOC Operators" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-indigo-500"></div>
                <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Description</label><input type="text" id="grp-desc" value="${g.description || ''}" placeholder="Optional" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-indigo-500"></div>
                <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">LDAP Group <span class="text-slate-400 normal-case font-normal">(optional — maps a directory group to this bundle)</span></label><input type="text" id="grp-ldap" value="${g.ldap_group || ''}" placeholder="cn=noc,ou=groups,dc=example,dc=com" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-indigo-500 font-mono"></div>
                <div class="border-t border-slate-200 pt-3"><label class="text-xs text-slate-500 uppercase font-bold">Tenant Scope <span class="text-slate-400 normal-case font-normal">(optional — grants tenant access to members; pairs with Entra/LDAP group login)</span></label><div class="grid grid-cols-2 gap-1 mt-2 max-h-36 overflow-y-auto pr-1">${tenantRows}</div></div>
                <div class="border-t border-slate-200 pt-3"><label class="text-xs text-slate-500 uppercase font-bold">Permissions</label><div class="grid grid-cols-4 gap-x-4 gap-y-1 mt-2">${rightRows}</div></div>
            </div>
            <div class="px-6 py-4 bg-slate-50 border-t border-slate-200 flex justify-end gap-3">
                <button onclick="closeGroupModal()" class="px-4 py-2 text-sm font-medium text-slate-600 hover:text-slate-800 transition-colors">Cancel</button>
                <button onclick="saveGroup()" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm">${groupId ? 'Save' : 'Create'} Group</button>
            </div>
        </div>`;
    document.body.appendChild(modal);
}

function closeGroupModal() {
    const modal = document.getElementById('group-modal');
    if (modal) modal.remove();
}

async function saveGroup() {
    const name = document.getElementById('grp-name').value.trim();
    if (!name) { alert('Please enter a group name'); return; }
    const permissions = {};
    Object.keys(_RBAC_RIGHT_LABELS).forEach(key => {
        if (document.getElementById('grp-perm-' + key)?.checked) permissions[key] = true;
    });
    // Collect granted tenant scope. Sending an explicit list (even empty)
    // replaces the stored set — matches the backend's "list = replace, empty =
    // clear" contract. Unknown ids are dropped server-side.
    const tenants = (window._allTenants || []).map(t => t.id).filter(tid =>
        document.getElementById('grp-tenant-' + tid)?.checked);
    const body = {
        group_id: document.getElementById('grp-id').value || '',
        name,
        description: document.getElementById('grp-desc').value.trim(),
        ldap_group: document.getElementById('grp-ldap').value.trim(),
        permissions,
        tenants,
    };
    try {
        const resp = await setupFetch('/setup/groups', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        if (resp.ok) {
            closeGroupModal();
            await loadGroups();
            await loadUsers();  // effective perms may have shifted
        } else {
            const d = await resp.json().catch(() => ({}));
            alert(d.detail || 'Failed to save group');
        }
    } catch (err) {
        alert('Error saving group: ' + err.message);
    }
}

async function deleteGroup(groupId) {
    const g = (window._permGroups || {})[groupId] || {};
    const n = g.member_count || 0;
    const warn = n > 0 ? `\n\n${n} user(s) are in this group and will be detached.` : '';
    if (!await showConfirmToast(`Delete permission group "${g.name || groupId}"?${warn}`)) return;
    try {
        const resp = await setupFetch(`/setup/groups/${groupId}`, { method: 'DELETE' });
        if (resp.ok) {
            await loadGroups();
            await loadUsers();
        } else {
            const d = await resp.json().catch(() => ({}));
            alert(d.detail || 'Failed to delete group');
        }
    } catch (err) {
        alert('Error deleting group: ' + err.message);
    }
}

// Fill a checklist container (add-user modal) with a checkbox per group.
async function _populateUserGroupChecklist(containerId, selectedIds) {
    const el = document.getElementById(containerId);
    if (!el) return;
    let groups = window._permGroups;
    if (!groups) {
        try {
            const resp = await setupFetch('/setup/groups');
            groups = resp.ok ? (await resp.json()).groups || {} : {};
            window._permGroups = groups;
        } catch { groups = {}; }
    }
    const sel = new Set(selectedIds || []);
    const entries = Object.entries(groups);
    if (entries.length === 0) {
        el.innerHTML = '<span class="text-[11px] text-slate-400 italic">No groups defined — create one below.</span>';
        return;
    }
    el.classList.remove('italic', 'text-slate-400');
    el.innerHTML = entries.map(([gid, g]) => `
        <label class="flex items-center gap-2 px-2 py-1 border border-slate-200 rounded-md cursor-pointer hover:bg-slate-50">
            <input type="checkbox" data-grp="${gid}" ${sel.has(gid) ? 'checked' : ''} class="w-4 h-4 text-indigo-600 border-slate-300 rounded focus:ring-indigo-500">
            <span class="text-xs text-slate-700">${g.name || gid}</span>
        </label>`).join('');
}

function _collectCheckedGroups(containerId) {
    const el = document.getElementById(containerId);
    if (!el) return [];
    return Array.from(el.querySelectorAll('input[data-grp]'))
        .filter(cb => cb.checked).map(cb => cb.getAttribute('data-grp'));
}

// ── API Tokens (Settings → API Tokens) ──────────────────────────────────────
// Self-service Bearer/refresh token management for the logged-in user. Backend:
// POST /auth/token (issue), GET /auth/tokens (list), POST /auth/token/revoke.
async function loadApiTokens() {
    const body = document.getElementById('apitok-table-body');
    if (!body) return;
    try {
        const res = await fetch('/auth/tokens', { credentials: 'same-origin' });
        const data = await res.json();
        const toks = data.tokens || [];
        if (!toks.length) {
            body.innerHTML = '<tr><td colspan="4" class="px-4 py-8 text-center text-slate-400 italic">No API tokens.</td></tr>';
            return;
        }
        const fmt = (s) => s ? new Date(s * 1000).toLocaleString() : '—';
        body.innerHTML = toks.map(t => `
            <tr>
                <td class="px-4 py-3 font-medium text-slate-700">${escapeHtml(t.name || '(unnamed)')}</td>
                <td class="px-4 py-3 text-slate-500">${fmt(t.created)}</td>
                <td class="px-4 py-3 text-slate-500">${fmt(t.expires)}</td>
                <td class="px-4 py-3 text-right"><button onclick="revokeApiToken('${escJsAttr(String(t.id))}')" class="text-xs text-red-600 hover:text-red-700 font-medium">Revoke</button></td>
            </tr>`).join('');
    } catch (e) {
        body.innerHTML = '<tr><td colspan="4" class="px-4 py-6 text-center text-red-400 italic">Failed to load.</td></tr>';
    }
}

async function createApiToken() {
    const btn = document.getElementById('apitok-create-btn');
    const name = (document.getElementById('apitok-name') || {}).value || '';
    if (btn) { btn.disabled = true; btn.textContent = 'Creating…'; }
    try {
        const res = await fetch('/auth/token', {
            method: 'POST', credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || res.status);
        const box = document.getElementById('apitok-new');
        if (box) {
            box.className = 'rounded-md border border-green-300 bg-green-50 p-4 space-y-2 text-xs';
            box.innerHTML = `
                <p class="font-bold text-green-800">Token created — copy these now; they won't be shown again.</p>
                <div><span class="text-slate-500">Access token (Bearer, 4h):</span><code class="block break-all bg-white border border-slate-200 rounded px-2 py-1 mt-1">${escapeHtml(data.access_token)}</code></div>
                <div><span class="text-slate-500">Refresh token (rotate via POST /auth/token/refresh):</span><code class="block break-all bg-white border border-slate-200 rounded px-2 py-1 mt-1">${escapeHtml(data.refresh_token)}</code></div>`;
        }
        const nm = document.getElementById('apitok-name'); if (nm) nm.value = '';
        loadApiTokens();
    } catch (e) {
        if (typeof showToast === 'function') showToast('Create failed: ' + e.message, 'error');
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = 'Create token'; }
    }
}

async function revokeApiToken(id) {
    if (!await (typeof showConfirmToast === 'function'
            ? showConfirmToast('Revoke this API token? Any client using it stops working immediately.')
            : Promise.resolve(confirm('Revoke this API token?')))) return;
    try {
        const res = await fetch('/auth/token/revoke', {
            method: 'POST', credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id }),
        });
        if (!res.ok) { const d = await res.json().catch(() => ({})); throw new Error(d.detail || res.status); }
        if (typeof showToast === 'function') showToast('Token revoked.', 'success');
        loadApiTokens();
    } catch (e) {
        if (typeof showToast === 'function') showToast('Revoke failed: ' + e.message, 'error');
    }
}

async function loadActiveSessions() {
    const tbody = document.getElementById('sessions-table-body');
    if (!tbody) return;
    try {
        const r = await setupFetch('/admin/sessions');
        if (!r.ok) throw new Error(r.statusText);
        const { sessions } = await r.json();
        if (!sessions.length) {
            tbody.innerHTML = `<tr><td colspan="5" class="px-4 py-8 text-center text-slate-400 italic">No active sessions.</td></tr>`;
            return;
        }
        const fmtExpiry = (secs) => {
            if (secs > 3600) return `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m`;
            if (secs > 60)   return `${Math.floor(secs / 60)}m`;
            return `${secs}s`;
        };
        tbody.innerHTML = sessions.map(s => `
            <tr class="hover:bg-slate-50">
                <td class="px-4 py-3 font-medium text-slate-700">${s.user_id}</td>
                <td class="px-4 py-3">
                    ${s.is_admin
                        ? `<span class="px-2 py-0.5 rounded-full bg-green-100 text-green-700 text-[10px] font-bold uppercase">Admin</span>`
                        : `<span class="px-2 py-0.5 rounded-full bg-slate-100 text-slate-500 text-[10px] font-bold uppercase">User</span>`}
                </td>
                <td class="px-4 py-3 text-slate-500 text-xs">${s.tenants.length ? s.tenants.join(', ') : '—'}</td>
                <td class="px-4 py-3 text-slate-500 text-xs">${fmtExpiry(s.expires_in)}</td>
                <td class="px-4 py-3 text-right">
                    <button onclick="revokeSession('${s.sid}')"
                        class="text-xs text-red-400 hover:text-red-600 font-medium">Revoke</button>
                </td>
            </tr>`).join('');
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="5" class="px-4 py-6 text-center text-red-400 italic">Failed to load sessions: ${e.message}</td></tr>`;
    }
}

async function revokeSession(sid) {
    if (!await showConfirmToast(`Revoke session ${sid}?`)) return;
    try {
        const r = await setupFetch(`/admin/sessions/${encodeURIComponent(sid)}`, { method: 'DELETE' });
        const d = await r.json();
        if (r.ok) {
            showToast(d.message || 'Session revoked', 'success');
            loadActiveSessions();
        } else {
            showToast(d.detail || 'Revoke failed', 'error');
        }
    } catch (e) {
        showToast('Revoke error: ' + e.message, 'error');
    }
}

// Human-readable label + tone for each hub-side connection lifecycle event.
// Mirrors the events recorded by Hub.record_spoke_event (core/src/main.py).
const SPOKE_EVENT_LABELS = {
    auth_attempt:        { label: 'Auth attempt',          tone: 'text-slate-600' },
    auth_ok:              { label: 'Authenticated',         tone: 'text-green-600' },
    auth_failed:          { label: 'Auth failed',           tone: 'text-red-600' },
    pending_negotiation:  { label: 'Zero-touch (no secret)', tone: 'text-amber-600' },
    connected:            { label: 'Connected',             tone: 'text-green-600' },
    mutual_auth_complete: { label: 'Mutual auth OK',        tone: 'text-green-600' },
    mutual_auth_skipped:  { label: 'Mutual auth skipped',    tone: 'text-slate-500' },
    mutual_auth_failed:   { label: 'Mutual auth failed',    tone: 'text-red-600' },
    mutual_auth_timeout:  { label: 'Mutual auth timeout',   tone: 'text-red-600' },
    registered:           { label: 'Registered',           tone: 'text-slate-600' },
    pending_approval:     { label: 'Pending approval',      tone: 'text-amber-600' },
    connection_closed:    { label: 'Connection closed',     tone: 'text-amber-600' },
    connection_error:     { label: 'Connection error',       tone: 'text-red-600' },
    replaced_connection:  { label: 'Reconnected (old socket closed)', tone: 'text-amber-600' },
    stale_key_rejected:   { label: 'Stale key rejected',     tone: 'text-red-600' },
    spoke_out_of_contact: { label: 'Out of contact (alert)', tone: 'text-amber-600' },
    spoke_back_in_contact:{ label: 'Back in contact',        tone: 'text-green-600' },
};

// Map a spoke's last_status + authenticated + flapping flags to a single
// diagnostic message that distinguishes the failure modes that previously
// all collapsed to "Never connected — service may not be running".
function spokeStatusMessage(s) {
    if (s.authenticated) {
        return s.approved ? { text: 'Online', tone: 'text-green-600' }
                          : { text: 'Online — pending approval', tone: 'text-amber-600' };
    }
    if (s.flapping) {
        return { text: `Flapping — ${s.recent_drops} drops in 5 min (process alive but not holding connection)`, tone: 'text-red-600' };
    }
    switch (s.last_status) {
        case 'AUTH_FAILED':    return { text: 'Auth failed — secret rejected (retrying / falling back to zero-touch)', tone: 'text-amber-600' };
        case 'PENDING_SECRET':  return { text: 'Zero-touch connected — awaiting admin approval', tone: 'text-amber-600' };
        case 'DISCONNECTED':    return { text: 'Disconnected (clean exit) — likely self-update restart that systemd did not revive', tone: 'text-red-600' };
        case 'ERROR':           return { text: `Connection error: ${s.last_error || 'see hub logs'}`, tone: 'text-red-600' };
        case 'CONNECTED':       return { text: 'Briefly connected then dropped (see event log)', tone: 'text-amber-600' };
        default:
            // After a hub reboot, spoke_telemetry is empty so last_status is
            // UNKNOWN and we land here — but a persisted last_seen (re-seeded
            // into heartbeat.last_seen at startup) still gives a real
            // heartbeat_age_s. Distinguish "was connected recently, hub just
            // rebooted" (amber) from "truly stale / never seen" (red). 15-min
            // (900s) threshold per operator request: red only if last contact
            // was more than 15 minutes ago.
            if (s.heartbeat_age_s != null) {
                const mins = Math.floor(s.heartbeat_age_s / 60);
                const secs = s.heartbeat_age_s % 60;
                const ago = mins > 0 ? `${mins}m ${secs}s ago` : `${secs}s ago`;
                if (s.heartbeat_age_s >= 900) {
                    return { text: `Last seen ${ago} — service may not be running`, tone: 'text-red-600' };
                }
                return { text: `Last seen ${ago} — reconnecting after hub reboot`, tone: 'text-amber-600' };
            }
            return { text: 'Never connected — service may not be running', tone: 'text-red-600' };
    }
}

function spokeEventRow(e) {
    const meta = SPOKE_EVENT_LABELS[e.event] || { label: e.event, tone: 'text-slate-600' };
    const when = new Date(e.ts * 1000).toLocaleTimeString();
    const detail = e.detail ? ` — ${e.detail}` : '';
    return `<div class="py-0.5"><span class="text-slate-400">${when}</span> <span class="${meta.tone} font-medium">${meta.label}</span><span class="text-slate-500">${detail}</span></div>`;
}

function toggleSpokeEvents(spokeId) {
    const panel = document.getElementById(`events-${spokeId}`);
    if (!panel) return;
    panel.classList.toggle('hidden');
}

// Copy a spoke/agent's connection-events panel to the clipboard — same
// clipboard-write + fallback + toast pattern as copyLogs() (Setup → Logs).
async function copySpokeEvents(spokeId) {
    const panel = document.getElementById(`events-${spokeId}`);
    if (!panel) return;
    const text = panel.innerText;
    try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            await navigator.clipboard.writeText(text);
        } else {
            const textArea = document.createElement('textarea');
            textArea.value = text;
            document.body.appendChild(textArea);
            textArea.select();
            try {
                document.execCommand('copy');
            } catch (err) {
                throw new Error('execCommand copy failed');
            }
            document.body.removeChild(textArea);
        }
        if (typeof showToast === 'function') showToast('Events copied to clipboard.', 'success');
    } catch (e) {
        if (typeof showToast === 'function') showToast('Copy failed: ' + e.message, 'error');
    }
}

// Minimal HTML escaper for safely interpolating server-provided strings
// (spoke IDs, error text, module types) into template literals.
function escapeHtml(s) {
    return String(s == null ? '' : s)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// Safe interpolation of a value into an onclick="fn('...')" JS-STRING that sits
// inside an HTML attribute. escapeHtml ALONE is wrong here: the browser decodes
// &#39; back to ' BEFORE the JS parser runs, so a value with an apostrophe breaks
// the handler (or injects). JS-escape backslash + single-quote first, THEN
// HTML-escape for the attribute context.
function escJsAttr(s) {
    return escapeHtml(String(s == null ? '' : s).replace(/\\/g, '\\\\').replace(/'/g, "\\'"));
}

// Watchdog recovery badge for a spoke. The hub's run_spoke_recovery_loop
// restarts stranded units (reset-failed + restart, backoff 60/120/180s) and
// exposes per-spoke state via GET_SPOKE_STATUS + /setup/diagnostics. This maps
// that state to a single colored badge so an operator can see — without CLI —
// whether a spoke is healthy, being recovered, gave up (needs a reinstall), or
// is paused by an admin.
function recoveryBadge(rec) {
    rec = rec || {};
    if (rec.manual_pause) return { text: 'Paused', tone: 'bg-slate-100 text-slate-500', title: 'Recovery paused by admin' };
    if (rec.gave_up)       return { text: 'Gave up', tone: 'bg-red-100 text-red-600', title: `Gave up: ${rec.last_error || 'unknown'}` };
    if (rec.in_progress)  return { text: `Recovering ${rec.attempts}/3`, tone: 'bg-amber-100 text-amber-600', title: `Last action: ${rec.last_action || 'restart'}` };
    if (rec.attempts > 0)  return { text: 'Recovered', tone: 'bg-green-100 text-green-600', title: `Recovered after ${rec.attempts} attempt(s)` };
    return { text: '—', tone: 'bg-slate-50 text-slate-400', title: 'No recovery activity' };
}

async function setRecoveryPause(spokeId, pause) {
    try {
        const res = await setupFetch(`/setup/spoke/${encodeURIComponent(spokeId)}/recovery`, {
            method: 'POST',
            body: JSON.stringify({ pause }),
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        await loadSpokesAndAgents();  // refresh to reflect new badge
    } catch (err) {
        showToast(`Failed to ${pause ? 'pause' : 'resume'} recovery for ${spokeId}: ${err.message}`, 'error');
    }
}

// _diagTelemetryExtras(s, fns) — the diagnostics-only telemetry bits for one
// spoke/agent, factored out of the former standalone Diagnostics tile so the
// Spokes / Agents / Generic Agents management cards can fold them in without
// re-rendering the name / module / approve row they already own. Returns the
// heartbeat-aware status dot plus the telemetry badges (heartbeat · age,
// version, skew, recovery, out-of-contact alert), the status-text + last-error
// meta lines, the Reset Secret / Delete / Recovery Pause / Events action row,
// and the expandable events panel — everything _mgmtEntryCard doesn't already
// get from the management renderer that calls this.
//
// `s` is a /setup/diagnostics entry (true spokes + generic Hub-direct agents)
// or a _normalizePxmxAgent() shape (Proxmox node agents). `fns` selects action
// handlers: spokes + generic agents use the spoke endpoints (defaults);
// Proxmox node agents pass the pxmx relay endpoints, suppress Recovery Pause
// (the hub watchdog is spoke-scoped, not per-agent), and suppress Reset Secret
// (revokeAgent is already the Agents tile's Un-approve button — no duplicate).
function _diagTelemetryExtras(s, fns) {
    fns = fns || {};
    const deleteFn = fns.deleteFn || 'deleteSpoke';
    const allowRecoveryPause = fns.allowRecoveryPause !== false;
    // resetFn/allowReset are no longer consumed here — Reset Secret moved into
    // the spoke Edit modal (openSpokeMetadataModal). Callers may still pass them.
    const status = spokeStatusMessage(s);
    const evCount = (s.events || []).length;
    const rec = s.recovery || {};
    const badge = recoveryBadge(rec);
    // Heartbeat: status color + age since last heartbeat frame.
    const hbStatus = String(s.heartbeat_status || '');
    const hbAge = (s.heartbeat_age_s == null) ? 'never'
               : (s.heartbeat_age_s === 0 ? 'now' : `${s.heartbeat_age_s}s`);
    const hbBadgeTone = hbStatus === 'GREEN' ? 'bg-green-100 text-green-700'
                      : hbStatus === 'YELLOW' ? 'bg-amber-100 text-amber-700'
                      : 'bg-red-100 text-red-700';
    // Out-of-contact alert badge (SpokeAlertMixin) — separate, forgiving tier
    // (warning >=5m / error >=30m) distinct from the realtime heartbeat light.
    const aTier = String(s.alert_tier || '');
    const alertBadge = (aTier === 'error' || aTier === 'warning')
        ? `<span class="text-[10px] px-2 py-0.5 rounded-full font-bold uppercase ${aTier === 'error' ? 'bg-red-100 text-red-700' : 'bg-amber-100 text-amber-700'}" title="Out of contact ${Math.round((s.alert_duration_s || 0) / 60)}m — forgiving alert tier (separate from the heartbeat light)">alert · ${aTier}</span>`
        : '';
    // Version chip color: GREEN = up to date, RED = out of date, slate =
    // unknown (no telemetry to compare against). "Out of date" is EITHER of two
    // signals, both hub-computed: version_behind (spoke's .NN is older than the
    // latest .NN the hub knows for ITS repo — a genuine "newer build exists")
    // OR version_skew (reported version isn't on the .NN numbering at all — a
    // stale X.Y.Z / v-tag / pre-reset value). Folds both into the version chip.
    const _ver = s.version || 'unknown';
    const _verUnknown = !s.version || _ver === 'unknown';
    const _behind = !!s.version_behind;
    const _stale = !!s.version_skew;
    const _outOfDate = _behind || _stale;
    const _verTone = _verUnknown ? 'bg-slate-100 text-slate-600'
                   : (_outOfDate ? 'bg-red-100 text-red-700' : 'bg-green-100 text-green-700');
    const _verTitle = _verUnknown ? 'Version unknown — no telemetry to compare'
                    : _behind ? ('Out of date — running ' + _ver + ' / latest ' + (s.latest_version || '?'))
                    : _stale ? 'Out of date — behind the current .NN version'
                    : 'Up to date';
    // Heartbeat-aware status dot: green = healthy & beating, amber = slow-but-
    // live, red = offline/never/RED, slate = no heartbeat telemetry yet. The
    // management renderers use this in place of their approval-only dot when
    // telemetry is available AND the spoke is approved/connected — a pending
    // spoke keeps its amber approval dot (heartbeat is meaningless pre-approval)
    // but an approved-but-silent spoke goes red even though it is approved.
    const dot = !s.authenticated
              // Offline: red only if we have NO recent last-seen, or last contact
              // was >15 min ago. A spoke that was connected seconds before a hub
              // reboot (persisted last_seen re-seeded at startup → real
              // heartbeat_age_s) shows amber, not red — it's almost certainly
              // reconnecting, not dead.
              ? ((s.heartbeat_age_s != null && s.heartbeat_age_s < 900) ? 'bg-amber-400' : 'bg-red-500')
              : hbStatus === 'GREEN' ? 'bg-green-500 shadow-[0_0_6px_rgba(34,197,94,0.5)]'
              : hbStatus === 'YELLOW' ? 'bg-amber-400'
              : hbStatus === 'RED' ? 'bg-red-500'
              : 'bg-slate-300';
    const isPaused = !!rec.manual_pause;
    const pauseLabel = isPaused ? 'Resume' : 'Pause';
    const eSid = s.spoke_id.replace(/'/g, "\\'");
    return {
        dot,
        // Raw {text, tone} so the caller can render the Online/Offline status
        // INLINE on the host/tenant row (one line) instead of its own stacked
        // div — saves vertical space on the Spokes & Agents tiles.
        status,
        badges: [
            `<span class="text-[10px] px-2 py-0.5 rounded-full font-bold uppercase ${hbBadgeTone}" title="Time since last inbound heartbeat frame (GREEN &lt;120s, YELLOW 120–300s, RED &gt;=300s/never)">${hbStatus || '—'} · ${hbAge}</span>`,
            `<span class="text-[10px] px-2 py-0.5 rounded-full font-bold uppercase font-mono ${_verTone}" title="${_verTitle}">${escapeHtml(_ver)}</span>`,
            `<span class="text-[10px] px-2 py-0.5 rounded-full font-bold uppercase ${badge.tone}" title="${escapeHtml(badge.title)}">${badge.text}</span>`,
            alertBadge,
        ],
        metaLines: [
            // status text moved INLINE to the caller's host/tenant row.
            s.last_error ? `<div class="text-[10px] text-red-500 font-mono pl-6 break-all">${escapeHtml(s.last_error)}</div>` : '',
        ],
        actions: [
            // Reset Secret moved into the spoke Edit modal (openSpokeMetadataModal)
            // to declutter the row; pxmx agents never showed it (allowReset=false),
            // so removing it here changes nothing for the Agents card.
            _mgmtBtn('Delete', `${deleteFn}('${eSid}')`, 'bg-red-600 hover:bg-red-700 text-white'),
            allowRecoveryPause
                ? _mgmtBtn(pauseLabel, `setRecoveryPause('${eSid}', ${!isPaused})`, isPaused ? 'text-green-600' : 'text-slate-400 hover:underline')
                : '',
        ],
        // Events (+ Copy) pinned to the far right of the header row (next to the
        // ID) via _mgmtEntryCard's cornerActions slot, not the bottom action row.
        eventsActions: [
            `<button onclick="toggleSpokeEvents('${eSid}')" class="text-blue-500 hover:text-blue-700 font-medium text-xs">${evCount} events ▾</button>`,
            evCount ? `<button onclick="copySpokeEvents('${eSid}')" class="text-xs text-blue-500 hover:text-blue-700 font-medium">Copy</button>` : '',
        ],
        eventsPanel: `<div id="events-${s.spoke_id}" class="hidden font-mono text-[11px] bg-slate-50 border border-slate-200 rounded p-3 max-h-56 overflow-y-auto ml-6 mt-1">${(s.events || []).map(spokeEventRow).join('') || '<span class="text-slate-400 italic">No connection events recorded.</span>'}</div>`,
    };
}

// Map a Proxmox node agent (from /api/pxmx/agents) into the same telemetry
// shape spokes/generic-agents use, so _diagTelemetryExtras can fold its
// heartbeat/version into the Agents card the same way it does for spokes.
// These agents connect through the pxmx hypervisor spoke; the pxmx spoke now
// relays their AGENT_HEARTBEAT up, so the hub HeartbeatManager tracks them
// (keyed spoke_id:agent_id) and /api/pxmx/agents carries heartbeat_status +
// heartbeat_age_s. We fall back to the spoke's own last_seen so a freshly-seen
// agent still shows a status before the first relayed beat lands. Recovery/
// events stay empty/neutral (the watchdog is spoke-scoped, not per-agent).
// True when v is a bare per-repo ".NN" version (e.g. ".33"). Each repo's .NN
// is an independent bump counter, so a component .NN differing from the hub's
// .NN is normal; SKEW now flags only versions NOT in this shape (stale X.Y.Z /
// v-tag / pre-reset). Mirrors the backend _is_nn check in api.py get_diagnostics.
function _isNN(v) { return /^\.\d+$/.test(String(v == null ? '' : v).trim()); }

function _normalizePxmxAgent(a) {
    const connected = a._status === 'connected';
    let hbStatus = a.heartbeat_status || '';
    let hbAge = a.heartbeat_age_s;
    if ((hbAge == null || !hbStatus) && typeof a.last_seen === 'number') {
        const age = Math.max(0, Math.floor(Date.now() / 1000 - a.last_seen));
        if (hbAge == null) hbAge = age;
        if (!hbStatus) hbStatus = age < 120 ? 'GREEN' : age < 300 ? 'YELLOW' : 'RED';
    }
    const ver = a.version || a.sw_version || 'unknown';
    return {
        spoke_id: a.agent_id,
        display_name: a.display_name || a.hostname || a.agent_id,
        // A connected pxmx-hosted agent is by definition approved — it only
        // reaches connected_agents on the spoke after authenticating with the
        // real secret, which it only has post-approval. The raw agent object
        // from GET_AGENTS never carries an explicit "approved" field (only
        // hub.approved_modules does, which isn't merged in here), so without
        // this, spokeStatusMessage() saw authenticated=true + approved=false
        // and showed "Online — pending approval" next to an already-green
        // "Connected" badge.
        approved: connected || !!a.approved,
        authenticated: connected,
        connection_state: connected ? 'CONNECTED' : 'PENDING',
        module_type: 'pxmx',
        version: ver,
        version_skew: ver !== 'unknown' && !_isNN(ver),
        heartbeat_status: hbStatus,
        heartbeat_age_s: hbAge,
        last_status: connected ? '' : 'PENDING_SECRET',
        last_error: null,
        flapping: false,
        recent_drops: 0,
        events: [],
        recovery: {},
        _kind: 'pxmx',
    };
}

// ── Log collapse / counter ────────────────────────────────────────────────
//
// Repeating log lines (e.g. the per-minute `NetboxSpoke - INFO - NetBox
// command: NETBOX_GET_PREFIXES` poll) are collapsed into a single row with a
// "×N" counter so a chatty event doesn't drown the view. Two lines group
// together when they are identical EXCEPT for the leading timestamp — the
// operator's "same event, different timestamp" rule. Each group renders once,
// at the position of its first (newest) occurrence; click the row to expand
// and see every occurrence with its own timestamp. Copy still emits every raw
// line with its timestamp (copyLogs reads container._rawLogs, not innerText),
// so the collapse is a display concern only — no data is lost.

// Grouping key for collapsing repeats. The DISPLAYED row is always the
// original line (with its real timestamp/uuid/counters); only this collapse
// KEY is normalized, so no data is lost — expanding a ×N group shows every
// occurrence verbatim. We normalize the per-instance parts that vary between
// otherwise-identical lines so "same event, different timestamp/uuid/counter"
// lines collapse into one ×N row (the operator's "combine all the common
// ones" rule):
//   1. leading `[source] ` prefix + leading `YYYY-MM-DD HH:MM:SS - ` timestamp
//      (the original de-dup keys; tolerate ,ms/.ms fractional seconds some
//      loggers append). Without stripping these the timestamp landed INSIDE
//      the key and every occurrence was unique, so spoke logs never collapsed.
//   2. UUIDs (8-4-4-4-12) — the per-request msg_id in `Request Timeout: [CMD]
//      <uuid> from <spoke>`, the `Request: <uuid> -> ...` debug id, the `Late
//      reply for <uuid>` id. Random correlation ids, never meaningful.
//   3. durations with a time unit (5.0s / 160s / 30ms) — timeout/backoff/
//      elapsed values that vary per occurrence (`Reconnecting in 160s`,
//      `after 5.0s`).
//   4. key=N counters (queue=16 / uptime_s=0 / count=5) — per-tick metrics in
//      heartbeat/telemetry lines.
// Identifiers that merely CONTAIN digits (cs-svr-03-spoke, lm-agent-opnsense,
// module=firewall, spoke_id=lm-agent) are NOT touched — they are not a leading
// [source]/timestamp, not a UUID, not a bare digit+time-unit, and not key=N
// (the value isn't digits) — so different spokes/modules/reasons still group
// SEPARATELY; only the noisy metrics within one spoke's stream collapse.
/**
 * Normalize a log line into a stable grouping key so identical-repeat events
 * (same source/level/message, differing only by timestamp/UUID/duration/counter)
 * collapse into one ×N row in the log view. Strips: leading [source] prefix,
 * leading timestamp (+optional ,ms/.ms), per-request UUIDs, durations
 * (`5.0s`/`30ms`), and `key=<N>` counter values. Two lines that differ ONLY in
 * those fields share a key and are grouped by `_renderGroupedLogs`.
 * @param {string} log - raw single log line
 * @returns {string} grouping key
 */
function _logLineKey(log) {
    return String(log)
        // Normalize the legacy two-line relay shape
        //   "[src] <ts> <name> <LEVEL>\n<msg>"   (space-sep, msg on next line)
        // to the canonical single-line shape
        //   "[src] <ts> - <name> - <LEVEL> - <msg>"
        // so both on-the-wire formats key identically and group together.
        // Some spokes (older cs builds) still relay uvicorn.access this way;
        // the canonical dash-sep shape is left untouched (it has no newline
        // right after the level, so this regex won't match it).
        .replace(/^(\[[^\]]*\]\s*)?(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(\S+)\s+([A-Z]+)[ \t]*\r?\n/, '$1$2 - $3 - $4 - ')
        .replace(/^\[[^\]]*\]\s*/, '')                                       // leading [source] prefix
        .replace(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:[,.]\d+)?\s*-\s*/, '')  // timestamp (+ optional ,ms/.ms)
        .replace(/\b\d{1,3}(?:\.\d{1,3}){3}:\d+\b/g, '<addr>')               // client IP:port (uvicorn.access) — ephemeral port varies per request
        .replace(/\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g, '<uuid>')  // per-request UUID (Request Timeout / Request / Late reply)
        .replace(/\b\d+(?:\.\d+)?(?:ms|s|us)\b/g, '<T>')                      // duration (5.0s / 160s / 30ms)
        .replace(/(\b\w+)=\d+\b/g, '$1=<N>');                                 // counter (queue=16 / uptime_s=0)
}

// One log line → a highlighted row. `count` (>1) adds a "×N" badge and wires the
// click-to-expand handler used by grouped rows. `lineRowFn` override lets the
// recovery view pass its own GAVE_UP styling while still collapsing repeats.
function _renderLogLineRow(log, count, lineRowFn) {
    if (lineRowFn) return lineRowFn(log, count);
    const u = log.toUpperCase();
    let cls = 'text-slate-600';
    let bg = 'hover:bg-slate-50';
    if (u.includes(' ERROR ') || u.includes(' CRITICAL ')) { cls = 'text-red-700 font-semibold'; bg = 'bg-red-50 hover:bg-red-100'; }
    else if (u.includes(' WARNING ') || u.includes(' WARN ')) { cls = 'text-amber-700'; bg = 'bg-amber-50 hover:bg-amber-100'; }
    else if (u.includes(' DEBUG ')) { cls = 'text-slate-400'; }
    // Highlight timestamp + source for both prefixed spoke logs
    // (`[lm-svcs-netbox] <ts> - Source - LEVEL - msg`) and bare hub logs
    // (`<ts> - Source - LEVEL - msg`). Also accept the legacy two-line relay
    // shape (`[src] <ts> <name> <LEVEL>\n<msg>` — space-sep, no dashes, message
    // on the next line) so older cs spoke builds render with the same
    // header + indented-message display and collapse via _logLineKey.
    const tsMatch = log.match(/^(?:\[([^\]]*)\]\s*)?(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) - ([^-]+?) - ([A-Z]+) - ([\s\S]*)$/)
        || log.match(/^(?:\[([^\]]*)\]\s*)?(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(\S+)\s+([A-Z]+)[ \t]*\r?\n([\s\S]*)$/);
    const badge = count && count > 1
        ? `<span class="ml-2 px-1.5 py-0.5 rounded-full text-[9px] font-bold bg-slate-200 text-slate-600 align-middle whitespace-nowrap" title="${count} identical events (same except timestamp) — click to expand">×${count}</span>`
        : '';
    // Keep the onclick as its OWN attribute — embedding `onclick="..."` inside
    // the double-quoted class attribute lets the inner `"` close class early so
    // the handler is silently swallowed and clicks never fire.
    const isGroup = count && count > 1;
    const clsExtra = isGroup ? ' cursor-pointer select-none' : '';
    const onClick = isGroup ? ' onclick="toggleLogGroup(this)"' : '';
    // Header (source + timestamp + logger + level + ×N badge) on the first
    // line, the message payload on a second indented line — easier to scan a
    // long trail than one long wrapped line. copyLogs reads the raw array, so
    // Copy still emits the original single-line `<ts> - Source - LEVEL - msg`.
    if (tsMatch) {
        const head = `${tsMatch[1] ? `<span class="text-slate-400">[${tsMatch[1]}]</span> ` : ''}<span class="text-slate-400">${tsMatch[2]}</span> <span class="text-indigo-500 font-semibold">${tsMatch[3].trim()}</span> <span class="opacity-60">${tsMatch[4]}</span>${badge}`;
        return `<div class="px-4 py-0.5 border-b border-slate-100 text-xs font-mono ${cls} ${bg}${clsExtra}"${onClick}>${head}<div class="pl-4 mt-0.5 break-all">${tsMatch[5]}</div></div>`;
    }
    return `<div class="px-4 py-0.5 border-b border-slate-100 text-xs font-mono ${cls} ${bg}${clsExtra}"${onClick}>${log}${badge}</div>`;
}

// Group `logs` (newest-first) by message key; render each group once at its
// first-occurrence position. Single-occurrence lines render as a plain row.
function _renderGroupedLogs(logs, lineRowFn) {
    const groups = [];
    const byKey = new Map();
    for (const log of logs) {
        const key = _logLineKey(log);
        let g = byKey.get(key);
        if (!g) { g = { key, lines: [] }; byKey.set(key, g); groups.push(g); }
        g.lines.push(log);
    }
    return groups.map(g => {
        if (g.lines.length === 1) return _renderLogLineRow(g.lines[0], 1, lineRowFn);
        // Header = newest occurrence + ×N badge; expand block = the remaining
        // N-1 older occurrences (header already shows the newest, so no dup).
        const header = _renderLogLineRow(g.lines[0], g.lines.length, lineRowFn);
        const expanded = g.lines.slice(1).map(l => _renderLogLineRow(l, 1, lineRowFn)).join('');
        return `<div class="log-group">${header}<div class="log-group-expanded hidden">${expanded}</div></div>`;
    }).join('');
}

// Click handler for a grouped log header: toggle the expand block. Walk up to
// the .log-group wrapper and find its .log-group-expanded child — robust to the
// header row containing nested elements (badge span, second-line payload div)
// and to the click landing on any of them.
function toggleLogGroup(headerEl) {
    const group = headerEl.closest ? headerEl.closest('.log-group') : null;
    if (!group) return;
    const block = group.querySelector('.log-group-expanded');
    if (block) block.classList.toggle('hidden');
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
        // Reverse so newest entries are at the top (log files are oldest-first on disk)
        const logs = (data.logs || []).slice().reverse();

        if (logs.length === 0) {
            container.innerHTML = `<div class="py-12 text-center text-slate-400 italic">No logs available for ${module}.</div>`;
            return;
        }

        if (module === 'agents' && !Array.isArray(logs)) {
            // Flatten every agent's lines so copyLogs emits all of them with
            // timestamps regardless of the per-agent collapse state below.
            container._rawLogs = Object.values(logs).flat();
            container.innerHTML = Object.entries(logs).map(([agentId, agentLogs]) => `
                <div class="mb-6">
                    <div class="px-4 py-2 bg-slate-100 border-b border-slate-200 text-xs font-bold text-slate-500 uppercase tracking-widest flex justify-between">
                        <span>Agent: ${agentId}</span>
                        <span class="opacity-60">Count: ${agentLogs.length}</span>
                    </div>
                    <div class="divide-y divide-slate-100">
                        ${_renderGroupedLogs(agentLogs)}
                    </div>
                </div>
            `).join('');
        } else {
            // Store the raw (timestamped) lines so copyLogs can emit every one
            // — the collapsed view's innerText only shows one row per group.
            container._rawLogs = logs;
            container.innerHTML = _renderGroupedLogs(logs);
        }

    } catch (err) {
        console.error(`Error loading ${module} logs:`, err);
        if (!isRefresh) {
            container.innerHTML = `<div class="py-12 text-center text-red-500 font-medium">Error loading ${module} logs: ${err.message}</div>`;
        }
    }
}

async function clearLogs(refreshFn) {
    // Destructive + fleet-wide: clears the hub's in-memory deque, every
    // relayed agent/spoke deque, the on-disk /var/log/lm/*.log files on the
    // hub box, AND broadcasts CLEAR_LOGS to every connected spoke so each
    // remote box truncates its own on-disk logs. Admin-only server-side.
    // After clearing, refresh the current tab (the loader passed in) so the
    // view empties immediately instead of showing the stale cached lines.
    if (!confirm('Clear ALL logs?\n\nThis wipes the hub logs, every agent/spoke log buffer, and the on-disk /var/log/lm/*.log files on the hub AND every connected spoke. This cannot be undone.')) {
        return;
    }
    try {
        const resp = await fetch('/setup/logs/clear', { method: 'POST' });
        if (!resp.ok) {
            throw new Error(`HTTP ${resp.status}`);
        }
        const data = await resp.json().catch(() => ({}));
        const n = (data.disk_files_truncated || []).length;
        if (typeof showToast === 'function') {
            showToast(`Cleared logs: ${data.hub_lines || 0} hub + ${data.agent_lines || 0} agent/spoke lines, ${n} file(s) on disk, broadcast to ${data.spokes_broadcast || 0} spoke(s).`, 'success');
        }
        if (typeof refreshFn === 'function') refreshFn();
    } catch (err) {
        console.error('Clear logs failed:', err);
        if (typeof showToast === 'function') showToast('Failed to clear logs: ' + err.message, 'error');
    }
}

async function copyLogs() {
    const container = document.getElementById('system-logs-container');
    if (!container) return;

    // Copy EVERY raw log line with its timestamp — not the collapsed view's
    // innerText (which only shows one row per repeated group). The collapse is
    // a display concern; Copy emits the full trail so an incident paste has all
    // occurrences. Falls back to innerText for views that don't set _rawLogs.
    const raw = container._rawLogs;
    const text = Array.isArray(raw) ? raw.join('\n') : container.innerText;
    try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            await navigator.clipboard.writeText(text);
        } else {
            const textArea = document.createElement('textarea');
            textArea.value = text;
            document.body.appendChild(textArea);
            textArea.select();
            try {
                document.execCommand('copy');
            } catch (err) {
                throw new Error('execCommand copy failed');
            }
            document.body.removeChild(textArea);
        }
        if (typeof showToast === 'function') showToast('Logs copied to clipboard.', 'success');
    } catch (err) {
        if (typeof showToast === 'function') showToast('Failed to copy logs: ' + err.message, 'error');
    }
}

async function toggleDebugLogging() {
    try {
        const statusRes = await setupFetch('/setup/debug-mode');
        const statusData = await statusRes.json();
        const newState = !statusData.enabled;

        const response = await setupFetch('/setup/debug-mode', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: newState })
        });

        if (!response.ok) throw new Error('Failed to toggle debug mode');
        const data = await response.json();

        updateDebugButtonUI(data.enabled);
        alert(`Debug logging has been ${data.enabled ? 'ENABLED' : 'DISABLED'} for all systems.`);
    } catch (err) {
        alert('Error toggling debug mode: ' + err.message);
    }
}

function updateDebugButtonUI(enabled) {
    const btn = document.getElementById('debug-toggle-btn');
    const text = document.getElementById('debug-mode-text');
    if (!btn || !text) return;

    if (enabled) {
        btn.className = 'text-[10px] bg-green-600 text-white border border-green-700 px-2 py-1 rounded hover:bg-green-700 transition-colors font-bold flex items-center gap-1';
        text.textContent = 'Debug Logging: ON';
    } else {
        btn.className = 'text-[10px] bg-white border border-slate-300 px-2 py-1 rounded hover:bg-slate-50 transition-colors font-medium flex items-center gap-1';
        text.textContent = 'Debug Logging: OFF';
    }
}

async function refreshDebugButtonState() {
    try {
        const response = await setupFetch('/setup/debug-mode');
        if (response.ok) {
            const data = await response.json();
            updateDebugButtonUI(data.enabled);
        }
    } catch (err) {
        console.error('Error refreshing debug button state:', err);
    }
}

async function loadApprovedSpokes() {
    try {
        // Global Admins read the full roster (/setup/pending_spokes, admin-only);
        // tenant-admins read only the spokes they may bind to via the
        // session-scoped /tenant/devices/spokes (same row shape).
        const response = await setupFetch(isAdmin() ? '/setup/pending_spokes' : '/tenant/devices/spokes');
        if (!response.ok) throw new Error('Failed to fetch spokes');
        const data = await response.json();
        return (data.spokes || []).filter(s => s.approved);
    } catch (err) {
        console.error('Error loading approved spokes:', err);
        return [];
    }
}

async function fetchLoadedRoles(spokeId) {
    // Fetch the roles a generic agent is currently hosting (GET_AVAILABLE_ROLES
    // via the generic command relay). Returns the `active` list (possibly empty).
    try {
        const res = await fetch(`/api/agent/${encodeURIComponent(spokeId)}/command`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ command: 'GET_AVAILABLE_ROLES' }),
        });
        if (!res.ok) return [];
        const data = await res.json();
        return Array.isArray(data.active) ? data.active : [];
    } catch (e) { return []; }
}

// Deploy-role status for a generic agent (netbox-server, bugfixer). Returns
// { deploy, active_role, netbox_installed } or null. netbox_installed survives
// an agent reload, so it's the durable gate for the reset-admin-password knob.
async function fetchDeployStatus(spokeId) {
    try {
        const res = await fetch(`/api/agent/${encodeURIComponent(spokeId)}/command`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ command: 'GET_DEPLOY_STATUS' }),
        });
        if (!res.ok) return null;
        return await res.json();
    } catch (e) { return null; }
}

// Prompt for a new NetBox admin password and reset it on the node that ran the
// netbox-server role (via the agent's NETBOX_RESET_ADMIN_PASSWORD command).
async function resetNetboxAdmin(spokeId) {
    const pw = await showPromptToast(
        `New NetBox admin password for ${spokeId}:`,
        { type: 'password', placeholder: 'new admin password', confirmLabel: 'Reset' });
    if (pw === null) return;                 // cancelled
    if (!pw || pw.length < 4) { showToast('Password must be at least 4 characters.', 'error'); return; }
    showToast(`Resetting NetBox admin password on ${spokeId}…`, 'info');
    try {
        const res = await fetch(`/api/agent/${encodeURIComponent(spokeId)}/command`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ command: 'NETBOX_RESET_ADMIN_PASSWORD', data: { password: pw } }),
        });
        const data = await res.json();
        if (res.ok && data.status === 'SUCCESS') {
            showToast(data.message || 'NetBox admin password reset.', 'success');
        } else {
            showToast(`Reset failed: ${data.detail || data.message || JSON.stringify(data)}`, 'error');
        }
    } catch (err) {
        showToast(`Reset failed: ${err.message}`, 'error');
    }
}

async function showLoadRoleModal(spokeId) {
    const existing = document.getElementById('load-role-modal');
    if (existing) existing.remove();

    const modal = document.createElement('div');
    modal.id = 'load-role-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50 backdrop-blur-sm p-4';
    modal.innerHTML = `
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-xl overflow-hidden border border-slate-200">
            <div class="px-6 py-4 bg-slate-50 border-b border-slate-200 flex justify-between items-center">
                <div>
                    <h3 class="text-lg font-bold text-slate-800">Load Role</h3>
                    <p class="text-xs text-slate-500 mt-0.5 font-mono">${spokeId}</p>
                </div>
                <button onclick="document.getElementById('load-role-modal').remove()" class="text-slate-400 hover:text-slate-600 transition-colors">
                    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                </button>
            </div>
            <div class="p-6 space-y-4">
                <p class="text-xs text-slate-500">A generic agent can host <strong>multiple roles at once</strong>. Each role opens its own sub-spoke (<code class="bg-slate-100 px-1 rounded">${spokeId}-&lt;role&gt;</code>) that auto-approves via this agent.</p>
                <div id="role-list" class="grid grid-cols-2 gap-2 max-h-60 overflow-y-auto pr-1">
                    <p class="text-xs text-slate-400 italic col-span-2">Loading roles…</p>
                </div>
                <div id="netbox-admin-creds" class="hidden p-3 bg-slate-50 border border-slate-200 rounded-md space-y-2">
                    <p class="text-xs font-semibold text-slate-700">NetBox admin account</p>
                    <input id="nb-admin-user" type="text" value="admin" placeholder="admin username" autocomplete="off"
                        class="w-full px-3 py-1.5 text-sm border border-slate-300 rounded-md focus:ring-1 focus:ring-green-500 focus:border-green-500">
                    <input id="nb-admin-pass" type="password" placeholder="admin password (blank = auto-generate)" autocomplete="new-password"
                        class="w-full px-3 py-1.5 text-sm border border-slate-300 rounded-md focus:ring-1 focus:ring-green-500 focus:border-green-500">
                    <p class="text-[11px] text-slate-500">Sets the NetBox WebUI login. Leave blank to auto-generate (shown in the deploy log).</p>
                </div>
                <p id="role-desc" class="text-xs text-slate-500 italic min-h-[1.5rem]"></p>
                <div id="role-note" class="p-3 bg-amber-50 border border-amber-200 rounded-md text-xs text-amber-800">
                    The agent installs required system packages (e.g. unbound, kea, certbot) and hosts the role as a new sub-spoke. This may take 30–60 seconds per role.
                </div>
            </div>
            <div class="px-6 py-4 bg-slate-50 border-t border-slate-200 flex justify-end gap-3">
                <button onclick="document.getElementById('load-role-modal').remove()"
                    class="px-4 py-2 text-sm font-medium text-slate-600 hover:text-slate-800 transition-colors">Cancel</button>
                <button onclick="loadRole('${spokeId}')"
                    class="bg-[#01A982] hover:bg-[#008c6a] text-white px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm">Activate Selected</button>
            </div>
        </div>`;
    document.body.appendChild(modal);

    const active = await fetchLoadedRoles(spokeId);
    const loadedByRole = new Map((active || []).map(a => [a.role, a]));
    const list = document.getElementById('role-list');
    const rows = Object.entries(AGENT_ROLES).map(([id, r]) => {
        const loaded = loadedByRole.get(id);
        if (loaded) {
            return `
                <div class="flex items-center justify-between gap-3 p-2 rounded-md bg-green-50 border border-green-200">
                    <label class="flex items-center gap-2 text-sm text-slate-700 flex-1 min-w-0">
                        <span class="font-medium truncate">${r.name}</span>
                        <span class="px-1.5 py-0.5 rounded-full text-[10px] font-bold bg-green-600 text-white shrink-0">loaded</span>
                    </label>
                    <button onclick="unloadRole('${spokeId}','${id}')"
                        class="text-xs font-bold text-red-600 hover:text-red-700 transition-colors shrink-0">Unload</button>
                </div>`;
        }
        const deployNote = r.deploy ? ' (background deploy — own service)' : '';
        return `
            <label class="flex items-center gap-2 p-2 rounded-md border border-slate-200 hover:bg-slate-50 transition-colors cursor-pointer" onfocus="updateRoleDesc('${id}')" onmouseover="updateRoleDesc('${id}')">
                <input type="checkbox" value="${id}" class="role-check w-4 h-4 rounded text-[#01A982] focus:ring-green-500" onchange="updateRoleDesc('${id}')">
                <span class="text-sm text-slate-700 font-medium">${r.name}${deployNote}</span>
            </label>`;
    }).join('');
    list.innerHTML = rows || '<p class="text-xs text-slate-400 italic col-span-2">No roles available.</p>';
}

// Show the NetBox admin-account inputs only while the netbox-server role is
// checked — the deploy passes them through to install.sh as the admin login.
function syncNetboxCreds() {
    const cb = document.querySelector('.role-check[value="netbox-server"]');
    const creds = document.getElementById('netbox-admin-creds');
    if (creds) creds.classList.toggle('hidden', !(cb && cb.checked));
}

function updateRoleDesc(roleId) {
    syncNetboxCreds();
    const r = AGENT_ROLES[roleId];
    const desc = document.getElementById('role-desc');
    if (desc) desc.textContent = r?.desc || '';
    const note = document.getElementById('role-note');
    if (note) {
        if (r?.deploy) {
            note.innerHTML = `The agent runs the role's install script in the background and stays online as a generic agent. The deployed service installs as a systemd unit and connects to the Hub as its own agent. This can take a few minutes; watch <strong>Setup → Spokes & Agents</strong> for the new agent to appear.`;
        } else {
            note.textContent = `The agent installs required system packages (e.g. unbound, kea, certbot) and hosts the role as a new sub-spoke, auto-approved via this agent. This may take 30–60 seconds; the new spoke appears in Spokes & Agents as Connected.`;
        }
    }
}

async function loadRole(spokeId) {
    const checked = Array.from(document.querySelectorAll('.role-check:checked')).map(el => el.value);
    if (checked.length === 0) { showToast('Select at least one role to load.', 'info'); return; }

    const btn = document.querySelector('#load-role-modal button[onclick^="loadRole"]');
    if (btn) { btn.disabled = true; btn.textContent = 'Activating…'; }

    // Collect the NetBox admin account (if the netbox-server role is selected)
    // BEFORE the loop removes the modal; passed as LOAD_ROLE config → install.sh.
    let netboxCfg = null;
    if (checked.includes('netbox-server')) {
        const u = document.getElementById('nb-admin-user')?.value.trim();
        const p = document.getElementById('nb-admin-pass')?.value;
        netboxCfg = {};
        if (u) netboxCfg.admin_user = u;
        if (p) netboxCfg.admin_password = p;
    }

    const results = [];
    for (const roleId of checked) {
        try {
            const body = { role: roleId };
            if (roleId === 'netbox-server' && netboxCfg && Object.keys(netboxCfg).length) {
                body.config = netboxCfg;
            }
            const res = await fetch(`/api/agent/${encodeURIComponent(spokeId)}/load-role`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body),
            });
            const data = await res.json();
            const name = AGENT_ROLES[roleId]?.name || roleId;
            if (res.ok && data.status === 'SUCCESS') {
                if (data.deploy) {
                    results.push(`✓ ${name}: deployment started (watch Spokes & Agents)`);
                } else {
                    results.push(`✓ ${name}: sub-spoke ${data.sub_spoke_id || spokeId + '-' + roleId} connecting (auto-approved)`);
                }
            } else {
                const msg = res.status === 503
                    ? 'agent not connected — reconnect it to manage roles'
                    : (data.detail || data.message || JSON.stringify(data));
                results.push(`✗ ${name}: ${msg}`);
            }
        } catch (err) {
            results.push(`✗ ${AGENT_ROLES[roleId]?.name || roleId}: ${err.message}`);
        }
    }
    document.getElementById('load-role-modal')?.remove();
    const anyFailed = results.some(r => r.startsWith('✗'));
    showToast(`Role activation on ${spokeId}:\n${results.join('\n')}`, anyFailed ? 'error' : 'success');
    // Refresh the Spokes & Agents table so the Active Role column updates
    // (generic nodes are now managed there, not a separate Generic Nodes tile).
    if (currentView === 'setup') loadSpokesAndAgents();
}

async function unloadRole(spokeId, role) {
    const roleLabel = AGENT_ROLES[role]?.name || role;
    if (!await showConfirmToast(`Unload role "${roleLabel}" from ${spokeId}? Its sub-spoke will disconnect.`)) return;
    // Only reopen the Load Role modal if the unload was triggered from inside it
    // (not from the per-role Unload action on a Spokes row).
    const modalOpen = !!document.getElementById('load-role-modal');
    try {
        const res = await fetch(`/api/agent/${encodeURIComponent(spokeId)}/command`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ command: 'UNLOAD_ROLE', data: { role } }),
        });
        const data = await res.json();
        if (res.ok && (data.status === 'SUCCESS' || data.payload?.status === 'SUCCESS')) {
            showToast(`Role "${roleLabel}" unloaded from ${spokeId}`, 'success');
            if (currentView === 'setup') loadSpokesAndAgents();
            if (modalOpen) showLoadRoleModal(spokeId);
        } else {
            const msg = res.status === 503
                ? `${spokeId} is not connected — reconnect the agent to manage its roles.`
                : (data.detail || data.message || JSON.stringify(data));
            showToast('Failed to unload role: ' + msg, 'error');
        }
    } catch (err) {
        showToast('Error unloading role: ' + err.message, 'error');
    }
}

function showDeployAgentInfo() {
    const existing = document.getElementById('deploy-agent-modal');
    if (existing) existing.remove();

    const hubHost = window.location.hostname;
    // Unified-443: the hub serves wss on 443 with path /ws/spoke for spokes.
    // Over HTTPS (the normal case) the port is implicit; HTTP dev fallback uses
    // the legacy plaintext loopback port. The agent appends /ws/spoke itself,
    // but pinning the full path avoids any ambiguity on a pathless pin.
    const hubWS   = window.location.protocol === "https:"
        ? `wss://${hubHost}:443/ws/spoke`
        : `ws://${hubHost}:443/ws/spoke`;
    const cmd = `curl -sSL https://raw.githubusercontent.com/lbockenstedt/lm/main/agent/install_agent.sh \\\n  | sudo bash -s -- \\\n    --hub ${hubWS} \\\n    --id my-agent-1`;

    const modal = document.createElement('div');
    modal.id = 'deploy-agent-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50 backdrop-blur-sm p-4';
    modal.innerHTML = `
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-lg overflow-hidden border border-slate-200">
            <div class="px-6 py-4 bg-slate-50 border-b border-slate-200 flex justify-between items-center">
                <h3 class="text-lg font-bold text-slate-800">Deploy Generic Agent</h3>
                <button onclick="document.getElementById('deploy-agent-modal').remove()" class="text-slate-400 hover:text-slate-600">
                    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                </button>
            </div>
            <div class="p-6 space-y-4">
                <p class="text-sm text-slate-600">Run this on the target server (requires root):</p>
                <div class="relative">
                    <pre id="deploy-cmd-pre" class="bg-slate-900 text-green-300 text-xs p-4 rounded-lg overflow-x-auto whitespace-pre-wrap">${cmd}</pre>
                    <button onclick="navigator.clipboard.writeText(document.getElementById('deploy-cmd-pre').innerText).then(()=>{this.textContent='Copied!';setTimeout(()=>this.textContent='Copy',1500)})"
                        class="absolute top-2 right-2 bg-slate-700 hover:bg-slate-600 text-white text-xs px-2 py-1 rounded">Copy</button>
                </div>
                <p class="text-xs text-slate-500">To pre-load a role at deploy time, add <code class="bg-slate-100 px-1 rounded">--role dns</code> or <code class="bg-slate-100 px-1 rounded">--role dhcp</code> to the command above.</p>
            </div>
            <div class="px-6 py-4 bg-slate-50 border-t border-slate-200 flex justify-end">
                <button onclick="document.getElementById('deploy-agent-modal').remove()"
                    class="px-4 py-2 text-sm font-medium text-slate-600 hover:text-slate-800 transition-colors">Close</button>
            </div>
        </div>`;
    document.body.appendChild(modal);
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
        const res = await setupFetch(`/setup/api-probe?spoke_id=${spokeId}&path=${encodeURIComponent(path)}`);
        const data = await res.json();
        responseEl.textContent = JSON.stringify(data, null, 2);
    } catch (err) {
        responseEl.textContent = `Error: ${err.message}`;
    }
}

function setProbePath(path) {
    document.getElementById('probe-path').value = path;
    executeProbe();
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

    if (emptyState) emptyState.classList.add('hidden');
    if (details) details.classList.remove('hidden');
    if (tableBody) tableBody.innerHTML = `<tr><td colspan="5" class="px-4 py-8 text-center text-slate-400 animate-pulse">Stitching VM data...</td></tr>`;

    try {
        const response = await fetch(`/vm/${vmId}/details`);
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to fetch VM details');
        }
        const data = await response.json();

        if (idEl) idEl.textContent = vmId;
        if (ipEl) ipEl.textContent = data.ip || 'Unknown';

        const res = data.proxmox || {};
        if (resResources) resResources.textContent = `CPU: ${res.cpu || '-'}% | RAM: ${res.ram || '-'}MB | Disk: ${res.disk || '-'}%`;

        const sec = data.cppm || {};
        if (resSecurity) resSecurity.textContent = `Policy: ${sec.policy || '-'} | Posture: ${sec.posture || '-'}`;

        const dhcp = data.opnsense?.dhcp || {};
        if (dhcpHost) dhcpHost.textContent = dhcp.hostname || '-';
        if (dhcpMac) dhcpMac.textContent = dhcp.mac || '-';
        if (dhcpEnd) dhcpEnd.textContent = dhcp.lease_end || '-';

        const rules = (data.opnsense && data.opnsense.rules) || [];
        if (rules.length === 0) {
            if (tableBody) tableBody.innerHTML = `<tr><td colspan="5" class="px-4 py-4 text-center text-slate-400 italic">No rules found for this VM.</td></tr>`;
        } else {
            if (tableBody) tableBody.innerHTML = rules.map(rule => `
                <tr class="hover:bg-slate-50 transition-colors">
                    <td class="px-4 py-3 font-mono text-xs text-slate-600">${escapeHtml(rule.source || 'any')}</td>
                    <td class="px-4 py-3 text-slate-600">${escapeHtml(rule.destination || '-')}</td>
                    <td class="px-4 py-3 text-slate-600">${escapeHtml(rule.protocol || 'TCP')}</td>
                    <td class="px-4 py-3"><span class="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase ${rule.action === 'pass' ? 'bg-green-100 text-green-600' : 'bg-red-100 text-red-600'}">${escapeHtml(rule.action)}</span></td>
                    <td class="px-4 py-3 text-slate-600 text-xs">${escapeHtml(rule.description || '-')}</td>
                </tr>
            `).join('');
        }
    } catch (err) {
        if (tableBody) tableBody.innerHTML = `<tr><td colspan="5" class="px-4 py-8 text-center text-red-500 font-medium">${err.message}</td></tr>`;
    }
}

async function loadOpnsenseManagement() {
    const container = document.getElementById('opn-table-container');
    if (!container) return;

    const subMenu = currentSubView;
    if (subMenu === 'Configuration' || subMenu === 'config') return;

    container.innerHTML = `<div class="py-12 text-center text-slate-400 animate-pulse">Fetching ${subMenu} data…</div>`;

    const firewalls = await _ensureFirewalls();
    if (firewalls.length === 0) {
        const _actions = document.getElementById('top-nav-actions');
        if (_actions) _actions.innerHTML = '';
        container.innerHTML = `<div class="py-12 text-center text-slate-400 italic">No firewalls configured. Add one in Setup → Firewalls.</div>`;
        return;
    }

    // Show/hide the "+ Add" button based on writable sub-views. It lives in the
    // menu strip (far-right #top-nav-actions) rather than the page body. The
    // target firewall is resolved inside the modal (auto-select when only one is
    // configured, a picker otherwise).
    const writable = ['Firewall Rules', 'NAT Policies', 'DNS Records', 'Aliases'];
    const actions = document.getElementById('top-nav-actions');
    if (actions) {
        if (writable.includes(subMenu) && canEdit()) {
            actions.innerHTML = `<button onclick="showOpnsenseAddModal('${subMenu}')" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-3 py-1 rounded-md text-xs font-bold transition-all shadow-sm">+ Add ${subMenu.replace(/s$/, '')}</button>`;
        } else {
            actions.innerHTML = '';
        }
    }

    try {
        // Map the active sub-view to the per-firewall endpoint suffix.
        const suffixFor = sm => {
            if (sm === 'Firewall Rules') return 'rules';
            if (sm === 'DHCP Leases') return 'dhcp';
            if (sm === 'Interfaces') return 'interfaces';
            if (sm === 'NAT Policies') return 'nat';
            if (sm === 'DNS Records') return 'dns';
            if (sm === 'Aliases') return 'aliases';
            return null;
        };
        const suffix = suffixFor(subMenu);
        if (!suffix) return;

        // Pull from every configured firewall in parallel and merge into one
        // table, tagging each row with its source firewall (_fwId / firewall).
        // ?tenant=currentTenant scopes the server-side subnet filter to the
        // selected tenant — including for admins (via the switcher), who
        // otherwise bypass the filter. Applies to every tab (rules/nat/dns/
        // interfaces/dhcp/aliases); aliases filter on their content IPs.
        const tenantQs = currentTenant ? `?tenant=${encodeURIComponent(currentTenant)}` : '';
        const results = await Promise.allSettled(firewalls.map(fw =>
            fetch(`/api/firewall/${fw.id}/${suffix}${tenantQs}`)
                .then(r => r.ok ? r.json()
                    // Non-OK: read the FastAPI error body so we can show *why*
                    // (e.g. "OPNsense NAT API returned errors … < 26.1") instead
                    // of a generic "unreachable" count.
                    : r.json().catch(() => ({})).then(body => Promise.reject(
                        new Error(body.detail || `${r.status} ${r.statusText}`))))
                .then(data => ({ fw, data }))
        ));
        const extractItems = data => {
            if (Array.isArray(data)) return data;
            if (data && typeof data === 'object') {
                if (Array.isArray(data.data)) return data.data;
                if (Array.isArray(data.payload?.data)) return data.payload.data;
                if (data.rows && Array.isArray(data.rows)) return data.rows;
            }
            return [];
        };
        let items = [];
        const errors = [];
        results.forEach(res => {
            if (res.status === 'fulfilled') {
                const fwItems = extractItems(res.value.data).map(it => ({
                    ...it, _fwId: res.value.fw.id, firewall: res.value.fw.name || res.value.fw.id
                }));
                items = items.concat(fwItems);
            } else {
                errors.push(String((res.reason && res.reason.message) || res.reason));
            }
        });

        if (items.length === 0) {
            // Distinguish "legitimately empty" from "the spoke returned an error"
            // — the latter carries a real reason (version/permissions) the user
            // needs to see, not a bare "No <things> found."
            const errNote = errors.length
                ? `<div class="text-xs text-amber-600 mt-2 max-w-2xl mx-auto">${errors.length} firewall(s) reported an error: ${escapeHtml(errors[0])}</div>`
                : '';
            container.innerHTML = `<div class="py-12 text-center text-slate-400 italic">No ${subMenu} found.${errNote}</div>`;
            return;
        }

        let keys;
        if (subMenu === 'Firewall Rules') keys = ['firewall', 'source', 'destination', 'protocol', 'action', 'description'];
        else if (subMenu === 'Interfaces') keys = ['firewall', 'description', 'ip', 'status', 'macaddr', 'mtu', 'media'];
        else if (subMenu === 'NAT Policies') keys = ['firewall', 'type', 'protocol', 'source', 'external_ip', 'external_port', 'internal_ip', 'internal_port', 'description'];
        else if (subMenu === 'DNS Records') keys = ['firewall', 'hostname', 'ip', 'type', 'ttl', 'description'];
        else if (subMenu === 'Aliases') keys = ['firewall', 'name', 'type', 'content', 'category', 'description'];
        else keys = ['firewall', ...Object.keys(items[0] || {}).filter(k => k !== 'id' && !k.toLowerCase().includes('hit') && k !== 'firewall' && !k.startsWith('_'))];

        const hiddenRules = JSON.parse(localStorage.getItem('lm_hidden_firewall_rules') || '[]');
        let filteredItems = items;
        if (subMenu === 'Firewall Rules') {
            // Subnet filtering for rules is enforced server-side
            // (_filter_fw → filter_firewall_rules, with OPNsense alias
            // expansion) so the tenant already receives only their in-prefix
            // rules. The client-side firewallRuleInTenantPrefixes can't resolve
            // alias/interface names and would wrongly hide rules the server
            // showed, so it is intentionally NOT applied here — only the
            // per-rule hide-toggle (localStorage) filter remains. Admins see all
            // (server no-op for admins).
            filteredItems = items.filter(item => {
                const rawId = item.id || JSON.stringify(item);
                const ruleId = `${item._fwId}:${rawId}`;   // firewall-scoped (hide checkbox + localStorage)
                return showHiddenOnlyFirewallRules ? hiddenRules.includes(ruleId) : !hiddenRules.includes(ruleId);
            });
        } else if (subMenu === 'NAT Policies') {
            // Subnet filtering for NAT is enforced server-side (_filter_fw →
            // filter_items_by_prefixes over source/internal_ip/external_ip, plus
            // the OPNsense category attribution) so the tenant already receives
            // only their NAT policies. The client-side itemInTenantPrefixes has
            // no category awareness and would hide category-attributed policies
            // the server showed, so it is intentionally NOT applied here (mirrors
            // the Firewall Rules path). Admins see all (server no-op for admins).
            filteredItems = items;
        } else if (subMenu === 'DHCP Leases') {
            filteredItems = items.filter(item => itemInTenantPrefixes(item, ['ip', 'address']));
        } else if (subMenu === 'DNS Records') {
            filteredItems = items.filter(item => itemInTenantPrefixes(item, ['ip', 'value']));
        } else if (subMenu === 'Interfaces') {
            filteredItems = items.filter(item => itemInTenantPrefixes(item, ['ip', 'ipaddr']));
        }

        const showDelete = writable.includes(subMenu);
        const headers = keys.map(k => `<th class="px-4 py-3">${k.toUpperCase().replace(/_/g, ' ')}</th>`).join('');
        const hideHeader = subMenu === 'Firewall Rules' ? '<th class="px-4 py-3 text-center">Hide</th>' : '';
        const delHeader = showDelete ? '<th class="px-4 py-3"></th>' : '';

        _opnCurrentItems = {};
        const rows = filteredItems.map((item, idx) => {
            const rawId = item.id || item.uuid || JSON.stringify(item);
            const ruleId = `${item._fwId}:${rawId}`;   // firewall-scoped (hide checkbox + localStorage)
            _opnCurrentItems[idx] = item;
            const cells = keys.map(k => {
                const val = item[k] !== undefined ? String(item[k]) : '-';
                const eVal = escapeHtml(val);  // OPNsense-editable (alias/rule/NAT names + descriptions) → escape
                if (k === 'action' && typeof item[k] === 'string') {
                    const color = item[k] === 'pass' ? 'bg-green-100 text-green-600' : 'bg-red-100 text-red-600';
                    return `<td class="px-4 py-3"><span class="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase ${color}">${eVal}</span></td>`;
                }
                if (k === 'status') {
                    const color = val === 'up' ? 'text-green-600' : 'text-slate-400';
                    return `<td class="px-4 py-3 font-mono text-xs ${color}">${eVal}</td>`;
                }
                if (k === 'firewall') {
                    return `<td class="px-4 py-3 text-slate-700 font-semibold text-xs whitespace-nowrap">${eVal}</td>`;
                }
                return `<td class="px-4 py-3 text-slate-600 font-mono text-xs max-w-[200px] truncate" title="${eVal}">${eVal}</td>`;
            }).join('');

            const hideCell = subMenu === 'Firewall Rules' ? `
                <td class="px-4 py-3 text-center"><label class="flex items-center justify-center cursor-pointer">
                    <input type="checkbox" data-rule-id="${ruleId.replace(/"/g,'&quot;')}" onchange="toggleFirewallRuleVisibility(this.dataset.ruleId,this.checked)" ${hiddenRules.includes(ruleId)?'checked':''} class="w-4 h-4 text-green-600 border-slate-300 rounded focus:ring-green-500">
                </label></td>` : '';

            const delCell = showDelete ? `
                <td class="px-4 py-3 text-right">
                    <div class="flex items-center justify-end gap-1">
                        <button onclick="showOpnsenseEditModal('${item._fwId}','${subMenu}',${idx})" class="p-1 text-slate-400 hover:text-blue-600 transition-colors" title="Edit">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"></path></svg>
                        </button>
                        <button onclick="deleteOpnsenseItem('${item._fwId}','${subMenu}','${escJsAttr(rawId)}')" class="p-1 text-slate-400 hover:text-red-600 transition-colors" title="Delete">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>
                        </button>
                    </div>
                </td>` : '';

            return `<tr class="hover:bg-slate-50 transition-colors">${cells}${hideCell}${delCell}</tr>`;
        }).join('');

        let footerHtml = '';
        if (subMenu === 'Firewall Rules' && hiddenRules.length > 0) {
            footerHtml = `<div class="pt-3 flex items-center gap-4">
                <span class="text-xs text-slate-400">${hiddenRules.length} rules manually hidden</span>
                <button onclick="toggleHiddenFirewallRules()" class="text-xs font-medium text-blue-600 hover:text-blue-800">${showHiddenOnlyFirewallRules ? 'Show All' : 'View Hidden'}</button>
                <button onclick="unhideAllFirewallRules()" class="text-xs font-medium text-blue-600 hover:text-blue-800">Unhide All</button>
            </div>`;
        }

        const moduleKey = subMenu === 'Firewall Rules' ? 'rules' : subMenu === 'NAT Policies' ? 'nat'
            : subMenu === 'DHCP Leases' ? 'dhcp' : subMenu === 'DNS Records' ? 'dns' : 'interfaces';
        const refreshBtn = !isAdmin() ? `<button onclick="refreshModuleCache('${moduleKey}').then(()=>loadOpnsenseManagement())"
            class="text-xs text-slate-400 hover:text-slate-600 flex items-center gap-1" title="Refresh from cache">
            <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
            Refresh</button>` : '';

        const errBanner = errors.length ? `<div class="text-xs text-amber-600">${errors.length} of ${firewalls.length} firewall(s) unreachable.</div>` : '';
        container.innerHTML = `
            <div class="space-y-4">
                ${refreshBtn ? `<div class="flex justify-end">${refreshBtn}</div>` : ''}
                ${errBanner}
                <div class="overflow-x-auto overflow-hidden rounded-md border border-slate-200 bg-white">
                    <table class="w-full text-left text-sm">
                        <thead class="bg-slate-100 text-slate-600 uppercase text-xs"><tr>${headers}${hideHeader}${delHeader}</tr></thead>
                        <tbody class="divide-y divide-slate-200">${rows}</tbody>
                    </table>
                </div>
                ${footerHtml}
            </div>`;
    } catch (err) {
        console.error(`[OPNsense] Error in loadOpnsenseManagement:`, err);
        container.innerHTML = `<div class="py-12 text-center text-red-500 font-medium">Error loading ${subMenu}: ${err.message}</div>`;
    }
}

// Network Devices management view (mirrors loadOpnsenseManagement).
// Devices → fleet list (/api/nw/devices); MAC Table / ARP / Interfaces →
// per-device fetch merged across the fleet (/api/nw/{id}/{macs|arp|interfaces}),
// each row tagged with its source device (_deviceId / device). ?tenant=
// scopes the server-side subnet filter to the selected tenant (incl. admins
// via the switcher); without it admins bypass the filter (see access.filter_nw).
async function loadNwData(subMenu) {
    const container = document.getElementById('nw-table-container');
    if (!container) return;
    subMenu = subMenu || currentSubView;
    container.innerHTML = `<div class="py-12 text-center text-slate-400 animate-pulse">Fetching ${subMenu} data…</div>`;

    // Suppress the per-view "+ Add" action strip for nw (no add-from-view flow;
    // devices are managed on Setup → Network Devices).
    const actions = document.getElementById('top-nav-actions');
    if (actions) actions.innerHTML = '';

    const tenantQs = currentTenant ? `?tenant=${encodeURIComponent(currentTenant)}` : '';

    try {
        if (subMenu === 'Devices') {
            let r;
            try {
                r = await fetch(`/api/nw/devices${tenantQs}`);
            } catch (e) {
                container.innerHTML = `<div class="py-12 text-center text-amber-600 italic">Network Devices spoke not connected. Approve one in Setup → Spokes & Agents.</div>`;
                return;
            }
            if (!r.ok) {
                container.innerHTML = `<div class="py-12 text-center text-amber-600 italic">Network Devices spoke not connected (HTTP ${r.status}).</div>`;
                return;
            }
            const data = await r.json();
            const items = Array.isArray(data) ? data : (Array.isArray(data?.data) ? data.data : []);
            if (!items.length) {
                container.innerHTML = `<div class="py-12 text-center text-slate-400 italic">No network devices configured. Add one in Setup → Network Devices.</div>`;
                return;
            }
            const keys = ['device', 'object_type', 'transport', 'address', 'reachable'];
            const headers = keys.map(k => `<th class="px-4 py-3">${k.toUpperCase().replace(/_/g, ' ')}</th>`).join('');
            const rows = items.map((it, idx) => {
                const typeLabel = _NW_OBJECT_TYPES[it.object_type] || it.object_type || '—';
                const transport = _NW_TRANSPORTS[it.transport] || it.transport || 'auto';
                const reachable = it.reachable;
                const rcell = reachable === true || reachable === 'up'
                    ? '<span class="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase bg-green-100 text-green-700">up</span>'
                    : reachable === false || reachable === 'down'
                        ? '<span class="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase bg-red-100 text-red-700">down</span>'
                        : `<span class="text-slate-400 text-xs">—</span>`;
                const cfg = isAdmin()
                    ? `<button onclick="pollNwDevice('${escJsAttr(it.id)}','${escJsAttr(it.name || it.id)}', this)" class="text-xs text-emerald-600 hover:text-emerald-800 font-medium mr-3">Poll Now</button>` +
                      `<button onclick="showNwConfigModal('${escJsAttr(it.id)}','${escJsAttr(it.name || it.id)}')" class="text-xs text-blue-500 hover:text-blue-700 font-medium">Configure</button>`
                    : '';
                return `<tr class="hover:bg-slate-50 transition-colors">
                    <td class="px-4 py-3 text-slate-700 font-semibold text-xs whitespace-nowrap">${escapeHtml(it.name || it.id)}</td>
                    <td class="px-4 py-3 text-slate-600 text-xs">${escapeHtml(typeLabel)}</td>
                    <td class="px-4 py-3 text-slate-600 text-xs">${escapeHtml(transport)}</td>
                    <td class="px-4 py-3 text-slate-600 font-mono text-xs">${escapeHtml(it.address || '—')}</td>
                    <td class="px-4 py-3">${rcell}</td>
                    <td class="px-4 py-3 text-right">${cfg}</td>
                </tr>`;
            }).join('');
            container.innerHTML = `
                <div class="space-y-4">
                    <div class="overflow-x-auto overflow-hidden rounded-md border border-slate-200 bg-white">
                        <table class="w-full text-left text-sm">
                            <thead class="bg-slate-100 text-slate-600 uppercase text-xs"><tr>${headers}<th class="px-4 py-3"></th></tr></thead>
                            <tbody class="divide-y divide-slate-200">${rows}</tbody>
                        </table>
                    </div>
                </div>`;
            return;
        }

        const suffixFor = sm => {
            if (sm === 'MAC Table') return 'macs';
            if (sm === 'ARP') return 'arp';
            if (sm === 'Interfaces') return 'interfaces';
            return null;
        };
        const suffix = suffixFor(subMenu);
        if (!suffix) return;

        // List the fleet first, then fetch the per-device sub-resource in
        // parallel and merge into one table tagged with _deviceId.
        let devList = [];
        try {
            const dr = await fetch(`/api/nw/devices`);
            if (dr.ok) {
                const dd = await dr.json();
                devList = Array.isArray(dd) ? dd : (Array.isArray(dd?.data) ? dd.data : []);
            }
        } catch (e) { /* spoke down handled below */ }
        if (!devList.length) {
            container.innerHTML = `<div class="py-12 text-center text-amber-600 italic">Network Devices spoke not connected or no devices configured.</div>`;
            return;
        }

        const results = await Promise.allSettled(devList.map(d =>
            fetch(`/api/nw/${d.id}/${suffix}${tenantQs}`)
                .then(r => r.ok ? r.json() : Promise.reject(new Error(`${r.status} ${r.statusText}`)))
                .then(data => ({ dev: d, data }))
        ));
        const extractItems = data => {
            if (Array.isArray(data)) return data;
            if (data && typeof data === 'object') {
                if (Array.isArray(data.data)) return data.data;
                if (Array.isArray(data.payload?.data)) return data.payload.data;
            }
            return [];
        };
        let items = [];
        const errors = [];
        results.forEach(res => {
            if (res.status === 'fulfilled') {
                items = items.concat(extractItems(res.value.data).map(it => ({
                    ...it, _deviceId: res.value.dev.id, device: res.value.dev.name || res.value.dev.id
                })));
            } else {
                errors.push(String((res.reason && res.reason.message) || res.reason));
            }
        });

        if (!items.length) {
            const errNote = errors.length ? `<div class="text-xs text-amber-600 mt-2">${errors.length} device(s) unreachable.</div>` : '';
            container.innerHTML = `<div class="py-12 text-center text-slate-400 italic">No ${subMenu} found.${errNote}</div>`;
            return;
        }

        let keys;
        if (subMenu === 'MAC Table') keys = ['device', 'mac', 'vlan', 'interface'];
        else if (subMenu === 'ARP') keys = ['device', 'ip', 'mac', 'interface'];
        else if (subMenu === 'Interfaces') keys = ['device', 'name', 'ip', 'mac', 'vlan', 'status', 'speed'];
        else keys = ['device', ...Object.keys(items[0] || {}).filter(k => k !== 'id' && k !== 'device' && !k.startsWith('_'))];

        const headers = keys.map(k => `<th class="px-4 py-3">${k.toUpperCase().replace(/_/g, ' ')}</th>`).join('');
        const rows = items.map(item => {
            const cells = keys.map(k => {
                const val = item[k] !== undefined && item[k] !== null && item[k] !== '' ? String(item[k]) : '-';
                if (k === 'device') return `<td class="px-4 py-3 text-slate-700 font-semibold text-xs whitespace-nowrap">${escapeHtml(val)}</td>`;
                if (k === 'status') {
                    const color = val === 'up' ? 'text-green-600' : 'text-slate-400';
                    return `<td class="px-4 py-3 font-mono text-xs ${color}">${escapeHtml(val)}</td>`;
                }
                return `<td class="px-4 py-3 text-slate-600 font-mono text-xs max-w-[200px] truncate" title="${escapeHtml(val)}">${escapeHtml(val)}</td>`;
            }).join('');
            return `<tr class="hover:bg-slate-50 transition-colors">${cells}</tr>`;
        }).join('');

        const errBanner = errors.length ? `<div class="text-xs text-amber-600">${errors.length} of ${devList.length} device(s) unreachable.</div>` : '';
        container.innerHTML = `
            <div class="space-y-4">
                ${errBanner}
                <div class="overflow-x-auto overflow-hidden rounded-md border border-slate-200 bg-white">
                    <table class="w-full text-left text-sm">
                        <thead class="bg-slate-100 text-slate-600 uppercase text-xs"><tr>${headers}</tr></thead>
                        <tbody class="divide-y divide-slate-200">${rows}</tbody>
                    </table>
                </div>
            </div>`;
    } catch (err) {
        console.error(`[Network] Error in loadNwData:`, err);
        container.innerHTML = `<div class="py-12 text-center text-red-500 font-medium">Error loading ${subMenu}: ${err.message}</div>`;
    }
}

// Admin: apply a CLI/REST config snippet to a device (POST /api/nw/{id}/config).
function showNwConfigModal(deviceId, deviceName) {
    const modal = document.createElement('div');
    modal.id = 'nw-config-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm';
    modal.innerHTML = `
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-lg overflow-hidden">
            <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50">
                <h3 class="text-lg font-bold text-[#263040]">Configure ${escapeHtml(deviceName)}</h3>
                <button onclick="closeNwConfigModal()" class="text-slate-400 hover:text-slate-600 transition-colors"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg></button>
            </div>
            <div class="p-6 space-y-3">
                <p class="text-xs text-slate-400">One command per line. Applied via the device's transport (SSH/CLI or REST) by the nw spoke.</p>
                <textarea id="nw-config-commands" rows="8" placeholder="show version\nshow running-config" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm font-mono outline-none focus:ring-2 focus:ring-green-500"></textarea>
                <div id="nw-config-result" class="text-xs text-slate-500"></div>
            </div>
            <div class="px-6 py-4 bg-slate-50 border-t border-slate-200 flex justify-end gap-3">
                <button onclick="closeNwConfigModal()" class="px-4 py-2 text-sm font-medium text-slate-600 hover:text-slate-800 transition-colors">Cancel</button>
                <button onclick="submitNwConfig('${escapeHtml(deviceId)}')" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm">Apply</button>
            </div>
        </div>`;
    document.body.appendChild(modal);
    modal.dataset.deviceId = deviceId;
}

async function submitNwConfig(deviceId) {
    const ta = document.getElementById('nw-config-commands');
    const out = document.getElementById('nw-config-result');
    const commands = (ta?.value || '').split('\n').map(s => s.trim()).filter(Boolean);
    if (!commands.length) { if (out) out.textContent = 'Enter at least one command.'; return; }
    if (out) out.textContent = 'Applying…';
    try {
        const r = await setupFetch(`/api/nw/${deviceId}/config`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ commands })
        });
        const data = await r.json().catch(() => ({}));
        if (r.ok && data?.status === 'SUCCESS') {
            const applied = Array.isArray(data.applied) ? data.applied.length : 0;
            const errs = Array.isArray(data.errors) ? data.errors.length : 0;
            if (out) out.innerHTML = `<span class="text-green-600">Applied ${applied} command(s)${errs ? `, ${errs} error(s)` : ''}.</span>`;
        } else {
            if (out) out.innerHTML = `<span class="text-red-600">Failed: ${escapeHtml(data?.message || r.status)}</span>`;
        }
    } catch (e) {
        if (out) out.innerHTML = `<span class="text-red-600">Error: ${escapeHtml(e.message)}</span>`;
    }
}

function closeNwConfigModal() {
    const modal = document.getElementById('nw-config-modal');
    if (modal) modal.remove();
}

// ─── PXMX / Proxmox ──────────────────────────────────────────────────────────

// Stable key tying a node to the VMs that run on it: "<cluster>::<node>".
// VMs expose the same cluster/node fields, so this scopes a node's VMs.
function pxmxNodeKey(cluster, node) {
    return `${cluster || ''}::${node || ''}`;
}

function pxmxTableWrap(html) {
    return `<div class="overflow-x-auto"><table class="w-full text-sm">${html}</table></div>`;
}

function pxmxTh(cols) {
    return `<thead class="bg-slate-50 text-xs text-slate-500 uppercase"><tr>${cols.map(c => `<th class="px-4 py-2 text-left font-medium">${c}</th>`).join('')}</tr></thead>`;
}

// VM table — shared by the node-detail view and the no-nodes fallback.
// Each VM is a 2-line entry: line 1 = identity (Cluster/Host, VMID, Name, IP,
// Clone action); line 2 = metadata (Type, Status, CPU, Memory, Pool). Cluster
// and Host(node) are merged into one "Cluster / Host" column as "<cluster>/<node>".
function pxmxVmTableHtml(vms) {
    const cols = ['<input type="checkbox" onclick="pxmxBulkSelectAll(this.checked)" title="Select all"/>', 'Cluster / Host', 'VMID', 'Name', 'IP Address', ''];
    const escJs = s => String(s == null ? '' : s).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
    const tplPools = window._pxmxTemplatePools || [];
    const isTemplate = vm => !!(vm.pool && tplPools.includes(String(vm.pool).toLowerCase()));
    const rows = vms.map(vm => {
        const memGb   = ((vm.mem_bytes || 0) / 1073741824).toFixed(1);
        const runCls  = vm.status === 'running' ? 'bg-green-100 text-green-700'
                      : vm.status === 'stopped' ? 'bg-slate-100 text-slate-500'
                      : 'bg-amber-100 text-amber-700';
        const typeCls = vm.type === 'lxc' ? 'bg-blue-50 text-blue-600' : 'bg-purple-50 text-purple-600';
        // ips: best-effort guest IPv4 list from the pxmx agent (qemu needs
        // qemu-guest-agent; lxc reads the container netns). [] for stopped VMs
        // or when the guest agent is absent/unresponsive → show '—'.
        const ipList = Array.isArray(vm.ips) ? vm.ips : [];
        const ipCell = ipList.length ? escapeHtml(ipList.join(', ')) : '—';
        // Cluster/Host merged: Proxmox node is the host, shown as "<cluster>/<node>".
        const clusterHost = escapeHtml(`${vm.cluster || '—'}/${vm.node || '—'}`);
        const poolCell = vm.pool ? escapeHtml(vm.pool) : '—';
        const uid = escJs(vm.unique_id || '');
        const cloneBtn = isTemplate(vm)
            ? `<button onclick="event.stopPropagation(); pxmxCloneVm('${uid}')" title="Clone this template to a new VM" class="px-2 py-1 rounded-md text-xs font-bold bg-indigo-600 hover:bg-indigo-700 text-white transition-colors">⧉ Clone</button>`
            : '';
        // Line 2 metadata: Type + Status keep their colored pill badges; CPU,
        // Memory and Pool are labeled text. Wrapped so it folds on narrow widths.
        const line2 = `<div class="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-slate-500">
            <span class="px-2 py-0.5 rounded-full font-medium ${typeCls}">${vm.type || 'vm'}</span>
            <span class="px-2 py-0.5 rounded-full font-medium ${runCls}">${vm.status}</span>
            <span>CPU ${vm.cpu ?? '—'}%</span>
            <span>Memory ${memGb} GB</span>
            <span>Pool ${poolCell}</span>
        </div>`;
        // One <tbody class="group"> per VM so both lines highlight together on
        // hover and read as a single entry; both rows open the VM detail panel.
        return `<tbody class="group">
            <tr class="border-b border-slate-50 group-hover:bg-slate-50 cursor-pointer" data-unique-id="${escapeHtml(vm.unique_id || '')}" onclick="openVmDetail('${uid}')">
                <td class="px-4 py-2" onclick="event.stopPropagation()"><input type="checkbox" class="pxmx-vm-sel" value="${escapeHtml(vm.unique_id || '')}"/></td>
                <td class="px-4 py-2 text-xs text-slate-500 font-mono">${clusterHost}</td>
                <td class="px-4 py-2 font-mono text-xs font-bold">${vm.vmid}</td>
                <td class="px-4 py-2 font-medium">${escapeHtml(vm.name || '—')}</td>
                <td class="px-4 py-2 font-mono text-xs text-slate-600">${ipCell}</td>
                <td class="px-4 py-2">${cloneBtn}</td>
            </tr>
            <tr class="border-b border-slate-100 group-hover:bg-slate-50 cursor-pointer" onclick="openVmDetail('${uid}')">
                <td colspan="6" class="px-4 pb-2 pt-0">${line2}</td>
            </tr>
        </tbody>`;
    }).join('');
    return pxmxBulkBar() + pxmxTableWrap(pxmxTh(cols) + rows);
}

// Bulk VM actions — operate on the checked rows. Reuses /api/pxmx/vm-action per
// VM (so Backup gets the same Hypervisors-config injection), confirming ONCE for
// the batch when confirm_destructive is on.
function pxmxBulkBar() {
    if (!canEdit()) return '';   // VM control is write-tier; view users see none
    return `<div class="flex flex-wrap items-center gap-2 mb-3 text-xs">
      <span class="text-slate-400 font-medium mr-1">Bulk (selected):</span>
      <button onclick="pxmxBulkAction('start')" class="bg-green-100 text-green-700 px-2.5 py-1 rounded font-bold hover:bg-green-200">▶ Start</button>
      <button onclick="pxmxBulkAction('stop')" class="bg-red-100 text-red-700 px-2.5 py-1 rounded font-bold hover:bg-red-200">■ Stop</button>
      <button onclick="pxmxBulkAction('reboot')" class="bg-amber-100 text-amber-700 px-2.5 py-1 rounded font-bold hover:bg-amber-200">↺ Restart</button>
      <button onclick="pxmxBulkAction('snapshot')" class="bg-slate-200 text-slate-700 px-2.5 py-1 rounded font-bold hover:bg-slate-300">📷 Snapshot</button>
      <button onclick="pxmxBulkAction('backup')" class="bg-sky-100 text-sky-700 px-2.5 py-1 rounded font-bold hover:bg-sky-200">💾 Backup</button>
      <span id="pxmx-bulk-status" class="text-slate-400"></span>
    </div>`;
}

window.pxmxBulkSelectAll = function (checked) {
    document.querySelectorAll('.pxmx-vm-sel').forEach(cb => { cb.checked = checked; });
};

window.pxmxBulkAction = async function (action) {
    const sel = Array.from(document.querySelectorAll('.pxmx-vm-sel:checked')).map(cb => cb.value);
    if (!sel.length) { showToast('No VMs selected', 'info'); return; }
    if (['stop', 'reboot', 'restart', 'backup'].includes(action)) {
        const cfg = await pxmxHvConfig();
        if (cfg.confirm_destructive !== false &&
            !window.confirm(`${action.toUpperCase()} ${sel.length} selected VM(s)?`)) return;
    }
    const statusEl = document.getElementById('pxmx-bulk-status');
    let ok = 0, fail = 0;
    for (const uid of sel) {
        const vm = (window._pxmxVms || []).find(v => v.unique_id === uid);
        if (!vm) { fail++; continue; }
        if (statusEl) statusEl.textContent = `${action}… ${ok + fail + 1}/${sel.length}`;
        try {
            const r = await setupFetch('/api/pxmx/vm-action', {
                method: 'POST',
                body: JSON.stringify({ unique_id: vm.unique_id, vmid: vm.vmid, node: vm.node, type: vm.type, action }),
            });
            const d = await r.json().catch(() => ({}));
            if (r.ok && d && d.status === 'SUCCESS') ok++; else fail++;
        } catch (e) { fail++; }
    }
    showToast(`Bulk ${action}: ${ok} ok${fail ? `, ${fail} failed` : ''}`, fail ? 'error' : 'success');
    if (statusEl) statusEl.textContent = `${ok} ok${fail ? `, ${fail} failed` : ''}`;
    setTimeout(() => loadPxmxData('Virtual Machines'), 1500);
};

// Clicking a VM row opens a details panel with Start/Stop/Restart/Snapshot
// controls (VNC Console wired up in the VNC increment). Back returns to the
// cached VM list. Actions POST /api/pxmx/vm-action (admin-only) which routes to
// the pxmx spoke's PXMX_VM_ACTION (unguarded — any vmid, not just the sim floor).
function openVmDetail(uniqueId) {
    const vms = window._pxmxVms || [];
    const vm = vms.find(v => v.unique_id === uniqueId);
    const container = document.getElementById('pxmx-content');
    if (!vm || !container) return;
    const memGb  = ((vm.mem_bytes || 0) / 1073741824).toFixed(1);
    const ipList = Array.isArray(vm.ips) ? vm.ips : [];
    const runCls  = vm.status === 'running' ? 'bg-green-100 text-green-700'
                 : vm.status === 'stopped' ? 'bg-slate-100 text-slate-500' : 'bg-amber-100 text-amber-700';
    const typeCls = vm.type === 'lxc' ? 'bg-blue-50 text-blue-600' : 'bg-purple-50 text-purple-600';
    const escJs = s => String(s == null ? '' : s).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
    const uid = escJs(vm.unique_id);
    container.innerHTML = `
        <button onclick="loadPxmxData('Virtual Machines')" class="mb-3 inline-flex items-center gap-1 text-sm text-slate-500 hover:text-[#01A982] font-medium transition-colors">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7"/></svg>
            Back to VM list
        </button>
        <div class="rounded-lg border border-slate-200 bg-slate-50/50 p-4 mb-4">
            <h3 class="text-base font-semibold text-[#263040]">${escapeHtml(vm.name || '—')}
                <span class="text-xs text-slate-400 font-normal font-mono">VMID ${vm.vmid} · ${escapeHtml((vm.cluster || '') + '/' + (vm.node || ''))}</span> ${helpIcon('pxmx', null, 'Hypervisor help')}</h3>
            <p class="text-xs text-slate-500 mt-1">Status
                <span class="px-2 py-0.5 rounded-full text-xs font-medium ${runCls}">${vm.status}</span>
                · <span class="px-2 py-0.5 rounded-full text-xs font-medium ${typeCls}">${vm.type || 'vm'}</span>
                · CPU ${vm.cpu ?? '—'}% · RAM ${memGb} GB
                · IP ${ipList.length ? escapeHtml(ipList.join(', ')) : '—'}
                · Pool ${vm.pool ? escapeHtml(vm.pool) : '—'}</p>
        </div>
        <div class="flex flex-wrap items-center gap-2 mb-4"${canEdit() ? '' : ' style="display:none"'}>
            <button onclick="pxmxVmAction('${uid}','start')" class="px-3 py-1.5 rounded-md text-xs font-bold bg-green-600 hover:bg-green-700 text-white transition-colors">▶ Start</button>
            <button onclick="pxmxVmAction('${uid}','stop')" class="px-3 py-1.5 rounded-md text-xs font-bold bg-red-600 hover:bg-red-700 text-white transition-colors">■ Stop</button>
            <button onclick="pxmxVmAction('${uid}','reboot')" class="px-3 py-1.5 rounded-md text-xs font-bold bg-amber-600 hover:bg-amber-700 text-white transition-colors">↺ Restart</button>
            <button onclick="pxmxVmAction('${uid}','snapshot')" class="px-3 py-1.5 rounded-md text-xs font-bold bg-slate-600 hover:bg-slate-700 text-white transition-colors">📷 Snapshot</button>
            <button onclick="pxmxVmAction('${uid}','backup')" title="vzdump backup to the storage configured in Setup → Hypervisors" class="px-3 py-1.5 rounded-md text-xs font-bold bg-sky-600 hover:bg-sky-700 text-white transition-colors">💾 Backup</button>
            <button id="pxmx-vm-console-btn" onclick="pxmxOpenConsole('${uid}')" title="Open VNC console (noVNC)" class="px-3 py-1.5 rounded-md text-xs font-bold bg-[#01A982] hover:bg-[#008c6a] text-white transition-colors">🖥 Console</button>
            ${(() => { const tp = (window._pxmxTemplatePools||[]); return (vm.pool && tp.includes(String(vm.pool).toLowerCase())) ? `<button onclick="pxmxCloneVm('${uid}')" title="Clone this template to a new VM" class="px-3 py-1.5 rounded-md text-xs font-bold bg-indigo-600 hover:bg-indigo-700 text-white transition-colors">⧉ Clone</button>` : ''; })()}
            <span id="pxmx-vm-action-status" class="text-xs text-slate-400"></span>
        </div>`;
}

// Hypervisor → Settings tab: backup (storage/mode/keep) + snapshot (keep/prefix)
// + confirm-destructive + per-host overrides. Reads GET /hypervisors-config and
// the live per-host storage list (GET /hypervisor-storages, which fans
// PXMX_LIST_STORAGE to each host). Saves via PUT. Governs the VM action panel.
async function renderPxmxSettings(container) {
    container.innerHTML = '<p class="text-sm text-slate-400 italic p-4">Loading Hypervisor settings…</p>';
    let cfg = {}, storages = { hosts: [] };
    try {
        const [cR, sR] = await Promise.all([
            setupFetch(`/sim/api/tenant/${currentTenant}/hypervisors-config?tenant_id=${encodeURIComponent(currentTenant)}`),
            setupFetch(`/sim/api/tenant/${currentTenant}/hypervisor-storages?tenant_id=${encodeURIComponent(currentTenant)}`),
        ]);
        cfg = (await cR.json()).hypervisors_config || {};
        storages = await sR.json() || { hosts: [] };
    } catch (e) {
        container.innerHTML = `<div class="p-4 text-sm text-red-600">Could not load Hypervisor settings: ${escapeHtml(String(e.message || e))}</div>`;
        return;
    }
    window._pxmxHvConfig = cfg; // refresh the cache the VM actions read
    const allStorages = [...new Set((storages.hosts || []).flatMap(h => h.storages || []))].sort();
    const optList = (arr, sel, blank) => `<option value="">${blank}</option>` +
        arr.map(s => `<option value="${escapeHtml(s)}"${s === sel ? ' selected' : ''}>${escapeHtml(s)}</option>`).join('');
    const modeSel = (sel, blank) => (blank ? `<option value="">${blank}</option>` : '') +
        ['snapshot', 'suspend', 'stop'].map(m => `<option value="${m}"${m === sel ? ' selected' : ''}>${m}</option>`).join('');
    const perHost = cfg.per_host || {};
    const hostRows = (storages.hosts || []).map(h => {
        const ph = perHost[h.hostname] || {};
        return `<tr data-host="${escapeHtml(h.hostname)}" class="border-b border-slate-50">
          <td class="px-3 py-2 text-sm font-medium text-slate-700">${escapeHtml(h.hostname)}</td>
          <td class="px-3 py-2"><select class="ph-storage border border-slate-200 rounded px-2 py-1 text-xs bg-white">${optList(h.storages || [], ph.backup_storage, '(use global)')}</select></td>
          <td class="px-3 py-2"><select class="ph-mode border border-slate-200 rounded px-2 py-1 text-xs bg-white">${modeSel(ph.backup_mode, '(global)')}</select></td>
          <td class="px-3 py-2"><input type="number" min="0" class="ph-keep border border-slate-200 rounded px-2 py-1 text-xs w-20" value="${ph.backup_keep ?? ''}" placeholder="global"/></td>
        </tr>`;
    }).join('') || `<tr><td colspan="4" class="px-3 py-3 text-xs text-slate-400 italic">No hosts reporting storages yet (agents fan PXMX_LIST_STORAGE on connect).</td></tr>`;
    const inp = 'border border-slate-200 rounded-md px-3 py-1.5 text-sm w-full';
    const lbl = 'block text-xs font-bold text-slate-500 uppercase tracking-wider mb-1';
    container.innerHTML = `
      <div class="space-y-5 max-w-3xl">
        <div class="hpe-card rounded-lg p-5 shadow-sm">
          <p class="text-sm font-bold text-[#263040] mb-3">Backup (vzdump) ${helpIcon('pxmx', null, 'Hypervisor help')}</p>
          <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div><label class="${lbl}">Default storage</label><select id="hv-backup-storage" class="${inp}">${optList(allStorages, cfg.backup_storage, '— select —')}</select></div>
            <div><label class="${lbl}">Mode</label><select id="hv-backup-mode" class="${inp}">${modeSel(cfg.backup_mode || 'snapshot', '')}</select></div>
            <div><label class="${lbl}">Keep last (0 = no prune)</label><input id="hv-backup-keep" type="number" min="0" value="${cfg.backup_keep ?? 3}" class="${inp}"/></div>
          </div>
          <p class="text-[11px] text-slate-400 mt-2">Snapshot mode = no downtime. Storage list is pulled live from each host; per-host overrides below win over the default.</p>
        </div>
        <div class="hpe-card rounded-lg p-5 shadow-sm">
          <p class="text-sm font-bold text-[#263040] mb-3">Snapshot</p>
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div><label class="${lbl}">Keep last</label><input id="hv-snap-keep" type="number" min="0" value="${cfg.snapshot_keep ?? 5}" class="${inp}"/></div>
            <div><label class="${lbl}">Name prefix</label><input id="hv-snap-prefix" type="text" value="${escapeHtml(cfg.snapshot_prefix || 'lm')}" class="${inp}"/></div>
          </div>
        </div>
        <div class="hpe-card rounded-lg p-5 shadow-sm">
          <p class="text-sm font-bold text-[#263040] mb-3">Per-host overrides</p>
          <div class="overflow-x-auto"><table class="w-full text-sm" id="pxmx-perhost-rows">
            <thead class="bg-slate-50 text-xs text-slate-500 uppercase"><tr><th class="px-3 py-2 text-left font-medium">Host</th><th class="px-3 py-2 text-left font-medium">Backup storage</th><th class="px-3 py-2 text-left font-medium">Mode</th><th class="px-3 py-2 text-left font-medium">Keep</th></tr></thead>
            <tbody>${hostRows}</tbody>
          </table></div>
        </div>
        <div class="hpe-card rounded-lg p-5 shadow-sm">
          <label class="flex items-center gap-2 text-sm text-slate-700"><input id="hv-confirm" type="checkbox" ${cfg.confirm_destructive !== false ? 'checked' : ''} class="rounded"/> Confirm before destructive VM actions (stop / restart / backup)</label>
        </div>
        <div class="flex items-center gap-3">
          <button onclick="savePxmxSettings()" class="bg-[#01A982] hover:bg-[#018a6c] text-white px-5 py-2 rounded-md text-sm font-bold">Save</button>
          <span id="pxmx-settings-status" class="text-xs text-slate-400"></span>
        </div>
      </div>`;
}

async function savePxmxSettings() {
    const val = id => (document.getElementById(id) || {}).value;
    const perHost = {};
    document.querySelectorAll('#pxmx-perhost-rows tr[data-host]').forEach(tr => {
        const host = tr.getAttribute('data-host');
        const st = (tr.querySelector('.ph-storage') || {}).value || '';
        const md = (tr.querySelector('.ph-mode') || {}).value || '';
        const kp = (tr.querySelector('.ph-keep') || {}).value;
        const o = {};
        if (st) o.backup_storage = st;
        if (md) o.backup_mode = md;
        if (kp !== '' && kp != null) o.backup_keep = parseInt(kp, 10);
        if (Object.keys(o).length) perHost[host] = o;
    });
    const cfg = {
        backup_storage: val('hv-backup-storage') || '',
        backup_mode: val('hv-backup-mode') || 'snapshot',
        backup_keep: parseInt(val('hv-backup-keep') || '0', 10) || 0,
        snapshot_keep: parseInt(val('hv-snap-keep') || '0', 10) || 0,
        snapshot_prefix: val('hv-snap-prefix') || 'lm',
        confirm_destructive: (document.getElementById('hv-confirm') || {}).checked !== false,
        per_host: perHost,
    };
    const st = document.getElementById('pxmx-settings-status');
    try {
        const r = await setupFetch(`/sim/api/tenant/${currentTenant}/hypervisors-config?tenant_id=${encodeURIComponent(currentTenant)}`, {
            method: 'PUT', body: JSON.stringify({ hypervisors_config: cfg }),
        });
        if (r.ok) { window._pxmxHvConfig = cfg; showToast('Hypervisor settings saved', 'success'); if (st) st.textContent = 'Saved'; }
        else { const d = await r.json().catch(() => ({})); showToast('Save failed: ' + (d.detail || r.status), 'error'); if (st) st.textContent = 'Save failed'; }
    } catch (e) { showToast('Save failed: ' + (e.message || e), 'error'); if (st) st.textContent = 'Save failed'; }
}

// Cached Setup → Hypervisors config (confirm toggle + backup/snapshot settings).
// Fetched once per view; pass force=true to refresh after a save.
async function pxmxHvConfig(force) {
    if (!force && window._pxmxHvConfig) return window._pxmxHvConfig;
    try {
        const r = await setupFetch(`/sim/api/tenant/${currentTenant}/hypervisors-config?tenant_id=${encodeURIComponent(currentTenant)}`);
        const d = await r.json();
        window._pxmxHvConfig = (d && d.hypervisors_config) || {};
    } catch (e) { window._pxmxHvConfig = window._pxmxHvConfig || {}; }
    return window._pxmxHvConfig;
}

async function pxmxVmAction(uniqueId, action) {
    const vms = window._pxmxVms || [];
    const vm = vms.find(v => v.unique_id === uniqueId);
    if (!vm) { showToast('VM not found in cache', 'error'); return; }
    // Confirm destructive actions when Setup → Hypervisors asks for it (default on).
    if (['stop', 'reboot', 'restart', 'backup'].includes(action)) {
        const cfg = await pxmxHvConfig();
        if (cfg.confirm_destructive !== false &&
            !window.confirm(`${action.toUpperCase()} "${vm.name || vm.vmid}"?`)) return;
    }
    const statusEl = document.getElementById('pxmx-vm-action-status');
    const setStat = (msg) => { if (statusEl) statusEl.textContent = msg; };
    setStat(`${action}…`);
    try {
        const r = await setupFetch('/api/pxmx/vm-action', {
            method: 'POST',
            body: JSON.stringify({ unique_id: vm.unique_id, vmid: vm.vmid, node: vm.node, type: vm.type, action })
        });
        const data = await r.json().catch(() => ({}));
        if (r.ok && data && data.status === 'SUCCESS') {
            showToast(`${action} succeeded for ${vm.name || vm.vmid}`, 'success');
            setStat(`${action} done — refreshing`);
            setTimeout(() => loadPxmxData('Virtual Machines'), 1500);
        } else {
            showToast(`${action} failed: ${data && (data.message || data.detail) || r.status}`, 'error');
            setStat(`${action} failed`);
        }
    } catch (e) {
        showToast(`${action} failed: ${e.message || e}`, 'error');
        setStat(`${action} failed`);
    }
}

// Clone-from-template: opens a small modal prompting for the new VM's name (a
// free VMID is auto-assigned by the agent when left blank), then POSTs
// /api/pxmx/clone with the template unique_id. Templates are shared — any admin
// acting as a tenant may clone; the new VM is tagged with the acting tenant's
// proxmox_tag and shows up after the list refresh + VM sync. The hub enforces
// the template-pool membership server-side (UI affordance mirrors it).
async function pxmxCloneVm(uniqueId) {
    const vm = (window._pxmxVms || []).find(v => v.unique_id === uniqueId);
    if (!vm) { showToast('Template not found in cache', 'error'); return; }
    const escJs = s => String(s == null ? '' : s).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
    const baseName = `${(vm.name || 'vm').replace(/[^a-zA-Z0-9-]/g, '').toLowerCase().slice(0, 12) || 'vm'}-clone`;
    // Fetch the Proxmox resource pools so the user can place the new VM in one.
    let pools = [];
    try {
        const r = await fetch('/api/pxmx/pools');
        const d = r.ok ? await r.json() : {};
        pools = d.pools || [];
    } catch (e) { /* dropdown just stays empty */ }
    const poolOpts = ['<option value="">— no pool —</option>']
        .concat(pools.map(p => `<option value="${escapeHtml(p.poolid)}">${escapeHtml(p.poolid)}${p.cluster ? ' (' + escapeHtml(p.cluster) + ')' : ''}</option>`))
        .join('');
    const tpl = `<div id="pxmx-clone-modal" class="fixed inset-0 z-[60] flex items-center justify-center bg-black/40">
        <div class="bg-white rounded-lg shadow-xl w-full max-w-md p-5 space-y-4">
            <div class="flex items-center justify-between">
                <h3 class="text-base font-semibold text-[#263040]">Clone template</h3>
                <button onclick="document.getElementById('pxmx-clone-modal').remove()" class="text-slate-400 hover:text-slate-600 text-xl leading-none">×</button>
            </div>
            <p class="text-xs text-slate-500">Cloning <span class="font-mono">${escapeHtml(vm.name || '')}</span> (VMID ${vm.vmid}, pool ${escapeHtml(vm.pool || '—')}). The new VM is tagged with the current tenant name and starts stopped.</p>
            <label class="block text-xs font-medium text-slate-600">New VM name
                <input id="pxmx-clone-name" value="${escapeHtml(baseName)}" class="mt-1 w-full px-3 py-2 border border-slate-300 rounded-md text-sm font-mono" />
            </label>
            <label class="block text-xs font-medium text-slate-600">New VMID (optional — blank = auto-assign)
                <input id="pxmx-clone-vmid" placeholder="auto" class="mt-1 w-full px-3 py-2 border border-slate-300 rounded-md text-sm font-mono" />
            </label>
            <label class="block text-xs font-medium text-slate-600">Destination pool (optional)
                <select id="pxmx-clone-pool" class="mt-1 w-full px-3 py-2 border border-slate-300 rounded-md text-sm">${poolOpts}</select>
            </label>
            <div class="flex justify-end gap-2 pt-1">
                <button onclick="document.getElementById('pxmx-clone-modal').remove()" class="px-3 py-2 rounded-md text-sm font-medium text-slate-600 hover:bg-slate-100">Cancel</button>
                <button id="pxmx-clone-go" onclick="pxmxCloneVmSubmit('${escJs(vm.unique_id)}')" class="px-4 py-2 rounded-md text-sm font-bold bg-indigo-600 hover:bg-indigo-700 text-white">⧉ Clone</button>
            </div>
            <p id="pxmx-clone-status" class="text-xs text-slate-400"></p>
        </div>
    </div>`;
    // Remove any stale modal first, then mount at the document root so it
    // survives the pxmx-content re-render that openVmDetail replaced.
    const existing = document.getElementById('pxmx-clone-modal');
    if (existing) existing.remove();
    document.body.insertAdjacentHTML('beforeend', tpl);
    const nameInput = document.getElementById('pxmx-clone-name');
    if (nameInput) { nameInput.focus(); nameInput.select(); }
}

async function pxmxCloneVmSubmit(uniqueId) {
    const vm = (window._pxmxVms || []).find(v => v.unique_id === uniqueId);
    if (!vm) { showToast('Template not found in cache', 'error'); return; }
    const name = (document.getElementById('pxmx-clone-name') || {}).value || '';
    const vmidRaw = (document.getElementById('pxmx-clone-vmid') || {}).value || '';
    const pool = (document.getElementById('pxmx-clone-pool') || {}).value || '';
    const statusEl = document.getElementById('pxmx-clone-status');
    const goBtn = document.getElementById('pxmx-clone-go');
    const cleanName = name.trim();
    if (!cleanName) { if (statusEl) statusEl.textContent = 'Name is required'; return; }
    if (goBtn) { goBtn.disabled = true; goBtn.textContent = 'Cloning…'; }
    if (statusEl) statusEl.textContent = 'Cloning — a full-disk clone can take a minute…';
    const body = { template_unique_id: vm.unique_id, name: cleanName, type: vm.type || 'qemu' };
    const nvid = parseInt(vmidRaw, 10);
    if (vmidRaw.trim() && !isNaN(nvid)) body.new_vmid = nvid;
    if (pool) body.pool = pool;
    try {
        const r = await setupFetch('/api/pxmx/clone', { method: 'POST', body: JSON.stringify(body) });
        const data = await r.json().catch(() => ({}));
        if (r.ok && data && data.status === 'SUCCESS') {
            showToast(`Cloned to VMID ${data.vmid} (${data.name})`, 'success');
            const modal = document.getElementById('pxmx-clone-modal');
            if (modal) modal.remove();
            setTimeout(() => loadPxmxData('Virtual Machines'), 1200);
        } else {
            const msg = data && (data.detail || data.message) || r.status;
            showToast(`Clone failed: ${msg}`, 'error');
            if (statusEl) statusEl.textContent = `Failed: ${msg}`;
            if (goBtn) { goBtn.disabled = false; goBtn.textContent = '⧉ Clone'; }
        }
    } catch (e) {
        showToast(`Clone failed: ${e.message || e}`, 'error');
        if (statusEl) statusEl.textContent = `Failed: ${e.message || e}`;
        if (goBtn) { goBtn.disabled = false; goBtn.textContent = '⧉ Clone'; }
    }
}

// Build VM from ISO: a modal that lets the admin (acting as a tenant) define a
// new qemu VM that boots a Proxmox installer ISO. The user picks a node → the
// ISO list + disk-storage list for that node load (PXMX_LIST_ISOS /
// PXMX_LIST_STORAGES via /api/pxmx/isos + /api/pxmx/storages), then sets name,
// memory, cores, disk size, and an optional destination pool (from
// /api/pxmx/pools). On submit POST /api/pxmx/create-vm; the new VM is tagged
// with the tenant name (label) + proxmox_tag (VM-sync key) and left stopped —
// the user boots it and installs via the VNC console.
function pxmxOpenCreateVm() {
    const nodes = window._pxmxNodes || [];
    if (!nodes.length) { showToast('No Proxmox nodes available', 'error'); return; }
    const nodeOpts = nodes.map(n => `<option value="${escapeHtml(n.node)}">${escapeHtml(n.node)}${n.cluster ? ' (' + escapeHtml(n.cluster) + ')' : ''}</option>`).join('');
    const tpl = `<div id="pxmx-create-vm-modal" class="fixed inset-0 z-[60] flex items-center justify-center bg-black/40">
        <div class="bg-white rounded-lg shadow-xl w-full max-w-lg p-5 space-y-3">
            <div class="flex items-center justify-between">
                <h3 class="text-base font-semibold text-[#263040]">Build VM from ISO</h3>
                <button onclick="document.getElementById('pxmx-create-vm-modal').remove()" class="text-slate-400 hover:text-slate-600 text-xl leading-none">×</button>
            </div>
            <p class="text-xs text-slate-500">Define a new qemu VM that boots an installer ISO. The VM is tagged with the current tenant name and starts stopped — boot it from the Console button, install, then Start.</p>
            <div class="grid grid-cols-2 gap-3">
                <label class="block text-xs font-medium text-slate-600">Node
                    <select id="pxmx-cv-node" onchange="pxmxLoadNodeMedia()" class="mt-1 w-full px-3 py-2 border border-slate-300 rounded-md text-sm">${nodeOpts}</select>
                </label>
                <label class="block text-xs font-medium text-slate-600">VM name
                    <input id="pxmx-cv-name" value="new-vm" class="mt-1 w-full px-3 py-2 border border-slate-300 rounded-md text-sm font-mono" />
                </label>
                <label class="block text-xs font-medium text-slate-600 col-span-2">Installer ISO
                    <select id="pxmx-cv-iso" disabled class="mt-1 w-full px-3 py-2 border border-slate-300 rounded-md text-sm"><option value="">Loading ISOs…</option></select>
                </label>
                <label class="block text-xs font-medium text-slate-600">Disk storage
                    <select id="pxmx-cv-storage" disabled class="mt-1 w-full px-3 py-2 border border-slate-300 rounded-md text-sm"><option value="">Loading…</option></select>
                </label>
                <label class="block text-xs font-medium text-slate-600">Disk size (GB)
                    <input id="pxmx-cv-disk" type="number" min="1" value="32" class="mt-1 w-full px-3 py-2 border border-slate-300 rounded-md text-sm" />
                </label>
                <label class="block text-xs font-medium text-slate-600">Memory (MB)
                    <input id="pxmx-cv-mem" type="number" min="128" value="2048" class="mt-1 w-full px-3 py-2 border border-slate-300 rounded-md text-sm" />
                </label>
                <label class="block text-xs font-medium text-slate-600">CPU cores
                    <input id="pxmx-cv-cores" type="number" min="1" value="2" class="mt-1 w-full px-3 py-2 border border-slate-300 rounded-md text-sm" />
                </label>
                <label class="block text-xs font-medium text-slate-600 col-span-2">Destination pool (optional)
                    <select id="pxmx-cv-pool" class="mt-1 w-full px-3 py-2 border border-slate-300 rounded-md text-sm"><option value="">— no pool —</option></select>
                </label>
            </div>
            <div class="flex justify-end gap-2 pt-1">
                <button onclick="document.getElementById('pxmx-create-vm-modal').remove()" class="px-3 py-2 rounded-md text-sm font-medium text-slate-600 hover:bg-slate-100">Cancel</button>
                <button id="pxmx-cv-go" onclick="pxmxCreateVmSubmit()" class="px-4 py-2 rounded-md text-sm font-bold bg-indigo-600 hover:bg-indigo-700 text-white">＋ Create VM</button>
            </div>
            <p id="pxmx-cv-status" class="text-xs text-slate-400"></p>
        </div>
    </div>`;
    const existing = document.getElementById('pxmx-create-vm-modal');
    if (existing) existing.remove();
    document.body.insertAdjacentHTML('beforeend', tpl);
    // Load ISOs + storages for the preselected node, and the pool list.
    pxmxLoadNodeMedia();
    pxmxLoadCreatePools();
}

async function pxmxLoadNodeMedia() {
    const nodeSel = document.getElementById('pxmx-cv-node');
    const isoSel = document.getElementById('pxmx-cv-iso');
    const stSel = document.getElementById('pxmx-cv-storage');
    if (!nodeSel) return;
    const node = nodeSel.value;
    if (isoSel) { isoSel.disabled = true; isoSel.innerHTML = '<option value="">Loading ISOs…</option>'; }
    if (stSel) { stSel.disabled = true; stSel.innerHTML = '<option value="">Loading…</option>'; }
    try {
        const [isoR, stR] = await Promise.all([
            fetch(`/api/pxmx/isos?node=${encodeURIComponent(node)}`),
            fetch(`/api/pxmx/storages?node=${encodeURIComponent(node)}&content=images`),
        ]);
        const isoD = isoR.ok ? await isoR.json() : {};
        const stD = stR.ok ? await stR.json() : {};
        const isos = isoD.isos || [];
        const storages = stD.storages || [];
        if (isoSel) {
            isoSel.innerHTML = isos.length
                ? isos.map(i => `<option value="${escapeHtml(i.volid)}">${escapeHtml(i.name || i.volid)}</option>`).join('')
                : '<option value="">— no ISOs on this node —</option>';
            isoSel.disabled = isos.length === 0;
        }
        if (stSel) {
            stSel.innerHTML = storages.length
                ? storages.map(s => `<option value="${escapeHtml(s.storage)}">${escapeHtml(s.storage)} (${Math.round((s.avail || 0) / 1e9)} GB free)</option>`).join('')
                : '<option value="">— no image storage —</option>';
            stSel.disabled = storages.length === 0;
        }
    } catch (e) {
        if (isoSel) { isoSel.innerHTML = '<option value="">Failed to load ISOs</option>'; }
        if (stSel) { stSel.innerHTML = '<option value="">Failed to load storages</option>'; }
    }
}

async function pxmxLoadCreatePools() {
    const poolSel = document.getElementById('pxmx-cv-pool');
    if (!poolSel) return;
    try {
        const r = await fetch('/api/pxmx/pools');
        const d = r.ok ? await r.json() : {};
        const pools = d.pools || [];
        poolSel.innerHTML = '<option value="">— no pool —</option>'
            + pools.map(p => `<option value="${escapeHtml(p.poolid)}">${escapeHtml(p.poolid)}${p.cluster ? ' (' + escapeHtml(p.cluster) + ')' : ''}</option>`).join('');
    } catch (e) { /* leave default */ }
}

async function pxmxCreateVmSubmit() {
    const get = id => (document.getElementById(id) || {}).value || '';
    const body = {
        node: get('pxmx-cv-node'),
        name: get('pxmx-cv-name').trim(),
        volid: get('pxmx-cv-iso'),
        disk_storage: get('pxmx-cv-storage'),
        disk_gb: parseInt(get('pxmx-cv-disk'), 10) || 32,
        memory_mb: parseInt(get('pxmx-cv-mem'), 10) || 2048,
        cores: parseInt(get('pxmx-cv-cores'), 10) || 2,
        pool: get('pxmx-cv-pool'),
    };
    const statusEl = document.getElementById('pxmx-cv-status');
    const goBtn = document.getElementById('pxmx-cv-go');
    if (!body.name) { if (statusEl) statusEl.textContent = 'Name is required'; return; }
    if (!body.volid) { if (statusEl) statusEl.textContent = 'Pick an ISO'; return; }
    if (!body.disk_storage) { if (statusEl) statusEl.textContent = 'Pick a disk storage'; return; }
    if (goBtn) { goBtn.disabled = true; goBtn.textContent = 'Creating…'; }
    if (statusEl) statusEl.textContent = 'Creating VM (defines + tags)…';
    try {
        const r = await setupFetch('/api/pxmx/create-vm', { method: 'POST', body: JSON.stringify(body) });
        const data = await r.json().catch(() => ({}));
        if (r.ok && data && data.status === 'SUCCESS') {
            showToast(`Created VMID ${data.vmid} (${data.name}) — boot it from Console to install`, 'success');
            const modal = document.getElementById('pxmx-create-vm-modal');
            if (modal) modal.remove();
            setTimeout(() => loadPxmxData('Virtual Machines'), 1200);
        } else {
            const msg = data && (data.detail || data.message) || r.status;
            showToast(`Create failed: ${msg}`, 'error');
            if (statusEl) statusEl.textContent = `Failed: ${msg}`;
            if (goBtn) { goBtn.disabled = false; goBtn.textContent = '＋ Create VM'; }
        }
    } catch (e) {
        showToast(`Create failed: ${e.message || e}`, 'error');
        if (statusEl) statusEl.textContent = `Failed: ${e.message || e}`;
        if (goBtn) { goBtn.disabled = false; goBtn.textContent = '＋ Create VM'; }
    }
}

// ── Console module (serial console access) ─────────────────────────────────
// Lists every connected Console spoke's serial ports and opens an xterm.js
// terminal wired to the hub's /ws/console-serial/{session_id} byte relay. xterm
// is dynamic-imported from CDN once (mirrors how noVNC is loaded below).
let _consolePorts = [];
let _xtermMod = null;

async function loadConsoleData() {
    const el = document.getElementById('console-container');
    if (!el) return;
    try {
        const res = await fetch('/api/console/ports', { credentials: 'same-origin' });
        if (!res.ok) {
            el.innerHTML = `<div class="py-12 text-center text-red-400 italic">${res.status === 403 ? 'Console module access required.' : 'Failed to load console ports (' + res.status + ').'}</div>`;
            return;
        }
        const data = await res.json();
        _consolePorts = data.ports || [];
        _renderConsolePorts(el, data);
    } catch (e) {
        el.innerHTML = `<div class="py-12 text-center text-red-400 italic">Error: ${escapeHtml(e.message)}</div>`;
    }
}

function _renderConsolePorts(el, data) {
    const ports = data.ports || [];
    const consoles = data.consoles || [];
    const admin = isAdmin();
    if (consoles.length === 0) {
        el.innerHTML = `<div class="py-12 text-center text-slate-400 italic">No Console agents connected. Load the <b>Console</b> role on a generic agent (Setup → Spokes &amp; Agents → Load Role).</div>`;
        return;
    }
    if (ports.length === 0) {
        el.innerHTML = `<div class="py-12 text-center text-slate-400 italic">${consoles.length} Console agent(s) connected, but no serial ports detected.</div>`;
        return;
    }
    const esc = s => (s || '').replace(/'/g, "\\'");
    const rows = ports.map(p => {
        const label = p.alias || p.product || p.device;
        const baud = (p.settings && p.settings.baud) || '—';
        const vendor = (p.probe && p.probe.vendor) || p.vendor || '';
        const inUse = p.in_use ? ` <span class="text-[10px] px-2 py-0.5 rounded-full bg-amber-100 text-amber-700 font-bold uppercase">In use</span>` : '';
        const tenant = p.tenant_id
            ? `<span class="font-mono text-xs text-slate-700">${escapeHtml(p.tenant_id)}</span>${p.tenant_override ? ' <span class="text-[9px] text-slate-400">(port)</span>' : ' <span class="text-[9px] text-slate-400">(agent)</span>'}`
            : '<span class="italic text-slate-400 text-xs">unassigned</span>';
        const eP = esc(p.port_id), eS = esc(p.spoke_id || ''), eT = esc(p.tenant_override || '');
        const tenantBtn = admin ? `<button onclick="openConsolePortTenantModal('${eS}','${eP}','${eT}')" class="text-[11px] px-2 py-1 rounded border border-[#01A982] text-[#01A982] hover:bg-slate-50">Tenant</button>` : '';
        const configBtn = hasConsoleWrite() ? `<button onclick="openConsoleConfigModal('${eS}','${eP}')" class="text-[11px] px-2 py-1 rounded border border-indigo-400 text-indigo-600 hover:bg-slate-50">Config</button>` : '';
        return `<tr class="hover:bg-slate-50">
            <td class="px-4 py-3"><div class="font-semibold text-slate-700">${escapeHtml(label)}${inUse}</div>
              <div class="text-xs font-mono text-slate-400">${escapeHtml(p.device)} · ${escapeHtml(p.port_id)}</div>
              ${p.probe && p.probe.vendor
                ? `<div class="text-xs mt-0.5"><span class="px-1.5 py-0.5 rounded bg-blue-100 text-blue-700 font-bold uppercase text-[9px]">${escapeHtml(p.probe.vendor)}</span> ${_consoleIdentitySummary(p.probe.identity)}</div>`
                : (vendor ? `<div class="text-xs text-slate-500">${escapeHtml(vendor)}</div>` : '')}</td>
            <td class="px-4 py-3 text-center text-sm">${baud}</td>
            <td class="px-4 py-3 text-xs font-mono text-slate-500">${escapeHtml(p.spoke_id || '')}</td>
            <td class="px-4 py-3">${tenant}</td>
            <td class="px-4 py-3 text-right whitespace-nowrap space-x-1">
              <button onclick="openConsoleTerminal('${eS}','${eP}')" class="text-[11px] px-2 py-1 rounded bg-[#01A982] hover:bg-[#008c6a] text-white font-bold">🖥 Open</button>
              <button onclick="consoleDetectBaud('${eS}','${eP}')" class="text-[11px] px-2 py-1 rounded border border-slate-300 hover:bg-slate-50">Detect baud</button>
              <button onclick="consoleIdentify('${eS}','${eP}')" class="text-[11px] px-2 py-1 rounded border border-slate-300 hover:bg-slate-50">Identify</button>
              <button onclick="openConsoleSettingsModal('${eS}','${eP}')" class="text-[11px] px-2 py-1 rounded border border-slate-300 hover:bg-slate-50">Settings</button>
              ${configBtn}
              ${tenantBtn}
            </td></tr>`;
    }).join('');
    const tools = admin
        ? `<div class="flex justify-end gap-2 p-2 border-b border-slate-100"><button onclick="openConsoleCredentialsModal()" class="text-[11px] px-3 py-1.5 rounded border border-slate-300 hover:bg-slate-50">🔑 Credentials</button></div>`
        : '';
    el.innerHTML = `${tools}<div class="p-0 overflow-hidden"><table class="w-full text-left text-sm">
        <thead class="bg-slate-100 text-slate-600 uppercase text-xs"><tr>
          <th class="px-4 py-3">Port</th><th class="px-4 py-3 text-center">Baud</th>
          <th class="px-4 py-3">Console agent</th><th class="px-4 py-3">Tenant</th>
          <th class="px-4 py-3 text-right">Actions</th></tr></thead>
        <tbody class="divide-y divide-slate-200">${rows}</tbody></table></div>`;
}

function _consoleIdentitySummary(identity) {
    if (!identity) return '';
    const parts = [];
    if (identity.serial) parts.push('SN ' + escapeHtml(identity.serial));
    if (identity.model) parts.push(escapeHtml(identity.model));
    if (identity.mac) parts.push(escapeHtml(identity.mac));
    if (identity.ip) parts.push(escapeHtml(identity.ip));
    return parts.length ? `<span class="text-slate-500">${parts.join(' · ')}</span>` : '';
}

async function consoleIdentify(spokeId, portId) {
    showToast('Identifying device (baud + banner + login + harvest)…', 'info');
    try {
        const res = await fetch('/api/console/identify', {
            method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ spoke_id: spokeId, port_id: portId }),
        });
        const d = await res.json().catch(() => ({}));
        if (res.ok) {
            showToast(d.vendor ? `Identified: ${d.vendor}${d.logged_in ? ' (logged in)' : ''}` : 'No device identified', d.vendor ? 'success' : 'info');
            loadConsoleData();
        } else showToast(d.detail || 'Identify failed', 'error');
    } catch (e) { showToast('Identify failed: ' + e.message, 'error'); }
}

async function openConsoleCredentialsModal() {
    const modal = document.createElement('div');
    modal.id = 'console-creds-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm';
    let existing = [];
    try {
        const res = await fetch('/api/console/credentials', { credentials: 'same-origin' });
        if (res.ok) existing = (await res.json()).credentials || [];
    } catch (e) { console.error(e); }
    const rowFor = (u) => `<div class="flex gap-2 console-cred-row">
        <input class="console-cred-user flex-1 border border-slate-300 rounded-md px-3 py-2 text-sm" placeholder="username" value="${(u || '').replace(/"/g, '&quot;')}">
        <input class="console-cred-pass flex-1 border border-slate-300 rounded-md px-3 py-2 text-sm" type="password" placeholder="password (blank = keep)">
        <button onclick="this.closest('.console-cred-row').remove()" class="px-2 text-red-400 hover:text-red-600">&times;</button></div>`;
    modal.innerHTML = `<div class="bg-white rounded-xl shadow-2xl w-full max-w-lg overflow-hidden">
        <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50">
          <h3 class="text-lg font-bold text-[#263040]">Console Credential Library</h3>
          <button onclick="this.closest('#console-creds-modal').remove()" class="text-slate-400 hover:text-slate-600 text-2xl leading-none">&times;</button>
        </div>
        <div class="p-6 space-y-3">
          <p class="text-[11px] text-slate-400">Tried in order during auto-identify. Stored encrypted on the hub and pushed to Console agents; passwords are never displayed back. Leave a password blank to keep the stored one.</p>
          <div id="console-cred-rows" class="space-y-2">${(existing.length ? existing.map(c => rowFor(c.username)).join('') : rowFor(''))}</div>
          <button onclick="document.getElementById('console-cred-rows').insertAdjacentHTML('beforeend', _consoleCredRowHtml())" class="text-[11px] px-3 py-1 rounded border border-slate-300 hover:bg-slate-50">+ Add credential</button>
          <div class="pt-3 flex justify-end gap-3">
            <button onclick="this.closest('#console-creds-modal').remove()" class="px-4 py-2 text-sm text-slate-600">Cancel</button>
            <button onclick="saveConsoleCredentials()" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-6 py-2 rounded-md text-sm font-bold">Save</button>
          </div>
        </div></div>`;
    document.body.appendChild(modal);
}

function _consoleCredRowHtml() {
    return `<div class="flex gap-2 console-cred-row">
        <input class="console-cred-user flex-1 border border-slate-300 rounded-md px-3 py-2 text-sm" placeholder="username">
        <input class="console-cred-pass flex-1 border border-slate-300 rounded-md px-3 py-2 text-sm" type="password" placeholder="password">
        <button onclick="this.closest('.console-cred-row').remove()" class="px-2 text-red-400 hover:text-red-600">&times;</button></div>`;
}

async function saveConsoleCredentials() {
    const rows = Array.from(document.querySelectorAll('.console-cred-row'));
    const credentials = rows.map(r => ({
        username: r.querySelector('.console-cred-user').value.trim(),
        password: r.querySelector('.console-cred-pass').value,
    })).filter(c => c.username);
    try {
        const res = await fetch('/api/console/credentials', {
            method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ credentials }),
        });
        if (res.ok) { showToast('Credentials saved', 'success'); document.getElementById('console-creds-modal')?.remove(); }
        else { const d = await res.json().catch(() => ({})); showToast(d.detail || 'Save failed', 'error'); }
    } catch (e) { showToast('Save failed: ' + e.message, 'error'); }
}

async function _consoleLoadXterm() {
    if (_xtermMod) return _xtermMod;
    if (!document.getElementById('xterm-css')) {
        const link = document.createElement('link');
        link.id = 'xterm-css'; link.rel = 'stylesheet';
        link.href = 'https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/css/xterm.min.css';
        document.head.appendChild(link);
    }
    try {
        _xtermMod = await import('https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/+esm');
    } catch (e) {
        console.error('xterm load failed', e);
        return null;
    }
    return _xtermMod;
}

async function openConsoleTerminal(spokeId, portId) {
    const mod = await _consoleLoadXterm();
    if (!mod || !mod.Terminal) { showToast('Failed to load terminal (CDN unreachable)', 'error'); return; }
    let session;
    try {
        const res = await fetch('/api/console/open', {
            method: 'POST', credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ spoke_id: spokeId, port_id: portId, mode: 'rw' }),
        });
        session = await res.json().catch(() => ({}));
        if (!res.ok) { showToast(session.detail || 'Open failed', 'error'); return; }
    } catch (e) { showToast('Open failed: ' + e.message, 'error'); return; }
    _consoleShowTerminalModal(portId, session, mod.Terminal);
}

function _consoleShowTerminalModal(portId, session, Terminal) {
    closeConsoleTerminal();
    const modal = document.createElement('div');
    modal.id = 'console-term-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-70 backdrop-blur-sm';
    const ro = !!session.read_only;
    modal.innerHTML = `<div class="bg-[#1e1e1e] rounded-xl shadow-2xl w-full max-w-4xl overflow-hidden flex flex-col" style="height:72vh">
        <div class="px-4 py-2 flex justify-between items-center bg-[#2d2d2d] text-slate-200">
          <div class="text-sm font-mono">${escapeHtml(portId)}${ro ? ' <span class="text-[10px] px-2 py-0.5 rounded bg-amber-600 text-white">READ-ONLY</span>' : ''}${session.settings && session.settings.baud ? ' <span class="text-[10px] text-slate-400">@' + session.settings.baud + '</span>' : ''}</div>
          <button onclick="closeConsoleTerminal()" class="text-slate-300 hover:text-white text-2xl leading-none">&times;</button>
        </div>
        <div id="console-term-body" class="flex-1 p-1 overflow-hidden bg-[#1e1e1e]"></div>
      </div>`;
    document.body.appendChild(modal);
    const term = new Terminal({ cursorBlink: true, fontSize: 13, scrollback: 5000,
                                theme: { background: '#1e1e1e' } });
    term.open(document.getElementById('console-term-body'));
    term.focus();
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    const ws = new WebSocket(`${proto}://${location.host}/ws/console-serial/${session.session_id}?token=${encodeURIComponent(session.ws_token)}`);
    ws.binaryType = 'arraybuffer';
    ws.onmessage = (ev) => {
        if (typeof ev.data === 'string') term.write(ev.data);
        else term.write(new Uint8Array(ev.data));
    };
    ws.onclose = (ev) => { try { term.write(`\r\n\x1b[33m[disconnected${ev.reason ? ': ' + ev.reason : ''}]\x1b[0m\r\n`); } catch (e) {} };
    if (!ro) term.onData(d => { if (ws.readyState === 1) ws.send(d); });
    window.__consoleTerm = { term, ws, modal };
}

function closeConsoleTerminal() {
    const c = window.__consoleTerm;
    if (c) {
        try { c.ws.close(); } catch (e) {}
        try { c.term.dispose(); } catch (e) {}
        try { c.modal.remove(); } catch (e) {}
        window.__consoleTerm = null;
        if (typeof currentView !== 'undefined' && currentView === 'console') loadConsoleData();
    }
}

async function consoleDetectBaud(spokeId, portId) {
    showToast('Detecting baud rate…', 'info');
    try {
        const res = await fetch('/api/console/detect-baud', {
            method: 'POST', credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ spoke_id: spokeId, port_id: portId }),
        });
        const d = await res.json().catch(() => ({}));
        if (res.ok && d.baud) { showToast(`Detected ${d.baud} baud (score ${d.score})`, 'success'); loadConsoleData(); }
        else showToast(d.detail || d.message || 'No baud rate detected', 'error');
    } catch (e) { showToast('Detect failed: ' + e.message, 'error'); }
}

function openConsoleSettingsModal(spokeId, portId) {
    const p = _consolePorts.find(x => x.port_id === portId && x.spoke_id === spokeId) || {};
    const s = p.settings || {};
    const bauds = [1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200, 230400];
    const baudOpts = bauds.map(b => `<option value="${b}" ${Number(s.baud) === b ? 'selected' : ''}>${b}</option>`).join('');
    const parOpts = ['N', 'E', 'O'].map(x => `<option value="${x}" ${(s.parity || 'N') === x ? 'selected' : ''}>${x}</option>`).join('');
    const flowOpts = ['none', 'rtscts', 'xonxoff'].map(x => `<option value="${x}" ${(s.flow || 'none') === x ? 'selected' : ''}>${x}</option>`).join('');
    const modal = document.createElement('div');
    modal.id = 'console-settings-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm';
    modal.innerHTML = `<div class="bg-white rounded-xl shadow-2xl w-full max-w-md overflow-hidden">
        <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50">
          <h3 class="text-lg font-bold text-[#263040]">Port Settings</h3>
          <button onclick="this.closest('#console-settings-modal').remove()" class="text-slate-400 hover:text-slate-600 text-2xl leading-none">&times;</button>
        </div>
        <div class="p-6 space-y-4">
          <div class="text-xs font-mono text-slate-400">${escapeHtml(portId)}</div>
          <div><label class="text-xs text-slate-500 uppercase font-bold">Alias</label>
            <input id="console-cfg-alias" value="${(p.alias || '').replace(/"/g, '&quot;')}" class="w-full border border-slate-300 rounded-md px-3 py-2 text-sm mt-1"></div>
          <div class="grid grid-cols-3 gap-3">
            <div><label class="text-xs text-slate-500 uppercase font-bold">Baud</label><select id="console-cfg-baud" class="w-full border border-slate-300 rounded-md px-2 py-2 text-sm mt-1">${baudOpts}</select></div>
            <div><label class="text-xs text-slate-500 uppercase font-bold">Parity</label><select id="console-cfg-parity" class="w-full border border-slate-300 rounded-md px-2 py-2 text-sm mt-1">${parOpts}</select></div>
            <div><label class="text-xs text-slate-500 uppercase font-bold">Flow</label><select id="console-cfg-flow" class="w-full border border-slate-300 rounded-md px-2 py-2 text-sm mt-1">${flowOpts}</select></div>
          </div>
          <div class="pt-3 flex justify-end gap-3">
            <button onclick="this.closest('#console-settings-modal').remove()" class="px-4 py-2 text-sm text-slate-600">Cancel</button>
            <button onclick="saveConsoleSettings('${spokeId.replace(/'/g, "\\'")}','${portId.replace(/'/g, "\\'")}')" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-6 py-2 rounded-md text-sm font-bold">Save</button>
          </div>
        </div></div>`;
    document.body.appendChild(modal);
}

async function saveConsoleSettings(spokeId, portId) {
    const alias = document.getElementById('console-cfg-alias').value;
    const body = {
        spoke_id: spokeId, port_id: portId,
        baud: parseInt(document.getElementById('console-cfg-baud').value, 10),
        parity: document.getElementById('console-cfg-parity').value,
        flow: document.getElementById('console-cfg-flow').value,
    };
    try {
        // Alias is a separate command on the spoke; send it first if changed.
        await fetch('/api/console/settings', {
            method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ spoke_id: spokeId, port_id: portId, alias }),
        });
        const res = await fetch('/api/console/settings', {
            method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        if (res.ok) { showToast('Settings saved', 'success'); document.getElementById('console-settings-modal')?.remove(); loadConsoleData(); }
        else { const d = await res.json().catch(() => ({})); showToast(d.detail || 'Save failed', 'error'); }
    } catch (e) { showToast('Save failed: ' + e.message, 'error'); }
}

async function openConsolePortTenantModal(spokeId, portId, currentTenantId) {
    const modal = document.createElement('div');
    modal.id = 'console-port-tenant-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm';
    let tenantOptions = '';
    try {
        const res = await setupFetch('/setup/tenants');
        if (res.ok) {
            const tenants = (await res.json()).tenants || [];
            tenantOptions = tenants.map(t => `<option value="${t.id}" ${t.id === currentTenantId ? 'selected' : ''}>${escapeHtml(t.name)}</option>`).join('');
        }
    } catch (e) { console.error('tenant fetch failed', e); }
    modal.innerHTML = `<div class="bg-white rounded-xl shadow-2xl w-full max-w-md overflow-hidden">
        <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50">
          <h3 class="text-lg font-bold text-[#263040]">Assign Port to Tenant</h3>
          <button onclick="this.closest('#console-port-tenant-modal').remove()" class="text-slate-400 hover:text-slate-600 text-2xl leading-none">&times;</button>
        </div>
        <div class="p-6 space-y-4">
          <div class="text-xs font-mono text-slate-400">${escapeHtml(portId)}</div>
          <p class="text-[11px] text-slate-400">A per-port override. Leave <b>(inherit agent)</b> to fall back to the whole console agent's tenant.</p>
          <select id="console-port-tenant" class="w-full border border-slate-300 rounded-md px-3 py-2 text-sm">
            <option value="" ${!currentTenantId ? 'selected' : ''}>(inherit agent)</option>${tenantOptions}
          </select>
          <div class="pt-3 flex justify-end gap-3">
            <button onclick="this.closest('#console-port-tenant-modal').remove()" class="px-4 py-2 text-sm text-slate-600">Cancel</button>
            <button onclick="saveConsolePortTenant('${spokeId.replace(/'/g, "\\'")}','${portId.replace(/'/g, "\\'")}')" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-6 py-2 rounded-md text-sm font-bold">Assign</button>
          </div>
        </div></div>`;
    document.body.appendChild(modal);
}

async function saveConsolePortTenant(spokeId, portId) {
    const tenantId = document.getElementById('console-port-tenant').value;
    try {
        const res = await fetch('/api/console/tenant', {
            method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ spoke_id: spokeId, port_id: portId, tenant_id: tenantId }),
        });
        if (res.ok) { showToast('Port tenant updated', 'success'); document.getElementById('console-port-tenant-modal')?.remove(); loadConsoleData(); }
        else { const d = await res.json().catch(() => ({})); showToast(d.detail || 'Assign failed', 'error'); }
    } catch (e) { showToast('Assign failed: ' + e.message, 'error'); }
}

function openConsoleConfigModal(spokeId, portId) {
    const eS = spokeId.replace(/'/g, "\\'"), eP = portId.replace(/'/g, "\\'");
    const modal = document.createElement('div');
    modal.id = 'console-config-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm';
    modal.innerHTML = `<div class="bg-white rounded-xl shadow-2xl w-full max-w-2xl overflow-hidden flex flex-col" style="max-height:85vh">
        <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50">
          <h3 class="text-lg font-bold text-[#263040]">Device Config — ${escapeHtml(portId)}</h3>
          <button onclick="this.closest('#console-config-modal').remove()" class="text-slate-400 hover:text-slate-600 text-2xl leading-none">&times;</button>
        </div>
        <div class="p-6 space-y-3 overflow-y-auto">
          <p class="text-[11px] text-slate-400">Requires the device to have been Identified. Push is transactional — verify before + after, save on success, roll back on failure (a failed push is never saved).</p>
          <button onclick="consoleConfigBackup('${eS}','${eP}')" class="text-[11px] px-3 py-1.5 rounded border border-slate-300 hover:bg-slate-50">⤓ Read / backup running-config</button>
          <textarea id="console-config-text" rows="10" placeholder="Paste config to push (one command per line)…" class="w-full border border-slate-300 rounded-md px-3 py-2 text-sm font-mono"></textarea>
          <div class="flex items-center gap-4 text-sm flex-wrap">
            <label class="flex items-center gap-2"><input type="checkbox" id="console-config-save" checked class="rounded border-slate-300"> Save to startup on success</label>
            <label class="flex items-center gap-2">Rollback on fail:
              <select id="console-config-rollback" class="border border-slate-300 rounded px-2 py-1 text-sm"><option value="negate">no &lt;command&gt;</option><option value="reboot">reboot</option></select></label>
          </div>
          <pre id="console-config-output" class="text-xs bg-slate-900 text-slate-100 rounded-md p-3 overflow-auto hidden" style="max-height:240px"></pre>
          <div class="pt-2 flex justify-end gap-3">
            <button onclick="this.closest('#console-config-modal').remove()" class="px-4 py-2 text-sm text-slate-600">Close</button>
            <button onclick="consoleConfigPush('${eS}','${eP}')" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-6 py-2 rounded-md text-sm font-bold">Push config</button>
          </div>
        </div></div>`;
    document.body.appendChild(modal);
}

function _consoleConfigOut(text, isErr) {
    const el = document.getElementById('console-config-output');
    if (!el) return;
    el.classList.remove('hidden');
    el.textContent = text;
    el.classList.toggle('text-red-300', !!isErr);
}

async function consoleConfigBackup(spokeId, portId) {
    _consoleConfigOut('Reading running-config…', false);
    try {
        const res = await fetch('/api/console/config/get', {
            method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ spoke_id: spokeId, port_id: portId }),
        });
        const d = await res.json().catch(() => ({}));
        if (res.ok && d.status === 'SUCCESS') _consoleConfigOut(d.config || '(empty)', false);
        else _consoleConfigOut(d.message || d.detail || 'Backup failed', true);
    } catch (e) { _consoleConfigOut('Backup failed: ' + e.message, true); }
}

async function consoleConfigPush(spokeId, portId) {
    const config = document.getElementById('console-config-text').value;
    if (!config.trim()) { showToast('Nothing to push', 'error'); return; }
    _consoleConfigOut('Pushing + verifying…', false);
    try {
        const res = await fetch('/api/console/config/push', {
            method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                spoke_id: spokeId, port_id: portId, config,
                save: document.getElementById('console-config-save').checked,
                rollback: document.getElementById('console-config-rollback').value,
            }),
        });
        const d = await res.json().catch(() => ({}));
        const summary = `status: ${d.status}\nverify_ok: ${d.verify_ok}   saved: ${d.saved}   rolled_back: ${d.rolled_back}\n`
            + ((d.errors && d.errors.length) ? `errors:\n${d.errors.map(e => '  ' + e.line + ' → ' + (e.output || '')).join('\n')}\n` : '')
            + ((d.missing && d.missing.length) ? `missing after push:\n  ${d.missing.join('\n  ')}\n` : '')
            + (d.message ? '\n' + d.message : '');
        _consoleConfigOut(summary, d.status !== 'SUCCESS');
        showToast(d.status === 'SUCCESS' ? 'Config pushed + saved' : 'Push failed — rolled back',
                  d.status === 'SUCCESS' ? 'success' : 'error');
    } catch (e) { _consoleConfigOut('Push failed: ' + e.message, true); }
}

// VNC console opener (agent-terminates-WSS): POST /api/pxmx/console to mint a
// one-shot session, then open a modal hosting noVNC whose RFB connects to the
// hub's /ws/console/{session_id}?token=... byte relay. The hub relays browser
// bytes → agent (VNC_FRAME_DOWN) and Proxmox bytes → browser (VNC_FRAME_UP);
// the agent owns the Proxmox vncwebsocket (local root-authed token). noVNC is
// loaded once from CDN and cached on window.__noVNCRFB.
async function pxmxOpenConsole(uniqueId) {
    const vm = (window._pxmxVms || []).find(v => v.unique_id === uniqueId);
    if (!vm) { showToast('VM not found in cache', 'error'); return; }
    // Immediate feedback — the agent opens the Proxmox vncwebsocket + mints the
    // first-use VNC token, which can take several seconds on a busy host.
    showToast(`Connecting to console for ${vm.name || vm.vmid}…`, 'info');
    const _btn = document.getElementById('pxmx-vm-console-btn');
    const _btnHtml = _btn ? _btn.innerHTML : null;
    if (_btn) { _btn.disabled = true; _btn.innerHTML = '⏳ Connecting…'; }
    const _restoreBtn = () => { if (_btn && _btnHtml != null) { _btn.disabled = false; _btn.innerHTML = _btnHtml; } };
    let session;
    try {
        const r = await setupFetch('/api/pxmx/console', {
            method: 'POST',
            body: JSON.stringify({ unique_id: vm.unique_id, vmid: vm.vmid, node: vm.node, type: vm.type || 'qemu', agent_id: vm.agent_id || '' }),
        });
        session = await r.json().catch(() => ({}));
        if (!r.ok || !session || !session.session_id) {
            _restoreBtn();
            showToast('Console start failed: ' + (session && (session.detail || session.message) || r.status), 'error');
            return;
        }
    } catch (e) {
        _restoreBtn();
        showToast('Console start failed: ' + (e.message || e), 'error');
        return;
    }
    const RFB = await pxmxLoadNoVNC();
    if (!RFB) { _restoreBtn(); showToast('Failed to load noVNC (CDN unreachable)', 'error'); return; }
    _restoreBtn();
    pxmxShowVncModal(vm, RFB, session);
}

// Load noVNC's RFB from CDN once, cache on window.__noVNCRFB. Mirrors the
// upstream cs reference (.scratch-shpe/cs-webui/templates/index.html:10).
let _pxmxNoVncPromise = null;
function pxmxLoadNoVNC() {
    if (window.__noVNCRFB) return Promise.resolve(window.__noVNCRFB);
    if (!_pxmxNoVncPromise) {
        _pxmxNoVncPromise = import('https://cdn.jsdelivr.net/npm/@novnc/novnc@1.4.0/core/rfb.js')
            .then(m => { window.__noVNCRFB = m.RFB || m.default; return window.__noVNCRFB; })
            .catch(e => { console.error('noVNC load failed', e); _pxmxNoVncPromise = null; return null; });
    }
    return _pxmxNoVncPromise;
}

// Build the modal DOM, attach the RFB, wire status + Ctrl+Alt+Del + close.
// Closing the modal drops the RFB (closes the WS → hub sends VNC_DISCONNECT →
// agent closes the Proxmox WSS). Returns nothing.
function pxmxShowVncModal(vm, RFB, session) {
    let modal = document.getElementById('pxmx-vnc-modal');
    if (modal) modal.remove();
    modal = document.createElement('div');
    modal.id = 'pxmx-vnc-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black/70';
    modal.innerHTML = `
        <div class="bg-[#1a1a2e] rounded-lg shadow-2xl w-[90vw] max-w-5xl h-[85vh] flex flex-col overflow-hidden">
            <div class="flex items-center gap-3 px-4 py-2 bg-[#16213e] border-b border-slate-700 text-slate-200 text-sm">
                <strong class="font-semibold">VM Console — ${escapeHtml(vm.name || vm.vmid)}</strong>
                <span class="text-xs text-slate-400 font-mono">${escapeHtml(vm.unique_id || '')}</span>
                <button id="pxmx-vnc-cad" class="ml-2 px-2 py-0.5 text-xs rounded border border-slate-500 hover:bg-slate-700">Ctrl+Alt+Del</button>
                <button id="pxmx-vnc-fs" class="px-2 py-0.5 text-xs rounded border border-slate-500 hover:bg-slate-700">Fullscreen</button>
                <span id="pxmx-vnc-status" class="ml-auto text-xs text-amber-400">Connecting…</span>
                <button id="pxmx-vnc-close" class="ml-3 text-slate-400 hover:text-red-400 text-lg leading-none">&times;</button>
            </div>
            <div id="pxmx-vnc-screen" class="flex-1 bg-black"></div>
        </div>`;
    document.body.appendChild(modal);
    const statusEl = modal.querySelector('#pxmx-vnc-status');
    const setStatus = (msg, cls) => { statusEl.textContent = msg; statusEl.className = 'ml-auto text-xs ' + (cls || 'text-amber-400'); };
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${proto}//${location.host}/ws/console/${encodeURIComponent(session.session_id)}?token=${encodeURIComponent(session.ws_token)}`;
    let rfb = null;
    try {
        // Proxmox's vncwebsocket ticket doubles as the RFB VNC password — the
        // agent mints it and the hub returns it in the /api/pxmx/console
        // response. noVNC must present it during the RFB security handshake or
        // Proxmox drops the session ("Security failure" / blank console).
        const vncPassword = (session && session.ticket) || '';
        rfb = new RFB(modal.querySelector('#pxmx-vnc-screen'), wsUrl, { credentials: { password: vncPassword } });
        rfb.scaleViewport = true;
        rfb.resizeSession = false;
        rfb.addEventListener('connect', () => setStatus('Connected', 'text-green-400'));
        rfb.addEventListener('disconnect', (e) => setStatus('Disconnected: ' + ((e.detail && e.detail.reason) || 'closed'), 'text-red-400'));
        rfb.addEventListener('credentialsrequired', () => {
            // Ticket already supplied above; if Proxmox still asks, re-send it
            // rather than prompting the user for a password they don't have.
            if (vncPassword) rfb.sendCredentials({ password: vncPassword });
        });
        rfb.addEventListener('securityfailure', (e) => setStatus('Security failure: ' + ((e.detail && e.detail.reason) || 'unknown'), 'text-red-400'));
    } catch (err) {
        setStatus('Error: ' + (err.message || err), 'text-red-400');
    }
    modal.querySelector('#pxmx-vnc-cad').onclick = () => rfb && rfb.sendCtrlAltDel();
    modal.querySelector('#pxmx-vnc-fs').onclick = () => {
        const screen = modal.querySelector('#pxmx-vnc-screen');
        if (document.fullscreenElement) document.exitFullscreen();
        else screen.requestFullscreen && screen.requestFullscreen().catch(() => {});
    };
    const close = () => {
        try { if (rfb) rfb.disconnect(); } catch (e) {}
        modal.remove();
    };
    modal.querySelector('#pxmx-vnc-close').onclick = close;
    modal.onclick = (e) => { if (e.target === modal) close(); };
}

// Render the clickable Nodes table; the selected row is highlighted.
// Short Proxmox version for table display: 'pve-manager/9.2.3/abc123' -> '9.2.3'.
// Falls back to the raw string if no N.N.N group is found, or '' when absent.
function pxmxShortVer(v) {
    if (v == null || v === '') return '';
    const m = String(v).match(/(\d+\.\d+\.\d+)/);
    return m ? m[1] : String(v);
}

function renderPxmxNodes() {
    const wrap = document.getElementById('pxmx-nodes-wrap');
    if (!wrap) return;
    const nodes = window._pxmxNodes || [];
    const sel = window._pxmxNodeSel;
    const cols = ['Cluster', 'Node', 'Status', 'CPU %', 'Cores', 'RAM Used', 'RAM Total', 'Version'];
    const escAttr = s => String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/"/g, '&quot;');
    const escJs   = s => String(s == null ? '' : s).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
    const rows = nodes.map(n => {
        const key        = pxmxNodeKey(n.cluster, n.node);
        const ramUsedGb  = ((n.mem_used  || 0) / 1073741824).toFixed(1);
        const ramTotalGb = ((n.mem_total || 0) / 1073741824).toFixed(1);
        const statusCls  = n.status === 'online' ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700';
        const selCls     = key === sel ? 'bg-green-50 ring-1 ring-green-300' : 'hover:bg-slate-50';
        return `<tr data-node-key="${escAttr(key)}" onclick="openNodeVms('${escJs(key)}')" class="border-b border-slate-100 cursor-pointer ${selCls}">
            <td class="px-4 py-2 text-xs text-slate-500">${n.cluster || '—'}</td>
            <td class="px-4 py-2 font-medium">${n.node}</td>
            <td class="px-4 py-2"><span class="px-2 py-0.5 rounded-full text-xs font-medium ${statusCls}">${n.status}</span></td>
            <td class="px-4 py-2">${n.cpu_usage ?? '—'}%</td>
            <td class="px-4 py-2">${n.cpu_cores ?? '—'}</td>
            <td class="px-4 py-2">${ramUsedGb} GB</td>
            <td class="px-4 py-2">${ramTotalGb} GB</td>
            <td class="px-4 py-2 text-xs text-slate-400">${pxmxShortVer(n.proxmox_version) || '—'}</td>
        </tr>`;
    }).join('');
    wrap.innerHTML = pxmxTableWrap(pxmxTh(cols) + `<tbody>${rows}</tbody>`);
}

// Clicking a node on the Nodes tab sets it as the VM filter and navigates to the
// Virtual Machines tab, which renders scoped to that node. The one-shot
// _pxmxNodeFilterPending flag lets loadPxmxData('Virtual Machines') tell apart
// "arrived via a node click" (scoped) from "clicked the tab directly" (all VMs).
function openNodeVms(key) {
    window._pxmxNodeSel = key;
    window._pxmxNodeFilterPending = true;
    setSubView('Virtual Machines');
}

// HTML for a node's summary card + that node's VMs. Used by the scoped
// Virtual Machines view (entered via openNodeVms). Returns '' if the node
// isn't in the cached nodes list.
function pxmxNodeDetailHtml(node, vms) {
    if (!node) return '';
    const ramUsedGb  = ((node.mem_used  || 0) / 1073741824).toFixed(1);
    const ramTotalGb = ((node.mem_total || 0) / 1073741824).toFixed(1);
    const ramPct     = node.mem_total ? Math.round(((node.mem_used || 0) / node.mem_total) * 100) : null;
    const sel        = pxmxNodeKey(node.cluster, node.node);
    const nodeVms    = vms.filter(vm => pxmxNodeKey(vm.cluster, vm.node) === sel);
    const running    = nodeVms.filter(v => v.status === 'running').length;
    const statusCls  = node.status === 'online' ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700';

    return `<div class="rounded-lg border border-slate-200 bg-slate-50/50 p-4 mb-4">
            <h3 class="text-base font-semibold text-[#263040]">${node.node}
                <span class="text-xs text-slate-400 font-normal">${node.cluster ? '· cluster ' + node.cluster : ''}</span> ${helpIcon('pxmx', null, 'Hypervisor help')}</h3>
            <p class="text-xs text-slate-500 mt-1">Status
                <span class="px-2 py-0.5 rounded-full text-xs font-medium ${statusCls}">${node.status}</span>
                · CPU ${node.cpu_usage ?? '—'}% (${node.cpu_cores ?? '—'} cores)
                · RAM ${ramUsedGb} / ${ramTotalGb} GB${ramPct !== null ? ` (${ramPct}%)` : ''}
                · Proxmox ${pxmxShortVer(node.proxmox_version) || '—'}</p>
        </div>` +
        `<h3 class="text-base font-semibold text-[#263040] mb-3 px-1">Virtual Machines &amp; Containers
            <span class="text-xs text-slate-400 font-normal">(${nodeVms.length} on this node, ${running} running)</span> ${helpIcon('pxmx', null, 'Hypervisor help')}</h3>` +
        (nodeVms.length > 0
            ? pxmxVmTableHtml(nodeVms)
            : '<p class="p-4 text-slate-400 italic text-sm">No VMs on this node.</p>');
}

async function loadPxmxData(subMenu) {
    const container = document.getElementById('pxmx-content');
    if (!container) return;
    container.innerHTML = '<p class="text-sm text-slate-400 italic p-4">Loading…</p>';

    const th = cols => `<thead class="bg-slate-50 text-xs text-slate-500 uppercase"><tr>${cols.map(c => `<th class="px-4 py-2 text-left font-medium">${c}</th>`).join('')}</tr></thead>`;
    const tableWrap = html => `<div class="overflow-x-auto"><table class="w-full text-sm">${html}</table></div>`;

    try {
        if (subMenu === 'Settings') {
            await renderPxmxSettings(container);
            return;
        }
        if (subMenu === 'Overview' || subMenu === 'Virtual Machines') {
            const [vmR, nodesR] = await Promise.all([
                fetch(`/api/pxmx/vms?tenant=${encodeURIComponent(currentTenant)}`),
                fetch('/api/pxmx/nodes'),
            ]);
            const vmData    = vmR.ok    ? await vmR.json()    : {};
            const nodesData = nodesR.ok ? await nodesR.json() : {};

            const vms   = vmData.vms   || [];
            const nodes = nodesData.nodes || [];

            // Shared cache for the clickable-node detail view (renderPxmxNodes /
            // openNodeVms / pxmxNodeDetailHtml).
            window._pxmxNodes = nodes;
            window._pxmxVms = vms;
            window._pxmxAgentCount = vmData.agent_count || '?';
            // Template-pool names from the hub: VMs whose pool is in this set are
            // shared templates any tenant may clone (clone-from-template). The
            // hub enforces this server-side too — this is just the UI affordance.
            window._pxmxTemplatePools = (vmData.template_pools || []).map(p => String(p).toLowerCase());

            // --- 'Overview' landing: just the clickable nodes table -----------
            if (subMenu === 'Overview') {
                if (nodes.length === 0 && vms.length === 0) {
                    container.innerHTML = `<div class="py-10 text-center space-y-3">
                        <p class="text-slate-400 italic text-sm">No Proxmox agents connected.</p>
                        <button onclick="showPxmxInstallModal()" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-4 py-2 rounded-md text-sm font-bold transition-all shadow-sm">Show Install Command</button>
                    </div>`;
                    return;
                }
                const isStale = vmData.stale || nodesData.stale;
                const staleBanner = isStale
                    ? `<div class="mb-4 px-3 py-2 bg-amber-50 border border-amber-200 rounded-md text-xs text-amber-700 flex items-center gap-2">
                           <svg class="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.07 16.5c-.77.833.192 2.5 1.732 2.5z"/></svg>
                           <span>Showing cached data — agent offline. Live stats resume automatically when the agent reconnects.</span>
                       </div>`
                    : '';
                container.innerHTML = staleBanner
                    + `<h3 class="text-base font-semibold text-[#263040] mb-3 px-1">Overview
                        <span class="text-xs text-slate-400 font-normal">(${nodes.length}) — click a node to view its VMs</span> ${helpIcon('pxmx', null, 'Hypervisor help')}</h3>`
                    + `<div id="pxmx-nodes-wrap"></div>`;
                renderPxmxNodes();
                return;
            }

            // --- 'Virtual Machines': scoped to a node if arrived via a node click ---
            // A one-shot flag distinguishes "arrived via node click" (scoped) from
            // "clicked the VM tab directly" (all VMs flat, no stale filter).
            const filter = window._pxmxNodeFilterPending ? window._pxmxNodeSel : null;
            window._pxmxNodeFilterPending = false;

            if (vms.length === 0 && nodes.length === 0) {
                container.innerHTML = `<div class="py-10 text-center space-y-3">
                    <p class="text-slate-400 italic text-sm">No Proxmox agents connected.</p>
                    <button onclick="showPxmxInstallModal()" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-4 py-2 rounded-md text-sm font-bold transition-all shadow-sm">Show Install Command</button>
                </div>`;
                return;
            }

            const isStale = vmData.stale || nodesData.stale;
            const staleBanner = isStale
                ? `<div class="mb-4 px-3 py-2 bg-amber-50 border border-amber-200 rounded-md text-xs text-amber-700 flex items-center gap-2">
                       <svg class="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.07 16.5c-.77.833.192 2.5 1.732 2.5z"/></svg>
                       <span>Showing cached data — agent offline. Live stats resume automatically when the agent reconnects.</span>
                   </div>`
                : '';

            const backBtn = `<button onclick="setSubView('Overview'); window._pxmxNodeSel = null;"
                class="mb-3 inline-flex items-center gap-1 text-sm text-slate-500 hover:text-[#01A982] font-medium transition-colors">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7"/></svg>
                Overview
            </button>`;

            if (filter) {
                // Scoped to one node: summary card + that node's VMs.
                // pxmxNodeDetailHtml filters the passed VMs by pxmxNodeKey internally.
                const node = nodes.find(n => pxmxNodeKey(n.cluster, n.node) === filter);
                if (node) {
                    container.innerHTML = staleBanner + backBtn
                        + pxmxNodeDetailHtml(node, vms);
                    return;
                }
                // Node not found (vanished between fetch and click) — fall through to flat.
            }

            // All VMs flat (direct tab click, or no node telemetry yet).
            const buildBtn = (window._pxmxNodes && window._pxmxNodes.length)
                ? `<button onclick="pxmxOpenCreateVm()" class="mb-3 ml-2 px-3 py-1.5 rounded-md text-xs font-bold bg-indigo-600 hover:bg-indigo-700 text-white transition-colors">＋ Build VM from ISO</button>`
                : '';
            container.innerHTML = staleBanner
                + `<div class="flex items-center justify-between mb-1 px-1">
                    <h3 class="text-base font-semibold text-[#263040]">Virtual Machines &amp; Containers
                        <span class="text-xs text-slate-400 font-normal">(${vms.length} total)</span> ${helpIcon('pxmx', null, 'Hypervisor help')}</h3>
                    ${buildBtn}
                </div>`
                + (vms.length > 0 ? pxmxVmTableHtml(vms)
                   : '<p class="p-4 text-slate-400 italic text-sm">No VMs found — waiting for agent telemetry.</p>');

        }
    } catch (err) {
        container.innerHTML = `<p class="p-4 text-red-500 text-sm">Error: ${err.message}</p>`;
    }
}

async function showPxmxInstallModal() {
    let cmd = 'Loading…';
    try {
        const r = await fetch('/api/pxmx/agent-install-cmd');
        const d = r.ok ? await r.json() : {};
        cmd = d.cmd || 'Could not generate command — check LM server logs.';
    } catch (e) {
        cmd = 'Error: ' + e.message;
    }
    const existing = document.getElementById('pxmx-install-modal');
    if (existing) existing.remove();
    const modal = document.createElement('div');
    modal.id = 'pxmx-install-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm';
    modal.innerHTML = `
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-2xl overflow-hidden">
            <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50">
                <h3 class="text-lg font-bold text-[#263040]">Install Proxmox Agent</h3>
                <button onclick="document.getElementById('pxmx-install-modal').remove()" class="text-slate-400 hover:text-slate-600"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg></button>
            </div>
            <div class="p-6 space-y-3">
                <p class="text-sm text-slate-600">Run this on each Proxmox host as <strong>root</strong>:</p>
                <pre id="pxmx-install-cmd" class="bg-slate-900 text-green-300 text-xs rounded-lg p-4 overflow-x-auto whitespace-pre-wrap break-all">${cmd.replace(/</g,'&lt;').replace(/>/g,'&gt;')}</pre>
                <p class="text-xs text-slate-400">The <code>--id</code> flag uses <code>$(hostname)</code> — replace it with a unique name if running on multiple nodes.</p>
            </div>
            <div class="px-6 py-4 bg-slate-50 border-t border-slate-200 flex justify-end gap-3">
                <button onclick="navigator.clipboard.writeText(document.getElementById('pxmx-install-cmd').innerText)" class="px-4 py-2 text-sm font-medium text-slate-600 hover:text-slate-800 border border-slate-300 rounded-md">Copy</button>
                <button onclick="document.getElementById('pxmx-install-modal').remove()" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm">Done</button>
            </div>
        </div>`;
    document.body.appendChild(modal);
}

// ─── NetBox IPAM / DCIM ──────────────────────────────────────────────────────

async function loadNetboxData(subMenu) {
    const container = document.getElementById('netbox-content');
    if (!container) return;
    container.innerHTML = '<p class="text-sm text-slate-400 italic p-4">Loading…</p>';

    // Show/hide the "+ Add" button based on writable sub-views. It lives in the
    // menu strip (far-right #top-nav-actions) rather than the page body.
    const writable = ['Devices', 'Racks', 'Prefixes', 'IP Addresses'];
    const actions = document.getElementById('top-nav-actions');
    if (actions) {
        if (writable.includes(subMenu)) {
            // The Prefixes sub-view also gets a "New Subnet" finder button:
            // it searches for the closest available subnet to one the tenant
            // already has (RFC1918 free-space scan) and assigns the pick. The
            // manual "+ Add" (carve-from-parent) flow stays alongside it.
            const findBtn = subMenu === 'Prefixes'
                ? `<button onclick="showFindSubnetModal()" class="bg-white border border-[#01A982] text-[#01A982] hover:bg-[#01A982] hover:text-white px-3 py-1 rounded-md text-xs font-bold transition-all shadow-sm mr-2">New Subnet</button>`
                : '';
            actions.innerHTML = canEdit()
                ? `${findBtn}<button onclick="showNetboxAddModal()" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-3 py-1 rounded-md text-xs font-bold transition-all shadow-sm">+ Add</button>`
                : '';
        } else {
            actions.innerHTML = '';
        }
    }

    const th = cols => `<thead class="bg-slate-50 text-xs text-slate-500 uppercase"><tr>${cols.map(c => `<th class="px-4 py-2 text-left font-medium">${c}</th>`).join('')}</tr></thead>`;
    const tw = html => `<div class="overflow-x-auto"><table class="w-full text-sm">${html}</table></div>`;
    const escAttr = s => String(s == null ? '' : s).replace(/"/g, '&quot;');
    const editIcon = `<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"></path></svg>`;
    const delIcon  = `<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>`;

    try {
        if (subMenu === 'Overview') {
            // Tenant-scoped summary: fan out to the four IPAM endpoints in
            // parallel and render a card grid (Hosts, Racks, Subnets, IPs).
            // allSettled so one spoke-down response degrades just that card to
            // "Unavailable" instead of blanking the whole overview. Each card
            // navigates to its management sub-view on click. Counts mirror the
            // tenant-filtered fetches each sub-view already makes.
            const t = encodeURIComponent(currentTenant);
            const get = (url, key) => fetch(url)
                .then(r => r.json().then(d => ({ ok: r.ok, d, key })));
            const results = await Promise.allSettled([
                get(`/api/netbox/devices?tenant=${t}`, 'devices'),
                get(`/api/netbox/racks?tenant=${t}`, 'racks'),
                get(`/api/netbox/prefixes?tenant=${t}`, 'prefixes'),
                get(`/api/netbox/ips?tenant=${t}`, 'ip_addresses'),
            ]);
            const count = i => {
                const res = results[i];
                if (res.status !== 'fulfilled' || !res.value.ok || res.value.d.status === 'ERROR') return null;
                return (res.value.d[res.value.key] || []).length;
            };
            const card = (label, n, target) => `
                <div onclick="setSubView('${target}')" class="cursor-pointer bg-white rounded-xl border border-slate-200 p-5 hover:border-[#01A982] hover:shadow-md transition-all">
                    <p class="text-xs font-bold text-slate-500 uppercase tracking-wider mb-2">${label}</p>
                    <p class="text-3xl font-bold text-[#263040]">${n === null ? '<span class="text-base font-medium text-amber-600">Unavailable</span>' : n}</p>
                </div>`;
            container.innerHTML = `
                <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 p-4">
                    ${card('Hosts', count(0), 'Devices')}
                    ${card('Racks', count(1), 'Racks')}
                    ${card('Subnets', count(2), 'Prefixes')}
                    ${card('IPs', count(3), 'IP Addresses')}
                </div>`;

        } else if (subMenu === 'Devices') {
            const r = await fetch(`/api/netbox/devices?tenant=${encodeURIComponent(currentTenant)}`);
            // Spoke-down is now a 503 with {detail} (see api.py error contract); older
            // builds returned 200+{status:'ERROR',message}. Handle both so the operator
            // sees the "spoke not connected" notice either way instead of "No devices".
            const d = await r.json().catch(() => ({}));
            if (!r.ok || d.status === 'ERROR') { container.innerHTML = `<p class="p-4 text-amber-600 text-sm font-medium">Error: ${d.message || d.detail || 'NetBox spoke not connected'}</p><p class="px-4 pb-4 text-xs text-slate-400">Verify the NetBox URL and API Token in Setup → IPAM.</p>`; return; }
            const devices = d.devices || [];
            window._nbDevices = devices;
            const cols = ['Name', 'Status', 'Site', 'Rack', 'Unit', 'Role', 'Type', 'Primary IP', ''];
            const rows = devices.map(dv => {
                const statusCls = dv.status === 'active' ? 'bg-green-100 text-green-700' : 'bg-slate-100 text-slate-500';
                return `<tr class="border-b border-slate-100 hover:bg-slate-50">
                    <td class="px-4 py-2 font-medium">${dv.name}</td>
                    <td class="px-4 py-2"><span class="px-2 py-0.5 rounded-full text-xs font-medium ${statusCls}">${dv.status}</span></td>
                    <td class="px-4 py-2 text-xs">${dv.site || '—'}</td>
                    <td class="px-4 py-2 text-xs">${dv.rack || '—'}</td>
                    <td class="px-4 py-2 text-center text-xs">${dv.position ?? '—'}</td>
                    <td class="px-4 py-2 text-xs">${dv.role || '—'}</td>
                    <td class="px-4 py-2 text-xs">${dv.device_type || '—'}</td>
                    <td class="px-4 py-2 text-xs font-mono">${dv.primary_ip || '—'}</td>
                    <td class="px-4 py-2 whitespace-nowrap">
                        <button onclick="editNetboxDevice(${dv.id})" title="Edit" class="p-1 text-slate-400 hover:text-blue-600 transition-colors">${editIcon}</button>
                        <button onclick="deleteNetboxDevice(${dv.id})" title="Delete" class="p-1 text-slate-300 hover:text-red-500 transition-colors">${delIcon}</button>
                    </td>
                </tr>`;
            }).join('');
            container.innerHTML = devices.length === 0
                ? '<p class="p-4 text-slate-400 italic text-sm">No devices found in NetBox.</p>'
                : tw(th(cols) + `<tbody>${rows}</tbody>`);

        } else if (subMenu === 'Racks') {
            // Tenant-scoped like Devices/Prefixes/IPs: the spoke's get_racks
            // filters by tenant slug when one is passed, so send currentTenant
            // to keep racks inside the tenant boundary instead of listing all.
            const r = await fetch(`/api/netbox/racks?tenant=${encodeURIComponent(currentTenant)}`);
            // 503 {detail} (new) or 200+{status:'ERROR'} (old) — both mean spoke-down.
            const d = await r.json().catch(() => ({}));
            if (!r.ok || d.status === 'ERROR') { container.innerHTML = `<p class="p-4 text-amber-600 text-sm font-medium">Error: ${d.message || d.detail || 'NetBox spoke not connected'}</p>`; return; }
            const racks = d.racks || [];
            window._nbRacks = racks;
            const cols = ['Name', 'Site', 'Facility ID', 'Height (U)', ''];
            const rows = racks.map(rk => `<tr class="border-b border-slate-100 hover:bg-slate-50">
                <td class="px-4 py-2 font-medium">${rk.name}</td>
                <td class="px-4 py-2 text-xs">${rk.site || '—'}</td>
                <td class="px-4 py-2 text-xs font-mono">${rk.facility_id || '—'}</td>
                <td class="px-4 py-2 text-center">${rk.u_height}</td>
                <td class="px-4 py-2 whitespace-nowrap">
                    <button onclick="editNetboxRack(${rk.id})" title="Edit" class="p-1 text-slate-400 hover:text-blue-600 transition-colors">${editIcon}</button>
                    <button onclick="deleteNetboxRack(${rk.id})" title="Delete" class="p-1 text-slate-300 hover:text-red-500 transition-colors">${delIcon}</button>
                </td>
            </tr>`).join('');
            container.innerHTML = racks.length === 0
                ? '<p class="p-4 text-slate-400 italic text-sm">No racks found in NetBox.</p>'
                : tw(th(cols) + `<tbody>${rows}</tbody>`);

        } else if (subMenu === 'Prefixes') {
            const r = await fetch(`/api/netbox/prefixes?tenant=${encodeURIComponent(currentTenant)}`);
            // 503 {detail} (new) or 200+{status:'ERROR'} (old) — both mean spoke-down.
            const d = await r.json().catch(() => ({}));
            if (!r.ok || d.status === 'ERROR') { container.innerHTML = `<p class="p-4 text-amber-600 text-sm font-medium">Error: ${d.message || d.detail || 'NetBox spoke not connected'}</p>`; return; }
            const prefixes = d.prefixes || [];
            window._nbPrefixes = prefixes;
            const cols = ['Prefix', 'Status', 'Site', 'VRF', 'Is Pool', 'Description', ''];
            const rows = prefixes.map(p => {
                const statusCls = p.status === 'active' ? 'bg-green-100 text-green-700' : 'bg-slate-100 text-slate-500';
                return `<tr class="border-b border-slate-100 hover:bg-slate-50">
                    <td class="px-4 py-2 font-mono font-medium">${escapeHtml(p.prefix)}</td>
                    <td class="px-4 py-2"><span class="px-2 py-0.5 rounded-full text-xs font-medium ${statusCls}">${escapeHtml(p.status)}</span></td>
                    <td class="px-4 py-2 text-xs">${p.site || '—'}</td>
                    <td class="px-4 py-2 text-xs">${p.vrf || 'Global'}</td>
                    <td class="px-4 py-2 text-center text-xs">${p.is_pool ? '✓' : ''}</td>
                    <td class="px-4 py-2 text-xs">${p.description || '—'}</td>
                    <td class="px-4 py-2 whitespace-nowrap">
                        <button onclick="showNetboxAllocateIPModal('${p.prefix}')" title="Allocate IP" class="p-1 text-slate-400 hover:text-[#01A982] transition-colors text-xs font-medium">+IP</button>
                        <button onclick="releaseSubnetToPool(${p.id}, '${p.prefix}')" title="Return to pool" class="p-1 text-slate-400 hover:text-amber-600 transition-colors text-xs font-medium">Pool</button>
                        <button onclick="editNetboxPrefix(${p.id})" title="Edit" class="p-1 text-slate-400 hover:text-blue-600 transition-colors">${editIcon}</button>
                        <button onclick="deleteNetboxPrefix(${p.id})" title="Delete" class="p-1 text-slate-300 hover:text-red-500 transition-colors">${delIcon}</button>
                    </td>
                </tr>`;
            }).join('');
            container.innerHTML = prefixes.length === 0
                ? '<p class="p-4 text-slate-400 italic text-sm">No prefixes found in NetBox.</p>'
                : tw(th(cols) + `<tbody>${rows}</tbody>`);

        } else if (subMenu === 'IP Addresses') {
            const r = await fetch(`/api/netbox/ips?tenant=${encodeURIComponent(currentTenant)}`);
            // 503 {detail} (new) or 200+{status:'ERROR'} (old) — both mean spoke-down.
            const d = await r.json().catch(() => ({}));
            if (!r.ok || d.status === 'ERROR') { container.innerHTML = `<p class="p-4 text-amber-600 text-sm font-medium">Error: ${d.message || d.detail || 'NetBox spoke not connected'}</p>`; return; }
            const ips = d.ip_addresses || [];
            window._nbIPs = ips;
            const cols = ['Address', 'Status', 'DNS Name', 'Description', 'Assigned To', 'Device', ''];
            const rows = ips.map(ip => {
                const statusCls = ip.status === 'active' ? 'bg-green-100 text-green-700' : 'bg-slate-100 text-slate-500';
                return `<tr class="border-b border-slate-100 hover:bg-slate-50">
                    <td class="px-4 py-2 font-mono font-medium">${escapeHtml(ip.address)}</td>
                    <td class="px-4 py-2"><span class="px-2 py-0.5 rounded-full text-xs font-medium ${statusCls}">${escapeHtml(ip.status)}</span></td>
                    <td class="px-4 py-2 text-xs">${ip.dns_name || '—'}</td>
                    <td class="px-4 py-2 text-xs">${ip.description || '—'}</td>
                    <td class="px-4 py-2 text-xs">${ip.assigned_to || '—'}</td>
                    <td class="px-4 py-2 text-xs">${ip.device || '—'}</td>
                    <td class="px-4 py-2 whitespace-nowrap">
                        <button onclick="editNetboxIP(${ip.id})" title="Edit" class="p-1 text-slate-400 hover:text-blue-600 transition-colors">${editIcon}</button>
                        <button onclick="releaseNetboxIP(${ip.id})" title="Release" class="p-1 text-slate-300 hover:text-red-500 transition-colors text-xs">Release</button>
                    </td>
                </tr>`;
            }).join('');
            container.innerHTML = ips.length === 0
                ? '<p class="p-4 text-slate-400 italic text-sm">No IP addresses found.</p>'
                : tw(th(cols) + `<tbody>${rows}</tbody>`);
        }
    } catch (err) {
        container.innerHTML = `<p class="p-4 text-red-500 text-sm">Error: ${err.message}</p>`;
    }
}

function showNetboxAddModal() {
    const subMenu = currentSubView;
    if (subMenu === 'Devices') showNetboxAddDeviceModal();
    else if (subMenu === 'Racks') showNetboxRackModal();
    else if (subMenu === 'Prefixes') showNetboxAllocatePrefixModal();
    else if (subMenu === 'IP Addresses') showNetboxAllocateIPModal('');
}

async function showCPPMDeviceDetail(mac) {
    document.getElementById('cppm-device-modal')?.remove();

    const modal = document.createElement('div');
    modal.id = 'cppm-device-modal';
    modal.className = 'fixed inset-0 bg-black/50 flex items-center justify-center z-50';

    const inner = document.createElement('div');
    inner.className = 'bg-white rounded-xl shadow-xl w-full max-w-xl p-6 space-y-4 max-h-[90vh] overflow-y-auto';
    inner.innerHTML = `
        <div class="flex justify-between items-start">
            <p class="font-mono text-base font-bold text-[#263040]">${mac}</p>
            <button class="cppm-modal-close text-slate-400 hover:text-slate-600 text-xl leading-none">&times;</button>
        </div>
        <div class="cppm-modal-body"><p class="text-xs text-slate-400 italic">Loading…</p></div>`;
    modal.appendChild(inner);
    modal.addEventListener('click', e => { if (e.target === modal) modal.remove(); });
    inner.querySelector('.cppm-modal-close').addEventListener('click', () => modal.remove());
    document.body.appendChild(modal);

    const body = inner.querySelector('.cppm-modal-body');
    try {
        const tparam = currentTenant && currentTenant !== 'default' ? `&tenant=${encodeURIComponent(currentTenant)}` : '';
        const [enrichRes, sessRes] = await Promise.all([
            fetch(`/api/cppm/device-enrich?mac=${encodeURIComponent(mac)}${tparam}`),
            fetch(`/api/cppm/device-sessions?mac=${encodeURIComponent(mac)}${tparam}`),
        ]);
        const ep = enrichRes.ok ? await enrichRes.json() : {};
        const sd = sessRes.ok ? await sessRes.json() : {};
        const sources = ep.sources || {};

        const srcBadge = key => sources[key] && sources[key] !== 'ClearPass'
            ? `<span class="ml-1 text-[9px] font-bold uppercase px-1 py-0.5 rounded bg-blue-50 text-blue-500">${sources[key]}</span>` : '';
        const field = (label, val, srcKey) => val
            ? `<div><p class="text-[10px] text-slate-400 uppercase font-bold tracking-wide mb-0.5">${label}${srcKey ? srcBadge(srcKey) : ''}</p><p class="text-sm text-slate-700">${val}</p></div>`
            : '';

        const statusVal = ep.status_val || '';
        const statusCls = statusVal === 'Known' ? 'bg-green-100 text-green-700' : statusVal === 'Unknown' ? 'bg-amber-100 text-amber-700' : 'bg-slate-100 text-slate-500';
        // Full endpoint attribute dump (the summary grid above shows the common
        // fields; this section lists EVERY attribute on the endpoint record so a
        // click on a My Devices / Unknown Devices row surfaces the whole set,
        // including Tenant / Tenant_Slug / NetBox_Tenant_* and profiler attrs).
        const allAttrs = ep.attributes || {};
        // Untagged = assigned to no tenant → eligible to Claim into NetBox.
        const isUntagged = !(allAttrs["NetBox_Tenant_Slug"] || allAttrs["Tenant_Slug"]);
        const attrEntries = Object.entries(allAttrs).filter(([, v]) => v != null && v !== '');
        const attrSection = attrEntries.length
            ? `<div class="mt-3">
                <p class="text-xs text-slate-500 font-bold uppercase tracking-wide mb-2">Endpoint Attributes</p>
                <div class="border border-slate-100 rounded-md p-3 bg-slate-50/50 space-y-1 max-h-56 overflow-y-auto">${attrEntries.map(([k, v]) =>
                    `<div class="flex gap-2 text-xs"><span class="text-slate-400 font-mono min-w-[140px] shrink-0">${k}</span><span class="text-slate-700 break-all">${v}</span></div>`
                ).join('')}</div>
            </div>`
            : '<p class="text-xs text-slate-400 italic mt-3">No endpoint attributes.</p>';

        const sessions = sd.sessions || [];
        const sessionHtml = sessions.length === 0
            ? '<p class="text-xs text-slate-400 italic">No RADIUS accounting sessions found for this device.</p>'
            : `<table class="w-full text-left text-xs border-collapse">
                <thead><tr class="border-b border-slate-200 text-slate-400 uppercase text-[10px]">
                    <th class="px-3 py-1.5">Username</th><th class="px-3 py-1.5">IP</th>
                    <th class="px-3 py-1.5">NAS</th><th class="px-3 py-1.5">Port</th><th class="px-3 py-1.5">Role</th>
                    <th class="px-3 py-1.5">Start</th><th class="px-3 py-1.5">State</th>
                </tr></thead><tbody>${sessions.map(s => `<tr class="border-b border-slate-100">
                    <td class="px-3 py-1.5">${s.username || '—'}</td>
                    <td class="px-3 py-1.5 font-mono">${s.ip || '—'}</td>
                    <td class="px-3 py-1.5">${s.nas_name || '—'}</td>
                    <td class="px-3 py-1.5 font-mono" title="${s.nas_port_type || ''}">${s.nas_port || '—'}</td>
                    <td class="px-3 py-1.5">${s.role || '—'}</td>
                    <td class="px-3 py-1.5">${fmtSessionStart(s.start_time)}</td>
                    <td class="px-3 py-1.5">${s.state || '—'}</td>
                </tr>`).join('')}</tbody></table>`;

        body.innerHTML = `
            <div class="flex items-center gap-2 mb-1">
                <span class="px-2 py-0.5 rounded-full text-xs font-medium ${statusCls}">${statusVal || '—'}</span>
                ${ep.description ? `<span class="text-xs text-slate-500">${ep.description}</span>` : ''}
            </div>
            <div class="grid grid-cols-2 gap-3">
                ${field('Hostname', ep.hostname, 'hostname')}
                ${field('IP Address', ep.ip, 'ip')}
                ${field('Vendor', ep.device_vendor)}
                ${field('OS', ep.device_os)}
                ${field('Type', ep.device_type)}
            </div>
            ${attrSection}
            <div class="mt-3">
                <p class="text-xs text-slate-500 font-bold uppercase tracking-wide mb-2">Session History</p>
                ${sessionHtml}
            </div>
            ${isUntagged ? `<div class="mt-4 pt-3 border-t border-slate-100 flex items-center justify-between">
                <p class="text-xs text-slate-400">Not assigned to any tenant - claim this device to your tenant.</p>
                <button onclick="showClaimDeviceModal('${encodeURIComponent(mac)}')" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-5 py-2 rounded-md text-sm font-bold shrink-0">Claim Device</button>
            </div>` : ''}`;
    } catch (e) {
        body.innerHTML = `<p class="text-xs text-red-400 italic">Error: ${e.message}</p>`;
    }
}

async function showClaimDeviceModal(mac) {
    const dev = (window._cppmDeviceMap || {})[mac] || {};
    const esc = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
    const inputCls = 'w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500';
    const selCls = inputCls;

    // Fetch the NetBox picklists (sites, device types, roles, tenants) so the
    // user chooses from real NetBox values. Server already filters tenants to
    // the non-admin's own; admins see all.
    let opts = { sites: [], device_types: [], device_roles: [], tenants: [] };
    try {
        const r = await fetch('/api/netbox/claim-device/options');
        if (r.ok) opts = await r.json();
    } catch (e) { console.error('showClaimDeviceModal: netbox claim-device options fetch failed — falling back to empty lists', e); }

    const preTenant = currentTenant && currentTenant !== 'default' ? currentTenant : '';
    const tenantLocked = !isAdmin();
    const opt = (arr, slug, label) => (arr || []).map(o =>
        `<option value="${esc(o.slug)}" ${o.slug === slug ? 'selected' : ''}>${esc(label(o))}</option>`).join('');
    const nameDefault = dev.hostname || `endpoint-${(mac || '').replace(/[^a-fA-F0-9]/g, '').toLowerCase()}`;

    const modal = document.createElement('div');
    modal.id = 'nb-claim-modal';
    modal.className = 'fixed inset-0 bg-black/50 flex items-center justify-center z-50';
    modal.innerHTML = `<div class="bg-white rounded-xl shadow-xl w-full max-w-lg p-6 space-y-4 max-h-[90vh] overflow-y-auto">
        <h3 class="text-lg font-bold text-[#263040]">Claim in NetBox</h3>
        <p class="text-xs text-slate-500">Creates a NetBox device owned by a tenant and attaches this endpoint's IP. After a sync, the device leaves Unknown Devices and appears under My Devices.</p>
        <div class="rounded-md bg-slate-50 border border-slate-100 p-3 grid grid-cols-2 gap-x-3 gap-y-1 text-xs">
            <div><span class="text-slate-400">MAC:</span> <span class="font-mono text-slate-700">${esc(dev.mac || mac || '—')}</span></div>
            <div><span class="text-slate-400">IP:</span> <span class="font-mono text-slate-700">${esc(dev.ip || '—')}</span></div>
            <div><span class="text-slate-400">Hostname:</span> <span class="text-slate-700">${esc(dev.hostname || '—')}</span></div>
            <div><span class="text-slate-400">Vendor/OS:</span> <span class="text-slate-700">${esc([dev.device_vendor, dev.device_os].filter(Boolean).join(' / ') || '—')}</span></div>
        </div>
        <div class="grid grid-cols-2 gap-3">
            <div class="col-span-2 space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Device Name</label><input id="cl-name" value="${esc(nameDefault)}" class="${inputCls}" placeholder="router-01"></div>
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Site <span class="text-red-400">*</span></label><select id="cl-site" class="${selCls}"><option value="">Select site…</option>${opt(opts.sites, '', o => o.name)}</select></div>
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Tenant <span class="text-red-400">*</span></label><select id="cl-tenant" class="${selCls}" ${tenantLocked ? 'disabled' : ''}><option value="">Select tenant…</option>${opt(opts.tenants, preTenant, o => o.name)}</select></div>
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Device Type <span class="text-red-400">*</span></label><select id="cl-type" class="${selCls}"><option value="">Select type…</option>${opt(opts.device_types, '', o => `${o.model}${o.manufacturer ? ' (' + o.manufacturer + ')' : ''}`)}</select></div>
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Role</label><select id="cl-role" class="${selCls}"><option value="">Select role…</option>${opt(opts.device_roles, '', o => o.name)}</select></div>
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Status</label><select id="cl-status" class="${selCls}"><option value="active">active</option><option value="planned">planned</option><option value="offline">offline</option><option value="failed">failed</option><option value="inventory">inventory</option></select></div>
            <div class="col-span-2 space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Description</label><input id="cl-desc" class="${inputCls}" placeholder="optional"></div>
        </div>
        <div class="flex gap-2 pt-2">
            <button id="cl-submit" onclick="submitClaimDevice('${encodeURIComponent(mac)}')" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-6 py-2 rounded-md text-sm font-bold">Claim Device</button>
            <button onclick="document.getElementById('nb-claim-modal').remove()" class="bg-slate-100 hover:bg-slate-200 text-slate-700 px-4 py-2 rounded-md text-sm">Cancel</button>
        </div>
    </div>`;
    modal.addEventListener('click', e => { if (e.target === modal) modal.remove(); });
    document.body.appendChild(modal);
}

async function submitClaimDevice(mac) {
    const modal = document.getElementById('nb-claim-modal');
    const get = id => document.getElementById(id)?.value?.trim() || '';
    const name = get('cl-name');
    const site = get('cl-site');
    const device_type = get('cl-type');
    const tenant = get('cl-tenant');
    if (!name) { alert('Device name is required'); return; }
    if (!site) { alert('Site is required'); return; }
    if (!device_type) { alert('Device type is required'); return; }
    if (!tenant) { alert('Tenant is required'); return; }
    const dev = (window._cppmDeviceMap || {})[mac] || {};
    const payload = {
        name, site, device_type, tenant,
        role: get('cl-role'),
        status: get('cl-status') || 'active',
        description: get('cl-desc'),
        mac: dev.mac || mac || '',
        ip: dev.ip || '',
    };
    const btn = document.getElementById('cl-submit');
    if (btn) { btn.disabled = true; btn.textContent = 'Claiming…'; }
    try {
        const r = await fetch('/api/netbox/claim-device', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        const d = await r.json().catch(() => ({}));
        if (r.ok && d.status === 'SUCCESS') {
            document.getElementById('nb-claim-modal')?.remove();
            document.getElementById('cppm-device-modal')?.remove();
            showToast('Claimed — syncing to ClearPass');
            loadCPPMData('Unknown Devices');
        } else {
            if (btn) { btn.disabled = false; btn.textContent = 'Claim Device'; }
            alert('Claim failed: ' + (d.detail || d.message || `HTTP ${r.status}`));
        }
    } catch (e) {
        if (btn) { btn.disabled = false; btn.textContent = 'Claim Device'; }
        alert('Claim failed: ' + e.message);
    }
}

function editNetboxDevice(id) {
    const item = (window._nbDevices || []).find(d => d.id === id);
    if (!item) { showToast('Row data not found — refresh and try again', 'error'); return; }
    showNetboxAddDeviceModal(item);
}

function showNetboxAddDeviceModal(editItem) {
    const editing = !!editItem;
    const val = v => (v == null ? '' : String(v).replace(/"/g, '&quot;'));
    const inputCls = 'w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500';
    const modal = document.createElement('div');
    modal.id = 'nb-device-modal';
    modal.className = 'fixed inset-0 bg-black/50 flex items-center justify-center z-50';
    if (editing) modal.dataset.deviceId = editItem.id;
    modal.innerHTML = `<div class="bg-white rounded-xl shadow-xl w-full max-w-lg p-6 space-y-4">
        <h3 class="text-lg font-bold text-[#263040]">${editing ? 'Edit' : 'Add'} Device</h3>
        <div class="grid grid-cols-2 gap-3">
            <div class="col-span-2 space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Device Name</label><input id="nb-d-name" value="${val(editItem?.name)}" class="${inputCls}" placeholder="router-01"></div>
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Site Slug</label><input id="nb-d-site" value="${val(editItem?.site)}" class="${inputCls}" placeholder="lab-a" ${editing ? 'readonly' : ''}></div>
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Rack Name</label><input id="nb-d-rack" value="${val(editItem?.rack)}" class="${inputCls}" placeholder="Rack-01"></div>
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Rack Unit</label><input id="nb-d-unit" type="number" min="1" value="${val(editItem?.position)}" class="${inputCls}" placeholder="1"></div>
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Face</label><select id="nb-d-face" class="${inputCls}"><option value="front">Front</option><option value="rear">Rear</option></select></div>
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Device Type Slug</label><input id="nb-d-type" class="${inputCls}" placeholder="cisco-catalyst-9200" ${editing ? 'readonly' : ''}></div>
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Role Slug</label><input id="nb-d-role" class="${inputCls}" placeholder="access-switch" ${editing ? 'readonly' : ''}></div>
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Status</label><select id="nb-d-status" class="${inputCls}"><option value="active">active</option><option value="planned">planned</option><option value="offline">offline</option><option value="failed">failed</option><option value="inventory">inventory</option></select></div>
        </div>
        <div class="flex gap-2 pt-2">
            <button onclick="submitNetboxAddDevice()" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-6 py-2 rounded-md text-sm font-bold">${editing ? 'Save Changes' : 'Add Device'}</button>
            <button onclick="document.getElementById('nb-device-modal').remove()" class="bg-slate-100 hover:bg-slate-200 text-slate-700 px-4 py-2 rounded-md text-sm">Cancel</button>
        </div>
    </div>`;
    document.body.appendChild(modal);
    if (editing && editItem.status) {
        const st = document.getElementById('nb-d-status');
        if (st) st.value = editItem.status;
    }
}

async function submitNetboxAddDevice() {
    const modal = document.getElementById('nb-device-modal');
    const editing = modal && modal.dataset.deviceId;
    const get = id => document.getElementById(id)?.value?.trim() || '';
    const deviceId = editing ? parseInt(modal.dataset.deviceId) : null;
    if (editing) {
        const payload = {
            name: get('nb-d-name'),
            status: get('nb-d-status') || 'active',
            rack: get('nb-d-rack'),
            rack_unit: get('nb-d-unit') ? parseInt(get('nb-d-unit')) : '',
        };
        try {
            const r = await fetch(`/api/netbox/devices/${deviceId}`, { method: 'PUT', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload) });
            const d = await r.json();
            if (d.status === 'SUCCESS') { modal.remove(); loadNetboxData('Devices'); }
            else alert('Error: ' + (d.message || 'Update failed'));
        } catch (e) { alert('Error: ' + e.message); }
        return;
    }
    const payload = {
        name: get('nb-d-name'), site: get('nb-d-site'), rack: get('nb-d-rack'),
        rack_unit: parseInt(get('nb-d-unit')) || 1, face: get('nb-d-face'),
        device_type: get('nb-d-type'), role: get('nb-d-role'), status: get('nb-d-status') || 'active',
    };
    try {
        const r = await fetch('/api/netbox/devices', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload) });
        const d = await r.json();
        if (d.status === 'SUCCESS') {
            document.getElementById('nb-device-modal')?.remove();
            loadNetboxData('Devices');
        } else {
            alert('Error: ' + (d.message || 'Unknown error'));
        }
    } catch (e) { alert('Error: ' + e.message); }
}

async function deleteNetboxDevice(deviceId) {
    if (!await showConfirmToast('Delete this device from NetBox?')) return;
    try {
        const r = await fetch(`/api/netbox/devices/${deviceId}`, { method: 'DELETE' });
        const d = await r.json();
        if (d.status === 'SUCCESS') loadNetboxData('Devices');
        else alert('Error: ' + (d.message || 'Delete failed'));
    } catch (e) { alert('Error: ' + e.message); }
}

function editNetboxRack(id) {
    const item = (window._nbRacks || []).find(r => r.id === id);
    if (!item) { showToast('Row data not found — refresh and try again', 'error'); return; }
    showNetboxRackModal(item);
}

function showNetboxRackModal(editItem) {
    const editing = !!editItem;
    const val = v => (v == null ? '' : String(v).replace(/"/g, '&quot;'));
    const inputCls = 'w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500';
    const modal = document.createElement('div');
    modal.id = 'nb-rack-modal';
    modal.className = 'fixed inset-0 bg-black/50 flex items-center justify-center z-50';
    if (editing) modal.dataset.rackId = editItem.id;
    modal.innerHTML = `<div class="bg-white rounded-xl shadow-xl w-full max-w-md p-6 space-y-4">
        <h3 class="text-lg font-bold text-[#263040]">${editing ? 'Edit' : 'Add'} Rack</h3>
        <div class="space-y-3">
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Rack Name</label><input id="nb-r-name" value="${val(editItem?.name)}" class="${inputCls}" placeholder="Rack-01"></div>
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Site Slug</label><input id="nb-r-site" value="${val(editItem?.site)}" class="${inputCls}" placeholder="lab-a" ${editing ? 'readonly' : ''}></div>
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Height (U)</label><input id="nb-r-uheight" type="number" min="1" value="${val(editItem?.u_height) || 42}" class="${inputCls}" placeholder="42"></div>
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Facility ID (optional)</label><input id="nb-r-facility" value="${val(editItem?.facility_id)}" class="${inputCls}" placeholder="A1"></div>
        </div>
        <div class="flex gap-2 pt-2">
            <button onclick="submitNetboxRack()" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-6 py-2 rounded-md text-sm font-bold">${editing ? 'Save Changes' : 'Add Rack'}</button>
            <button onclick="document.getElementById('nb-rack-modal').remove()" class="bg-slate-100 hover:bg-slate-200 text-slate-700 px-4 py-2 rounded-md text-sm">Cancel</button>
        </div>
    </div>`;
    document.body.appendChild(modal);
}

async function submitNetboxRack() {
    const modal = document.getElementById('nb-rack-modal');
    const editing = modal && modal.dataset.rackId;
    const get = id => document.getElementById(id)?.value?.trim() || '';
    const payload = {
        name: get('nb-r-name'),
        site: get('nb-r-site'),
        u_height: parseInt(get('nb-r-uheight')) || 42,
        facility_id: get('nb-r-facility') || undefined,
    };
    if (!payload.name || (!editing && !payload.site)) {
        alert('Name and Site are required');
        return;
    }
    try {
        const url = editing ? `/api/netbox/racks/${modal.dataset.rackId}` : '/api/netbox/racks';
        const r = await fetch(url, { method: editing ? 'PUT' : 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload) });
        const d = await r.json();
        if (d.status === 'SUCCESS') { modal.remove(); loadNetboxData('Racks'); }
        else alert('Error: ' + (d.message || 'Operation failed'));
    } catch (e) { alert('Error: ' + e.message); }
}

async function deleteNetboxRack(rackId) {
    if (!await showConfirmToast('Delete this rack from NetBox?')) return;
    try {
        const r = await fetch(`/api/netbox/racks/${rackId}`, { method: 'DELETE' });
        const d = await r.json();
        if (d.status === 'SUCCESS') loadNetboxData('Racks');
        else alert('Error: ' + (d.message || 'Delete failed'));
    } catch (e) { alert('Error: ' + e.message); }
}

function editNetboxPrefix(id) {
    const item = (window._nbPrefixes || []).find(p => p.id === id);
    if (!item) { showToast('Row data not found — refresh and try again', 'error'); return; }
    showNetboxAllocatePrefixModal(item);
}

async function showNetboxAllocatePrefixModal(editItem) {
    const editing = !!editItem;
    const val = v => (v == null ? '' : String(v).replace(/"/g, '&quot;'));
    const inputCls = 'w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500';
    const selectCls = inputCls;
    const modal = document.createElement('div');
    modal.id = 'nb-prefix-modal';
    modal.className = 'fixed inset-0 bg-black/50 flex items-center justify-center z-50';
    if (editing) modal.dataset.prefixId = editItem.id;
    const allocFields = editing ? '' : `
        <div class="space-y-1">
            <label class="text-xs text-slate-500 font-bold uppercase">Parent Prefix</label>
            <select id="nb-p-parent" class="${selectCls}"><option value="">Loading…</option></select>
        </div>
        <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Prefix Length</label><input id="nb-p-len" type="number" min="1" max="32" value="24" class="${inputCls}"></div>
        <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Subnet (optional)</label><input id="nb-p-prefix" class="${inputCls}" placeholder="10.0.0.16/28 — exact subnet to create; blank = auto"></div>`;
    const statusOpts = ['active', 'container', 'reserved', 'deprecated'].map(s =>
        `<option value="${s}"${editing && editItem.status === s ? ' selected' : ''}>${s}</option>`).join('');
    modal.innerHTML = `<div class="bg-white rounded-xl shadow-xl w-full max-w-md p-6 space-y-4">
        <h3 class="text-lg font-bold text-[#263040]">${editing ? 'Edit' : 'Allocate'} Subnet${editing ? ` — <span class="font-mono text-sm">${val(editItem.prefix)}</span>` : ''}</h3>
        <div class="space-y-3">
            ${allocFields}
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Description</label><input id="nb-p-desc" value="${val(editItem?.description)}" class="${inputCls}" placeholder="e.g. Lab Tenant A VLAN10"></div>
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Site Slug (optional)</label><input id="nb-p-site" value="${val(editItem?.site)}" class="${inputCls}" placeholder="lab-a"></div>
            ${editing ? `<div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Status</label><select id="nb-p-status" class="${selectCls}">${statusOpts}</select></div>` : ''}
        </div>
        <div class="flex gap-2 pt-2">
            <button onclick="submitNetboxAllocatePrefix()" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-6 py-2 rounded-md text-sm font-bold">${editing ? 'Save Changes' : 'Allocate'}</button>
            <button onclick="document.getElementById('nb-prefix-modal').remove()" class="bg-slate-100 hover:bg-slate-200 text-slate-700 px-4 py-2 rounded-md text-sm">Cancel</button>
        </div>
    </div>`;
    document.body.appendChild(modal);

    if (editing) return;

    // Populate parent prefix dropdown from NetBox
    try {
        const url = currentTenant && currentTenant !== 'default'
            ? `/api/netbox/prefixes?tenant=${encodeURIComponent(currentTenant)}`
            : '/api/netbox/prefixes';
        const r = await fetch(url, { credentials: 'same-origin' });
        const d = r.ok ? await r.json() : {};
        const prefixes = (d.prefixes || []).map(p => p.prefix).sort();
        const sel = document.getElementById('nb-p-parent');
        if (sel) {
            sel.innerHTML = prefixes.length
                ? `<option value="">— select parent prefix —</option>` + prefixes.map(p => `<option value="${p}">${p}</option>`).join('')
                : `<option value="">No prefixes found in NetBox</option>`;
        }
    } catch (err) {
        console.error('showNetboxAllocatePrefixModal: could not load parent prefixes', err);
        const sel = document.getElementById('nb-p-parent');
        if (sel) sel.innerHTML = `<option value="">Could not load prefixes</option>`;
    }
}

async function submitNetboxAllocatePrefix() {
    const modal = document.getElementById('nb-prefix-modal');
    const editing = modal && modal.dataset.prefixId;
    const get = id => document.getElementById(id)?.value?.trim() || '';
    if (editing) {
        const payload = {
            description: get('nb-p-desc'),
            status: get('nb-p-status') || 'active',
            site: get('nb-p-site') || undefined,
        };
        try {
            const r = await fetch(`/api/netbox/prefixes/${modal.dataset.prefixId}`, { method: 'PUT', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload) });
            const d = await r.json();
            if (d.status === 'SUCCESS') { modal.remove(); loadNetboxData('Prefixes'); }
            else alert('Error: ' + (d.message || 'Update failed'));
        } catch (e) { alert('Error: ' + e.message); }
        return;
    }
    const payload = {
        parent_prefix: get('nb-p-parent'),
        prefix_length: parseInt(get('nb-p-len')) || 24,
        requested_prefix: get('nb-p-prefix') || undefined,
        description: get('nb-p-desc'),
        site: get('nb-p-site') || undefined,
        status: 'active',
        tenant: (currentTenant && currentTenant !== 'default') ? currentTenant : undefined,
    };
    try {
        const r = await fetch('/api/netbox/prefixes', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload) });
        const d = await r.json();
        if (d.status === 'SUCCESS') {
            document.getElementById('nb-prefix-modal')?.remove();
            alert(`Allocated: ${d.prefix}`);
            loadNetboxData('Prefixes');
        } else {
            alert('Error: ' + (d.message || 'Allocation failed'));
        }
    } catch (e) { alert('Error: ' + e.message); }
}

async function deleteNetboxPrefix(prefixId) {
    if (!await showConfirmToast('Delete this prefix from NetBox? Any IP addresses under it may also be removed.')) return;
    try {
        const r = await fetch(`/api/netbox/prefixes/${prefixId}`, { method: 'DELETE' });
        const d = await r.json();
        if (d.status === 'SUCCESS') loadNetboxData('Prefixes');
        else alert('Error: ' + (d.message || 'Delete failed'));
    } catch (e) { alert('Error: ' + e.message); }
}

// ─── New Subnet finder + release-to-pool ─────────────────────────────────────
//
// "New Subnet": search for the closest available subnet to one the tenant
// already has (free = undefined-in-NetBox or defined-but-unassigned, RFC1918
// only), ranked by numeric distance; the user picks one and Assigns it. Size is
// given as a prefix length or as a host count (smallest mask that fits). If
// nothing is available, the user can type a subnet — the exact typed CIDR is
// tried first, else the nearest free one. "Pool" on a prefix row returns it to
// the pool (deletes it from NetBox).

function _maskForHosts(hosts) {
    hosts = parseInt(hosts) || 1;
    for (let L = 30; L >= 22; L--) {
        if ((1 << (32 - L)) - 2 >= hosts) return L;
    }
    return 22;
}
function _usableForMask(L) { return (1 << (32 - L)) - 2; }

async function showFindSubnetModal() {
    const existing = document.getElementById('nb-find-modal');
    if (existing) { existing.remove(); return; }
    const inputCls = 'w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500';
    const modal = document.createElement('div');
    modal.id = 'nb-find-modal';
    modal.className = 'fixed inset-0 bg-black/50 flex items-center justify-center z-50';
    modal.innerHTML = `<div class="bg-white rounded-xl shadow-xl w-full max-w-lg p-6 space-y-4 max-h-[90vh] overflow-y-auto">
        <h3 class="text-lg font-bold text-[#263040]">New Subnet</h3>
        <p class="text-xs text-slate-500 -mt-2">Finds the closest available subnet to one you already have (RFC1918 only; free = not in NetBox or unassigned).</p>
        <div class="space-y-3">
            <div class="space-y-1">
                <label class="text-xs text-slate-500 font-bold uppercase">Close to (your existing subnet)</label>
                <select id="nb-f-near" class="${inputCls}"><option value="">Loading…</option></select>
            </div>
            <div class="space-y-1">
                <label class="text-xs text-slate-500 font-bold uppercase">Size</label>
                <div class="flex gap-2 items-center">
                    <select id="nb-f-size-mode" class="${inputCls} flex-none w-36" onchange="_onFindSizeModeChange()">
                        <option value="mask">Prefix length</option>
                        <option value="hosts">Hosts needed</option>
                    </select>
                    <select id="nb-f-mask" class="${inputCls} flex-1">
                        ${[22,23,24,25,26,27,28,29,30].map(m => `<option value="${m}">/${m}</option>`).join('')}
                    </select>
                    <input id="nb-f-hosts" type="number" min="1" value="60" class="${inputCls} flex-1 hidden" oninput="_updateFindSizeHint()">
                </div>
                <p id="nb-f-size-hint" class="text-[10px] text-slate-400"></p>
            </div>
            <div class="space-y-1">
                <label class="text-xs text-slate-500 font-bold uppercase">Description (optional)</label>
                <input id="nb-f-desc" class="${inputCls}" placeholder="e.g. Lab Tenant A VLAN11">
            </div>
            <div class="space-y-1 hidden" id="nb-f-typewrap">
                <label class="text-xs text-slate-500 font-bold uppercase">Type a subnet to search near (exact tried first, else nearest)</label>
                <input id="nb-f-typed" class="${inputCls}" placeholder="10.50.0.0/24">
            </div>
            <button onclick="searchAvailableSubnets()" class="bg-slate-700 hover:bg-slate-800 text-white px-4 py-2 rounded-md text-sm font-bold w-full">Search</button>
            <div id="nb-f-results" class="space-y-1"></div>
        </div>
        <div class="flex gap-2 pt-2">
            <button id="nb-f-assign-btn" onclick="submitFindSubnetAssign()" disabled class="bg-[#01A982] hover:bg-[#008c6a] text-white px-6 py-2 rounded-md text-sm font-bold disabled:opacity-40 disabled:cursor-not-allowed">Assign</button>
            <button onclick="document.getElementById('nb-find-modal').remove()" class="bg-slate-100 hover:bg-slate-200 text-slate-700 px-4 py-2 rounded-md text-sm">Cancel</button>
        </div>
    </div>`;
    modal.addEventListener('click', e => { if (e.target === modal) modal.remove(); });
    document.body.appendChild(modal);
    window._nbFindAvail = [];
    window._nbFindSelected = null;

    // Populate "close to" with the tenant's own prefixes; default the mask to
    // the first one's mask.
    try {
        const url = currentTenant && currentTenant !== 'default'
            ? `/api/netbox/prefixes?tenant=${encodeURIComponent(currentTenant)}`
            : '/api/netbox/prefixes';
        const r = await fetch(url, { credentials: 'same-origin' });
        const d = r.ok ? await r.json() : {};
        const prefixes = (d.prefixes || []).map(p => p.prefix).sort();
        const sel = document.getElementById('nb-f-near');
        if (sel) {
            sel.innerHTML = prefixes.length
                ? `<option value="">— select an existing subnet —</option>` + prefixes.map(p => `<option value="${p}">${p}</option>`).join('')
                : `<option value="">No existing subnets — type one below</option>`;
        }
        if (prefixes.length) {
            const m = prefixes[0].split('/')[1];
            const maskSel = document.getElementById('nb-f-mask');
            if (maskSel && m) maskSel.value = m;
        }
    } catch (err) {
        console.error('showFindSubnetModal: could not load prefixes', err);
        const sel = document.getElementById('nb-f-near');
        if (sel) sel.innerHTML = `<option value="">Could not load prefixes</option>`;
    }
    _updateFindSizeHint();
}

function _onFindSizeModeChange() {
    const mode = document.getElementById('nb-f-size-mode').value;
    document.getElementById('nb-f-mask').classList.toggle('hidden', mode === 'hosts');
    document.getElementById('nb-f-hosts').classList.toggle('hidden', mode === 'mask');
    _updateFindSizeHint();
}

function _updateFindSizeHint() {
    const mode = document.getElementById('nb-f-size-mode')?.value;
    const hint = document.getElementById('nb-f-size-hint');
    if (!hint) return;
    if (mode === 'hosts') {
        const L = _maskForHosts(document.getElementById('nb-f-hosts').value);
        hint.textContent = `→ /${L} (${_usableForMask(L)} usable hosts)`;
    } else {
        const L = parseInt(document.getElementById('nb-f-mask').value);
        hint.textContent = `/${L} = ${_usableForMask(L)} usable hosts`;
    }
}

function _findPrefixLength() {
    const mode = document.getElementById('nb-f-size-mode').value;
    if (mode === 'hosts') return _maskForHosts(document.getElementById('nb-f-hosts').value);
    return parseInt(document.getElementById('nb-f-mask').value) || 24;
}

async function searchAvailableSubnets() {
    const near = document.getElementById('nb-f-near')?.value?.trim() || '';
    const typed = document.getElementById('nb-f-typed')?.value?.trim() || '';
    const anchor = near || typed;
    if (!anchor) { alert('Pick an existing subnet or type one to search near.'); return; }
    const prefixLength = _findPrefixLength();
    const resultsEl = document.getElementById('nb-f-results');
    const assignBtn = document.getElementById('nb-f-assign-btn');
    resultsEl.innerHTML = '<p class="text-xs text-slate-400 italic">Searching…</p>';
    assignBtn.disabled = true;
    window._nbFindSelected = null;
    try {
        const params = new URLSearchParams({ near: anchor, prefix_length: String(prefixLength), count: '20' });
        if (typed) params.set('exact', typed);
        const r = await fetch(`/api/netbox/available-subnets?${params}`, { credentials: 'same-origin' });
        const d = r.ok ? await r.json() : {};
        if (d.status === 'ERROR') { resultsEl.innerHTML = `<p class="text-xs text-red-500">${d.message || 'Search failed'}</p>`; return; }
        const avail = d.available || [];
        if (!avail.length) {
            resultsEl.innerHTML = `<p class="text-xs text-amber-600">No subnets available near ${anchor}. Type one below and search again.</p>`;
            document.getElementById('nb-f-typewrap').classList.remove('hidden');
            return;
        }
        document.getElementById('nb-f-typewrap').classList.add('hidden');
        window._nbFindAvail = avail;
        resultsEl.innerHTML = avail.map((a, i) => {
            const distLabel = a.distance === 0 ? 'exact' : `${a.distance} away`;
            return `<label class="flex items-center gap-2 px-2 py-1.5 rounded-md hover:bg-slate-50 cursor-pointer border border-slate-100">
                <input type="radio" name="nb-f-pick" value="${i}" onchange="_pickFindSubnet(${i})">
                <span class="font-mono text-sm">${a.prefix}</span>
                <span class="text-[10px] text-slate-400 ml-auto">${distLabel}</span>
            </label>`;
        }).join('');
        _pickFindSubnet(0);
    } catch (e) {
        resultsEl.innerHTML = `<p class="text-xs text-red-500">Error: ${e.message}</p>`;
    }
}

function _pickFindSubnet(i) {
    const a = (window._nbFindAvail || [])[i];
    if (!a) return;
    window._nbFindSelected = a.prefix;
    document.querySelectorAll('input[name="nb-f-pick"]').forEach(el => { el.checked = parseInt(el.value) === i; });
    document.getElementById('nb-f-assign-btn').disabled = false;
}

async function submitFindSubnetAssign() {
    const prefix = window._nbFindSelected;
    if (!prefix) { alert('Search and pick a subnet first.'); return; }
    const desc = document.getElementById('nb-f-desc')?.value?.trim() || '';
    try {
        const r = await fetch('/api/netbox/subnet-assign', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ prefix, description: desc, status: 'active' }),
            credentials: 'same-origin',
        });
        const d = await r.json();
        if (d.status === 'SUCCESS') {
            document.getElementById('nb-find-modal')?.remove();
            showToast(`Subnet assigned: ${d.prefix}`, 'success');
            loadNetboxData('Prefixes');
        } else {
            alert('Error: ' + (d.message || 'Assign failed'));
        }
    } catch (e) { alert('Error: ' + e.message); }
}

async function releaseSubnetToPool(prefixId, prefixStr) {
    let ipCount = 0;
    try {
        const r = await fetch(`/api/netbox/ips?prefix=${encodeURIComponent(prefixStr)}`, { credentials: 'same-origin' });
        const d = r.ok ? await r.json() : {};
        ipCount = (d.ip_addresses || []).length;
    } catch { /* unknown — proceed without a count */ }
    const msg = ipCount > 0
        ? `Return ${prefixStr} to the pool? This removes the subnet and its ${ipCount} IP address(es) from NetBox.`
        : `Return ${prefixStr} to the pool? This removes the subnet from NetBox.`;
    if (!await showConfirmToast(msg)) return;
    try {
        const r = await fetch(`/api/netbox/prefixes/${prefixId}`, { method: 'DELETE' });
        const d = await r.json();
        if (d.status === 'SUCCESS') { showToast('Returned to pool', 'success'); loadNetboxData('Prefixes'); }
        else alert('Error: ' + (d.message || 'Release failed'));
    } catch (e) { alert('Error: ' + e.message); }
}

function editNetboxIP(id) {
    const item = (window._nbIPs || []).find(ip => ip.id === id);
    if (!item) { showToast('Row data not found — refresh and try again', 'error'); return; }
    showNetboxAllocateIPModal('', item);
}

function showNetboxAllocateIPModal(prefixHint, editItem) {
    const editing = !!editItem;
    const val = v => (v == null ? '' : String(v).replace(/"/g, '&quot;'));
    const inputCls = 'w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500';
    const modal = document.createElement('div');
    modal.id = 'nb-ip-modal';
    modal.className = 'fixed inset-0 bg-black/50 flex items-center justify-center z-50';
    if (editing) modal.dataset.ipId = editItem.id;
    const allocFields = editing ? '' : `
        <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Prefix</label><input id="nb-ip-prefix" value="${prefixHint}" class="${inputCls}" placeholder="10.0.0.0/24"></div>
        <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">IP Address (optional)</label><input id="nb-ip-address" class="${inputCls}" placeholder="10.0.0.5 — exact address; blank = auto"></div>`;
    const statusOpts = ['active', 'reserved', 'deprecated', 'dhcp'].map(s =>
        `<option value="${s}"${editing && editItem.status === s ? ' selected' : ''}>${s}</option>`).join('');
    modal.innerHTML = `<div class="bg-white rounded-xl shadow-xl w-full max-w-md p-6 space-y-4">
        <h3 class="text-lg font-bold text-[#263040]">${editing ? 'Edit' : 'Allocate'} IP Address${editing ? ` — <span class="font-mono text-sm">${val(editItem.address)}</span>` : ''}</h3>
        <div class="space-y-3">
            ${allocFields}
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">DNS Name (optional)</label><input id="nb-ip-dns" value="${val(editItem?.dns_name)}" class="${inputCls}" placeholder="host.example.com"></div>
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Description (optional)</label><input id="nb-ip-desc" value="${val(editItem?.description)}" class="${inputCls}" placeholder="e.g. Gateway VM"></div>
            ${editing ? `<div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Status</label><select id="nb-ip-status" class="${inputCls}">${statusOpts}</select></div>` : ''}
        </div>
        <div class="flex gap-2 pt-2">
            <button onclick="submitNetboxAllocateIP()" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-6 py-2 rounded-md text-sm font-bold">${editing ? 'Save Changes' : 'Allocate'}</button>
            <button onclick="document.getElementById('nb-ip-modal').remove()" class="bg-slate-100 hover:bg-slate-200 text-slate-700 px-4 py-2 rounded-md text-sm">Cancel</button>
        </div>
    </div>`;
    document.body.appendChild(modal);
}

async function submitNetboxAllocateIP() {
    const modal = document.getElementById('nb-ip-modal');
    const editing = modal && modal.dataset.ipId;
    const get = id => document.getElementById(id)?.value?.trim() || '';
    if (editing) {
        const payload = {
            dns_name: get('nb-ip-dns'),
            description: get('nb-ip-desc'),
            status: get('nb-ip-status') || 'active',
        };
        try {
            const r = await fetch(`/api/netbox/ips/${modal.dataset.ipId}`, { method: 'PUT', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload) });
            const d = await r.json();
            if (d.status === 'SUCCESS') { modal.remove(); loadNetboxData('IP Addresses'); }
            else alert('Error: ' + (d.message || 'Update failed'));
        } catch (e) { alert('Error: ' + e.message); }
        return;
    }
    const payload = { prefix: get('nb-ip-prefix'), address: get('nb-ip-address') || undefined, dns_name: get('nb-ip-dns'), description: get('nb-ip-desc'), status: 'active' };
    try {
        const r = await fetch('/api/netbox/ips', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload) });
        const d = await r.json();
        if (d.status === 'SUCCESS') {
            document.getElementById('nb-ip-modal')?.remove();
            alert(`Allocated: ${d.address}`);
            loadNetboxData('IP Addresses');
        } else {
            alert('Error: ' + (d.message || 'Allocation failed'));
        }
    } catch (e) { alert('Error: ' + e.message); }
}

async function releaseNetboxIP(ipId) {
    if (!await showConfirmToast('Release this IP address? This will delete it from NetBox.')) return;
    try {
        const r = await fetch(`/api/netbox/ips/${ipId}`, { method: 'DELETE' });
        const d = await r.json();
        if (d.status === 'SUCCESS') loadNetboxData('IP Addresses');
        else alert('Error: ' + (d.message || 'Release failed'));
    } catch (e) { alert('Error: ' + e.message); }
}

// ─── DNS (Unbound) ───────────────────────────────────────────────────────────

// _spokeFetch — shared fetch helper for the DNS/DHCP spoke-relay endpoints.
// The hub relay (`_relay_spoke` in api.py) now translates a spoke-side ERROR
// into HTTP 502 with {detail} (was: 200 + {status:'ERROR',message}), matching
// the rest of the API error contract. Success bodies are the spoke's
// {status:'SUCCESS', ...} payload, unchanged. Returns {ok, status, data,
// detail}: on success data is the parsed body; on failure data is null and
// detail carries the spoke's message (or the HTTP status text). Consolidates
// the 8 near-identical `r.ok ? r.json() : {}` / `if (d.status === 'ERROR')`
// blocks across the DNS + DHCP consumers — and fixes the prior UX gap where a
// 503 (spoke down) rendered as "No records found" instead of the real message.
async function _spokeFetch(url, opts) {
    const r = await fetch(url, opts);
    if (r.ok) return { ok: true, status: r.status, data: await r.json().catch(() => ({})), detail: null };
    const e = await r.json().catch(() => ({}));
    return { ok: false, status: r.status, data: null, detail: e.detail || e.message || r.statusText };
}

// Amber error banner used by the DNS/DHCP list views on a spoke failure.
function _spokeErrorBanner(detail, fallback) {
    return `<p class="p-4 text-amber-600 text-sm font-medium">Error: ${escapeHtml(detail || fallback)}</p>`;
}

// ── Shared stat-tile + utilization-bar helpers for the DNS/DHCP analytics
// panels (Phase 3). Kept local to the resolver views; mirror the compact
// tile look used elsewhere in the app.
function _ddTile(label, value, sub, valueColor) {
    return `<div class="bg-white border border-slate-200 rounded-lg p-4">
        <div class="text-[11px] uppercase tracking-wide text-slate-400 font-semibold">${escapeHtml(label)}</div>
        <div class="mt-1 text-2xl font-bold ${valueColor || 'text-slate-800'}">${escapeHtml(String(value))}</div>
        ${sub ? `<div class="text-xs text-slate-400 mt-0.5">${escapeHtml(String(sub))}</div>` : ''}
    </div>`;
}

// A horizontal utilization/percentage bar, green→amber→red by threshold.
function _ddBar(pct, label) {
    const p = Math.max(0, Math.min(100, Number(pct) || 0));
    const color = p >= 90 ? 'bg-red-500' : p >= 70 ? 'bg-amber-500' : 'bg-emerald-500';
    return `<div class="flex items-center gap-2">
        <div class="flex-1 bg-slate-100 rounded-full h-2 overflow-hidden"><div class="${color} h-2 rounded-full" style="width:${p}%"></div></div>
        <span class="text-xs font-mono text-slate-500 w-12 text-right">${p}%</span>
        ${label ? `<span class="text-xs text-slate-400">${escapeHtml(label)}</span>` : ''}
    </div>`;
}

// Humanize an uptime in seconds → "3d 4h 12m".
function _ddUptime(sec) {
    sec = Number(sec) || 0;
    const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
    return (d ? `${d}d ` : '') + (h || d ? `${h}h ` : '') + `${m}m`;
}

// Best-effort "last NetBox → Unbound/Kea auto-sync" line for the analytics
// panels; silent when the status endpoint is unreachable.
async function _ddSyncStatusLine(side) {
    try {
        const { ok, data } = await _spokeFetch('/api/dns-dhcp/sync-status');
        if (!ok || !data) return '';
        const s = (data.status || {})[side] || {};
        const cfg = data.config || {};
        if (!s.last_run) {
            return `<div class="text-xs text-slate-400 mt-2">NetBox auto-sync: ${cfg.enabled === false ? 'disabled' : 'enabled'} (every ${cfg.interval || 300}s) — no run yet</div>`;
        }
        const when = new Date(s.last_run * 1000).toLocaleString();
        const badge = s.status === 'ok' ? 'text-emerald-600' : s.status === 'error' ? 'text-red-500' : 'text-amber-500';
        const detail = side === 'dns'
            ? (s.records_synced != null ? `${s.records_synced} records` : (s.reason || s.error || ''))
            : (s.subnets_synced != null ? `${s.subnets_synced} subnets / ${s.reservations_synced} reservations` : (s.reason || s.error || ''));
        return `<div class="text-xs text-slate-400 mt-2">NetBox auto-sync: <span class="${badge} font-medium">${escapeHtml(s.status)}</span> · ${escapeHtml(detail)} · <span title="${escapeHtml(when)}">${escapeHtml(when)}</span></div>`;
    } catch (_e) { return ''; }
}

async function loadDNSData(subMenu) {
    const container = document.getElementById('dns-content');
    if (!container) return;
    container.innerHTML = '<p class="text-sm text-slate-400 italic p-4">Loading…</p>';
    const addBtn = document.getElementById('dns-add-btn');
    // Add-record only applies to the Records tab; Statistics/Forwarders are read-only.
    if (addBtn) addBtn.classList.toggle('hidden', !(subMenu === 'Records' || !subMenu));

    const th = cols => `<thead class="bg-slate-50 text-xs text-slate-500 uppercase"><tr>${cols.map(c => `<th class="px-4 py-2 text-left font-medium">${c}</th>`).join('')}</tr></thead>`;
    const tw = html => `<div class="overflow-x-auto"><table class="w-full text-sm">${html}</table></div>`;
    const editIcon = `<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"></path></svg>`;
    const delIcon  = `<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>`;

    try {
        // ── Statistics: Unbound query telemetry (OPNsense-grade) ──────────
        if (subMenu === 'Statistics') {
            const { ok, data: d, detail } = await _spokeFetch('/api/dns/stats');
            if (!ok) { container.innerHTML = _spokeErrorBanner(detail, 'DNS spoke not connected'); return; }
            if (d.status && d.status !== 'SUCCESS') {
                container.innerHTML = _spokeErrorBanner(d.message, 'unbound-control stats unavailable'); return;
            }
            const g = d.global || {};
            const qt = d.query_types || {};
            const syncLine = await _ddSyncStatusLine('dns');
            const tiles = [
                _ddTile('Total Queries', (g.total_queries || 0).toLocaleString()),
                _ddTile('Cache Hit Ratio', `${g.cache_hit_ratio || 0}%`, `${(g.cache_hits || 0).toLocaleString()} hits / ${(g.cache_misses || 0).toLocaleString()} miss`,
                        (g.cache_hit_ratio || 0) >= 70 ? 'text-emerald-600' : 'text-amber-600'),
                _ddTile('Recursive Replies', (g.num_recursive || 0).toLocaleString(), `avg ${g.recursion_time_avg || 0}s`),
                _ddTile('Uptime', _ddUptime(g.uptime_seconds), `${(g.prefetch || 0).toLocaleString()} prefetched`),
            ].join('');
            // Per-type query breakdown as proportion-of-total bars.
            const typeTotal = Object.values(qt).reduce((a, b) => a + b, 0) || 1;
            const typeRows = Object.entries(qt).sort((a, b) => b[1] - a[1]).map(([t, c]) => `
                <div class="flex items-center gap-3 py-1">
                    <span class="w-16 text-xs font-mono font-medium text-slate-600">${escapeHtml(t)}</span>
                    <div class="flex-1">${_ddBar(Math.round(c / typeTotal * 100))}</div>
                    <span class="w-20 text-right text-xs font-mono text-slate-500">${c.toLocaleString()}</span>
                </div>`).join('');
            container.innerHTML = `
                <div class="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-4">${tiles}</div>
                <div class="bg-white border border-slate-200 rounded-lg p-4">
                    <div class="text-sm font-semibold text-slate-700 mb-2">Queries by Type</div>
                    ${typeRows || '<p class="text-slate-400 italic text-sm">No query-type data yet.</p>'}
                </div>
                ${syncLine}`;
            return;
        }

        // ── Forwarders: configured upstream resolvers ─────────────────────
        if (subMenu === 'Forwarders') {
            const { ok, data: d, detail } = await _spokeFetch('/api/dns/forwarders');
            if (!ok) { container.innerHTML = _spokeErrorBanner(detail, 'DNS spoke not connected'); return; }
            if (d.status && d.status !== 'SUCCESS') {
                container.innerHTML = _spokeErrorBanner(d.message, 'unbound-control forwarders unavailable'); return;
            }
            const fwds = d.forwarders || [];
            const cols = ['Zone', 'Class', 'Upstream Servers'];
            const rows = fwds.map(f => `<tr class="border-b border-slate-100 hover:bg-slate-50">
                <td class="px-4 py-2 font-mono font-medium">${escapeHtml(f.zone || '.')}</td>
                <td class="px-4 py-2 text-xs">${escapeHtml(f.class || 'IN')}</td>
                <td class="px-4 py-2 font-mono text-xs">${(f.upstreams || []).map(u => escapeHtml(u)).join(', ') || '—'}</td>
            </tr>`).join('');
            container.innerHTML = fwds.length === 0
                ? '<p class="p-4 text-slate-400 italic text-sm">No upstream forwarders configured (Unbound is resolving recursively from root).</p>'
                : tw(th(cols) + `<tbody>${rows}</tbody>`);
            return;
        }

        // ── Records (default) ─────────────────────────────────────────────
        const { ok, data: d, detail } = await _spokeFetch('/api/dns/records');
        if (!ok) {
            container.innerHTML = `${_spokeErrorBanner(detail, 'DNS spoke not connected')}<p class="px-4 pb-4 text-xs text-slate-400">Verify the Unbound configuration in Setup → DNS.</p>`;
            if (addBtn) addBtn.classList.add('hidden');
            return;
        }
        // Only show forward records in the editable list; auto-generated PTRs
        // (type PTR) are derived from A/AAAA values and not directly editable.
        const records = (d.records || []).filter(r => r.type !== 'PTR');
        window._dnsRecords = records;
        const cols = ['Name', 'Type', 'Value', 'TTL', ''];
        const rows = records.map(r => {
            const eName = String(r.name).replace(/'/g, "\\'");
            const eType = String(r.type).replace(/'/g, "\\'");
            return `<tr class="border-b border-slate-100 hover:bg-slate-50">
                <td class="px-4 py-2 font-mono font-medium">${escapeHtml(r.name)}</td>
                <td class="px-4 py-2"><span class="px-2 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-700">${escapeHtml(r.type)}</span></td>
                <td class="px-4 py-2 font-mono text-xs">${escapeHtml(r.value)}</td>
                <td class="px-4 py-2 text-center text-xs">${escapeHtml(String(r.ttl))}</td>
                <td class="px-4 py-2 whitespace-nowrap">
                    <button onclick="editDnsRecord('${eName}','${eType}')" title="Edit" class="p-1 text-slate-400 hover:text-blue-600 transition-colors">${editIcon}</button>
                    <button onclick="deleteDnsRecord('${eName}','${eType}')" title="Delete" class="p-1 text-slate-300 hover:text-red-500 transition-colors">${delIcon}</button>
                </td>
            </tr>`;
        }).join('');
        container.innerHTML = records.length === 0
            ? '<p class="p-4 text-slate-400 italic text-sm">No DNS records found.</p>'
            : tw(th(cols) + `<tbody>${rows}</tbody>`);
    } catch (err) {
        container.innerHTML = `<p class="p-4 text-red-500 text-sm">Error: ${err.message}</p>`;
    }
}

// ─── Certificate Management (le) view ──────────────────────────────────────
// Status bar (managed count) + a certificates table. The le spoke's handlers
// are structured stubs until certbot/acme.sh is wired, so the table is usually
// empty and the status bar carries the "not yet wired" message from the spoke.
async function loadLEData(subMenu) {
    const container = document.getElementById('le-content');
    if (!container) return;
    container.innerHTML = '<p class="text-sm text-slate-400 italic p-4">Loading…</p>';

    const th = cols => `<thead class="bg-slate-50 text-xs text-slate-500 uppercase"><tr>${cols.map(c => `<th class="px-4 py-2 text-left font-medium">${c}</th>`).join('')}</tr></thead>`;
    const tw = html => `<div class="overflow-x-auto"><table class="w-full text-sm">${html}</table></div>`;
    // The le spoke returns nested {status, data:{...}}; unwrap to the inner data
    // so both the nested le shape and a flat sibling shape resolve the same way.
    const inner = b => (b && typeof b.data === 'object' && b.data !== null) ? b.data : (b || {});

    // Status bar from /api/le/status (best-effort — falls back to the certs call).
    try {
        const s = await _spokeFetch('/api/le/status');
        const bar = document.getElementById('le-status-bar');
        if (bar && s.ok && s.data) {
            const d = inner(s.data);
            bar.innerHTML =
                `<span><b class="text-sm text-slate-700">${d.certs_managed ?? 0}</b> managed</span>`;
        } else if (bar) {
            bar.innerHTML = `<span class="text-amber-600">${s.detail || 'le spoke not connected'}</span>`;
        }
    } catch (e) { /* status is decorative; the certs call surfaces the real error */ }

    try {
        const { ok, data: d, detail } = await _spokeFetch('/api/le/certs');
        if (!ok) {
            container.innerHTML = `${_spokeErrorBanner(detail, 'Certificate (le) spoke not connected')}<p class="px-4 pb-4 text-xs text-slate-400">Install the le spoke (install_all.sh, or its install_le.sh) and approve it in Setup → Spokes &amp; Agents.</p>`;
            return;
        }
        const body = inner(d);
        const certs = body.certs || [];
        window._leCerts = certs;
        const tgtBadge = t => {
            const ok = t.last_status === 'SUCCESS';
            const cls = ok ? 'bg-green-100 text-green-700' : (t.last_status === 'ERROR' ? 'bg-red-100 text-red-700' : 'bg-slate-100 text-slate-500');
            const mark = ok ? '✓' : (t.last_status === 'ERROR' ? '✗' : '·');
            return `<span class="px-1.5 py-0.5 rounded text-xs font-medium ${cls}">${mark} ${t.module_type}${t.identifier ? '/' + t.identifier : ''}</span>`;
        };
        // Color-coded expiry badge from not_after. The le renewal loop renews
        // within 30d, so amber (<30d) = renew pending/failed, red (<7d / expired)
        // = at risk — surfaces a stuck renewal the hourly distribution wouldn't.
        const leExpiry = na => {
            if (!na) return { text: '—', cls: 'text-slate-400', days: null };
            const dt = new Date(na);
            if (isNaN(dt)) return { text: String(na).slice(0, 10), cls: 'text-slate-500', days: null };
            const days = Math.floor((dt.getTime() - Date.now()) / 86400000);
            let cls, label;
            if (days < 0) { cls = 'bg-red-100 text-red-700'; label = `expired ${-days}d ago`; }
            else if (days < 7) { cls = 'bg-red-100 text-red-700'; label = `${days}d left`; }
            else if (days < 30) { cls = 'bg-amber-100 text-amber-700'; label = `${days}d left`; }
            else { cls = 'bg-green-100 text-green-700'; label = `${days}d left`; }
            return { text: `${dt.toISOString().slice(0, 10)} · ${label}`, cls, days };
        };
        const cols = ['Domain', 'Email', 'Challenge', 'Staging', 'Expires', 'Targets', 'Actions'];
        const rows = certs.map(c => {
            const dEsc = escJsAttr(c.domain || '');
            const tgts = c.targets || [];
            const tgtCell = tgts.length
                ? `<div class="flex flex-wrap gap-1">${tgts.map(tgtBadge).join('')}</div>`
                : `<span class="text-xs text-slate-400 italic">none</span>`;
            const exp = leExpiry(c.not_after);
            return `<tr class="border-b border-slate-100 hover:bg-slate-50">
                <td class="px-4 py-2 font-mono font-medium">${c.domain || '—'}</td>
                <td class="px-4 py-2 text-xs">${c.email || '—'}</td>
                <td class="px-4 py-2"><span class="px-2 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-700">${c.challenge || '—'}</span></td>
                <td class="px-4 py-2 text-center text-xs">${c.staging ? 'yes' : 'no'}</td>
                <td class="px-4 py-2"><span class="px-2 py-0.5 rounded-full text-xs font-medium ${exp.cls}">${exp.text}</span></td>
                <td class="px-4 py-2"><div class="flex items-center gap-2">${tgtCell}<button onclick="showLeTargetsModal('${dEsc}')" class="text-xs text-green-700 hover:text-green-800 font-medium">manage</button></div></td>
                <td class="px-4 py-2"><div class="flex items-center gap-3 whitespace-nowrap">
                    <button onclick="leRenewCert('${dEsc}')" class="text-xs text-green-700 hover:text-green-800 font-medium" title="Renew this cert">Renew</button>
                    <button onclick="leRevokeCert('${dEsc}')" class="text-xs text-red-600 hover:text-red-700 font-medium" title="Revoke + remove from managed list">Revoke</button>
                </div></td>
            </tr>`;
        }).join('');
        // Top-of-card banner if any cert is expiring soon / expired / stuck
        // renewing (the le loop renews <30d, so amber+red here mean a renewal
        // that didn't land — worth surfacing above the table).
        const soon = certs.filter(c => { const x = leExpiry(c.not_after); return x.days !== null && x.days < 30; });
        const expBanner = soon.length === 0 ? '' : (() => {
            const expired = soon.filter(c => leExpiry(c.not_after).days < 0).length;
            const cls = expired > 0 ? 'bg-red-50 border-red-200 text-red-700' : 'bg-amber-50 border-amber-200 text-amber-700';
            const msg = expired > 0
                ? `${expired} cert(s) EXPIRED, ${soon.length - expired} expiring within 30d — check the le renewal loop / journalctl -u lm-le.`
                : `${soon.length} cert(s) expiring within 30d — the le renewal loop should renew these; verify with ⚡ Distribute now.`;
            return `<div class="mx-4 mt-3 mb-1 px-3 py-2 rounded-md border text-xs ${cls}">${msg}</div>`;
        })();
        const note = body.message ? `<p class="px-4 pb-3 text-xs text-slate-400 italic">${body.message}</p>` : '';
        container.innerHTML = certs.length === 0
            ? `${note}<p class="p-4 text-slate-400 italic text-sm">No managed certificates yet. Click <b class="text-slate-600 not-italic">＋ Issue certificate</b> above to configure an ACME account (email + challenge type) and issue your first cert.</p>`
            : expBanner + note + tw(th(cols) + `<tbody>${rows}</tbody>`);
    } catch (err) {
        container.innerHTML = `<p class="p-4 text-red-500 text-sm">Error: ${err.message}</p>`;
    }
}

// Re-push any stale cert material to its targets now (no certbot invocation —
// the hub pulls LE_GET_CERT and pushes INSTALL_CERT for changed targets only).
async function leDistributeNow() {
    try {
        const { ok, detail } = await _spokeFetch('/api/le/distribute', { method: 'POST' });
        if (!ok) alert('Distribute failed: ' + (detail || ''));
        await loadLEData();
    } catch (e) { alert('Distribute failed: ' + e.message); }
}

// Per-cert target manager modal. The hub brokers cert material from the le
// spoke to each target spoke (resolved by module_type); each target applies the
// cert to its own device. Wired INSTALL_CERT targets: firewall (OPNsense Trust
// API) + hypervisor (Proxmox — spoke relays to the per-node agent, which runs
// `pvenode cert set` on its local pveproxy; the target `identifier` is the node
// name) + directory (OpenLDAP — spoke writes PEM to /etc/ldap/tls, points
// slapd's olcTLS* via ldapmodify -Y EXTERNAL over ldapi, restarts slapd). Other
// module types record an ERROR ("does not support cert install yet") until wired.
const LE_MODULE_TYPES = [
    ['hub', 'hub (LM WebUI)'],
    ['firewall', 'firewall (OPNsense)'],
    ['ipam', 'ipam (NetBox)'],
    ['hypervisor', 'hypervisor (Proxmox)'],
    ['nac', 'nac (ClearPass)'],
    ['directory', 'directory (LDAP)'],
    ['simulation', 'simulation (Client Sim)'],
    ['nw', 'nw (Network Devices)'],
    ['dns', 'dns'], ['dhcp', 'dhcp'],
];

function showLeTargetsModal(domain) {
    const cert = (window._leCerts || []).find(c => c.domain === domain) || {};
    const tgts = cert.targets || [];
    const esc = s => String(s || '').replace(/'/g, "\\'").replace(/"/g, '&quot;');
    const row = (t, i) => {
        const ok = t.last_status === 'SUCCESS';
        const cls = ok ? 'bg-green-100 text-green-700' : (t.last_status === 'ERROR' ? 'bg-red-100 text-red-700' : 'bg-slate-100 text-slate-500');
        return `<tr class="border-b border-slate-100">
            <td class="px-3 py-2 text-xs font-mono">${t.module_type || '—'}${t.identifier ? ' / ' + esc(t.identifier) : ''}</td>
            <td class="px-3 py-2"><span class="px-2 py-0.5 rounded-full text-xs font-medium ${cls}">${t.last_status || 'pending'}</span></td>
            <td class="px-3 py-2 text-xs text-slate-500">${(t.last_pushed_at || '—').slice(0, 19).replace('T', ' ')}</td>
            <td class="px-3 py-2 text-xs text-slate-400">${t.last_message ? esc(t.last_message).slice(0, 60) : ''}</td>
            <td class="px-3 py-2"><button onclick="removeLeTarget('${esc(domain)}', ${i})" class="text-xs text-red-600 hover:text-red-700 font-medium">remove</button></td>
        </tr>`;
    };
    const mtOpts = LE_MODULE_TYPES.map(([v, lbl]) => `<option value="${v}">${lbl}</option>`).join('');
    const modal = document.createElement('div');
    modal.id = 'le-targets-modal';
    modal.className = 'fixed inset-0 bg-black/50 flex items-center justify-center z-50';
    modal.innerHTML = `<div class="bg-white rounded-xl shadow-xl max-w-2xl w-full p-6">
        <h3 class="text-lg font-bold mb-1">Distribution targets — <span class="font-mono">${esc(domain)}</span></h3>
        <p class="text-xs text-slate-500 mb-4">Each target is a spoke (by module type) the hub pushes this cert to; that spoke installs it on its device.</p>
        <div class="overflow-x-auto mb-4"><table class="w-full text-sm">
            <thead class="bg-slate-50 text-xs text-slate-500 uppercase"><tr>
                <th class="px-3 py-2 text-left font-medium">Target</th>
                <th class="px-3 py-2 text-left font-medium">Status</th>
                <th class="px-3 py-2 text-left font-medium">Last push</th>
                <th class="px-3 py-2 text-left font-medium">Message</th>
                <th></th>
            </tr></thead>
            <tbody>${tgts.length ? tgts.map(row).join('') : '<tr><td colspan="5" class="px-3 py-3 text-xs text-slate-400 italic">No targets yet — add one below, then “Distribute now”.</td></tr>'}</tbody>
        </table></div>
        <div class="flex flex-wrap items-end gap-2 border-t border-slate-200 pt-4">
            <div class="flex flex-col">
                <label class="text-xs text-slate-500 mb-1">Module type</label>
                <select id="le-tgt-mt" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">${mtOpts}</select>
            </div>
            <div class="flex flex-col flex-1 min-w-[180px]">
                <label class="text-xs text-slate-500 mb-1">Identifier (optional)</label>
                <input id="le-tgt-id" type="text" placeholder="e.g. edge-1" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500" />
            </div>
            <button onclick="addLeTarget('${esc(domain)}')" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-4 py-2 rounded-md text-sm font-bold">Add target</button>
            <button onclick="leDistributeNow()" class="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-md text-sm font-bold">Distribute now</button>
            <button onclick="document.getElementById('le-targets-modal').remove()" class="ml-auto bg-slate-100 hover:bg-slate-200 text-slate-700 px-4 py-2 rounded-md text-sm font-medium">Close</button>
        </div>
    </div>`;
    document.body.appendChild(modal);
}

async function addLeTarget(domain) {
    const mt = document.getElementById('le-tgt-mt')?.value;
    const identifier = document.getElementById('le-tgt-id')?.value?.trim() || '';
    if (!mt) { alert('Module type required'); return; }
    try {
        const { ok, detail } = await _spokeFetch(`/api/le/certs/${encodeURIComponent(domain)}/targets`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ module_type: mt, identifier }),
        });
        if (!ok) { alert('Add target failed: ' + (detail || '')); return; }
        await loadLEData();
        showLeTargetsModal(domain);
    } catch (e) { alert('Add target failed: ' + e.message); }
}

async function removeLeTarget(domain, idx) {
    try {
        const { ok, detail } = await _spokeFetch(`/api/le/certs/${encodeURIComponent(domain)}/targets/${idx}`, { method: 'DELETE' });
        if (!ok) { alert('Remove target failed: ' + (detail || '')); return; }
        await loadLEData();
        showLeTargetsModal(domain);
    } catch (e) { alert('Remove target failed: ' + e.message); }
}

// ── le action UI: issue / renew / revoke ─────────────────────────────────────
// All four spoke endpoints (/api/le/issue, /renew, /revoke, /distribute) already
// exist — this is the WebUI write/action half that was deferred when the read
// half (list + targets modal) was built. The issue modal's email field is the
// "configure certbot/acme account" entry point: certbot keeps the ACME account
// in /etc/letsencrypt/accounts/ keyed by the email supplied per-issue.

// DNS-01 providers supported by the le spoke (le/src/acme.py:_DNS_PLUGIN_APT).
// cloudflare + route53 are preinstalled by install_le.sh; the rest are
// apt-installed on demand by the spoke's ensure_dns_plugin(). Entries whose
// value is an alias (LE_DNS_PROVIDER_ALIAS) map to a different certbot plugin
// name at submit time — e.g. Hurricane Electric's free DNS (dns.he.net) does
// dynamic updates over RFC 2136 + TSIG, so it uses the certbot-dns-rfc2136
// plugin and the spoke receives dns_provider="rfc2136" (so certbot gets
// --dns-rfc2136 and creds land at /etc/lm-le/dns-rfc2136.ini).
const LE_DNS_PROVIDERS = [
    ['cloudflare', 'Cloudflare'],
    ['route53', 'AWS Route 53'],
    ['google', 'Google Domains'],
    ['digitalocean', 'DigitalOcean'],
    ['linode', 'Linode'],
    ['rfc2136', 'RFC 2136 (BIND)'],
    ['he-login', 'Hurricane Electric (account login)'],
    ['he', 'Hurricane Electric (RFC 2136 / TSIG)'],
    ['hetzner', 'Hetzner'],
    ['inwx', 'INWX'],
    ['transip', 'TransIP'],
];

// Frontend-only provider aliases → the certbot plugin name the spoke must
// receive. Keys are LE_DNS_PROVIDERS entries; values are the real
// _DNS_PLUGIN_APT name in le/src/acme.py.
const LE_DNS_PROVIDER_ALIAS = {
    he: 'rfc2136',
};

// Per-provider INI key shown as the DNS creds placeholder. The le spoke writes
// the raw content to /etc/lm-le/dns-<provider>.ini at 0600 (write_dns_creds).
const LE_DNS_CREDS_HINT = {
    cloudflare: 'dns_cloudflare_api_token = YOUR_TOKEN',
    route53:    'dns_route53_access_key_id = ...\ndns_route53_secret_access_key = ...',
    google:     'dns_google_domains_access_token = ...',
    digitalocean: 'dns_digitalocean_token = ...',
    linode:     'dns_linode_api_key = ...',
    rfc2136:    'dns_rfc2136_server = ...\ndns_rfc2136_name = ...\ndns_rfc2136_secret = ...',
    he:         '# Hurricane Electric dns.he.net — TSIG dynamic update\n' +
                'dns_rfc2136_server = 216.218.130.2\n' +  // ns1.he.net (certbot needs an IP)
                'dns_rfc2136_port = 53\n' +
                'dns_rfc2136_name = YOUR_KEY_NAME\n' +
                'dns_rfc2136_secret = YOUR_TSIG_SECRET\n' +
                'dns_rfc2136_algorithm = hmac-sha256',
    hetzner:    'dns_hetzner_api_token = ...',
    inwx:       'dns_inwx_url = https://api.domrobot.com/xmlrpc/\ndns_inwx_username = ...\ndns_inwx_password = ...',
    transip:    'dns_transip_username = ...\ndns_transip_api_key = ...',
};

// RFC 2136 family — providers whose certbot plugin is --dns-rfc2136 and whose
// only user-supplied secrets are a TSIG key name + key secret. For these we
// show a friendly two-field form (server/port/algorithm under "Advanced") and
// assemble the INI ourselves, instead of the raw textarea. Hurricane Electric
// (he) is an alias of rfc2136 (LE_DNS_PROVIDER_ALIAS above).
const LE_RFC2136_PROVIDERS = new Set(['rfc2136', 'he']);

// Default server pre-fill for the Advanced "Server" field, by provider. Empty
// string = leave the placeholder visible (user fills it).
// certbot-dns-rfc2136 requires the server as a literal IP (a hostname is
// rejected). ns1.he.net = 216.218.130.2 (HE's stable anycast); default to the IP
// so the form works even before the le spoke's hostname resolver is deployed.
const LE_RFC2136_DEFAULT_SERVER = { he: '216.218.130.2', rfc2136: '' };

// Initial-targets picker state for the issue modal. Array of {module_type, identifier}.
let _leIssueTargets = [];

function leIssueToggleChallenge() {
    const sel = document.getElementById('le-issue-challenge');
    if (!sel) return;
    const ch = sel.value;                       // http | http-webroot | dns | tls-alpn
    const set = (id, show) => { const el = document.getElementById(id); if (el) el.classList.toggle('hidden', !show); };
    set('le-issue-webroot-row', ch === 'http-webroot');
    set('le-issue-dns-cred-row', ch === 'dns');
    set('le-issue-dns-provider-row', ch === 'dns');
    set('le-issue-dns-creds-row', ch === 'dns');
    // Populate the DNS fields for the (default) provider as soon as the DNS-01
    // row appears, so the right input shape is visible without a provider
    // re-select. Also load the tenant's saved credentials into the picker.
    if (ch === 'dns') { leIssueUpdateDnsFields(); leIssuePopulateCreds(); }
}

// Load the tenant's saved DNS credentials into the issue-form picker.
async function leIssuePopulateCreds() {
    const sel = document.getElementById('le-issue-dns-credential');
    if (!sel || sel.dataset.loaded) return;
    try {
        const r = await _spokeFetch('/api/le/dns-credentials', { method: 'GET' });
        const d = (r.data && r.data.data) ? r.data.data : (r.data || {});
        const creds = d.credentials || [];
        sel.innerHTML = '<option value="">— enter manually below —</option>' +
            creds.map(c => {
                const label = (DNS_CRED_PROVIDERS[c.provider] || {}).label || c.provider;
                return `<option value="${escapeHtml(c.name)}">${escapeHtml(c.name)} — ${escapeHtml(label)}</option>`;
            }).join('');
        sel.dataset.loaded = '1';
    } catch (e) { /* leave manual entry available */ }
}

// When a saved credential is picked, it supplies the provider + secrets, so hide
// the manual provider/creds inputs; "— enter manually —" shows them again.
function leIssueToggleSavedCred() {
    const useSaved = !!document.getElementById('le-issue-dns-credential')?.value;
    const set = (id, show) => { const el = document.getElementById(id); if (el) el.classList.toggle('hidden', !show); };
    set('le-issue-dns-provider-row', !useSaved);
    set('le-issue-dns-creds-row', !useSaved);
    if (!useSaved) leIssueUpdateDnsFields();
}

function leIssueAddTarget() {
    const mt = document.getElementById('le-issue-tgt-mt')?.value;
    const identifier = document.getElementById('le-issue-tgt-id')?.value?.trim() || '';
    if (!mt) { alert('Pick a module type first'); return; }
    _leIssueTargets.push({ module_type: mt, identifier });
    document.getElementById('le-issue-tgt-id').value = '';
    leIssueRenderTargets();
}

function leIssueRemoveTarget(i) {
    _leIssueTargets.splice(i, 1);
    leIssueRenderTargets();
}

function leIssueRenderTargets() {
    const cell = document.getElementById('le-issue-targets-list');
    if (!cell) return;
    cell.innerHTML = _leIssueTargets.length === 0
        ? `<span class="text-xs text-slate-400 italic">none — add below (optional)</span>`
        : `<div class="flex flex-wrap gap-1">${_leIssueTargets.map((t, i) =>
            `<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-slate-100 text-slate-700">
                ${t.module_type}${t.identifier ? '/' + escapeHtml(t.identifier) : ''}
                <button onclick="leIssueRemoveTarget(${i})" class="text-slate-400 hover:text-red-600" type="button">✕</button>
            </span>`).join('')}</div>`;
}

function showLeIssueModal() {
    _leIssueTargets = [];
    const mtOpts = LE_MODULE_TYPES.map(([v, lbl]) => `<option value="${v}">${lbl}</option>`).join('');
    const dnsOpts = LE_DNS_PROVIDERS.map(([v, lbl]) => `<option value="${v}">${lbl}</option>`).join('');
    // Remove any prior modal (e.g. left over from a previous open).
    document.getElementById('le-issue-modal')?.remove();
    const modal = document.createElement('div');
    modal.id = 'le-issue-modal';
    modal.className = 'fixed inset-0 bg-black/50 flex items-center justify-center z-50 overflow-y-auto py-6';
    modal.innerHTML = `<div class="bg-white rounded-xl shadow-xl max-w-2xl w-full p-6 my-auto">
        <h3 class="text-lg font-bold mb-1">Issue a certificate</h3>
        <p class="text-xs text-slate-500 mb-4">Runs <code>certbot certonly</code> on the le spoke. The ACME account email below is registered with Let's Encrypt on first use and reused after. Staging issues an untrusted cert — use it to validate the flow before going live.</p>
        <div class="space-y-3">
            <div class="grid grid-cols-2 gap-3">
                <div class="flex flex-col">
                    <label class="text-xs text-slate-500 mb-1">Domain <span class="text-red-500">*</span></label>
                    <input id="le-issue-domain" type="text" placeholder="www.example.com" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500" />
                </div>
                <div class="flex flex-col">
                    <label class="text-xs text-slate-500 mb-1">ACME account email <span class="text-red-500">*</span></label>
                    <input id="le-issue-email" type="email" placeholder="admin@example.com" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500" />
                </div>
            </div>
            <div class="grid grid-cols-2 gap-3">
                <div class="flex flex-col">
                    <label class="text-xs text-slate-500 mb-1">Challenge type</label>
                    <select id="le-issue-challenge" onchange="leIssueToggleChallenge()" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                        <option value="http">HTTP-01 (standalone)</option>
                        <option value="http-webroot">HTTP-01 (webroot)</option>
                        <option value="dns">DNS-01</option>
                        <option value="tls-alpn">TLS-ALPN-01</option>
                    </select>
                </div>
                <div class="flex flex-col">
                    <label class="text-xs text-slate-500 mb-1">Key type</label>
                    <select id="le-issue-keytype" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                        <option value="rsa">RSA</option>
                        <option value="ecdsa">ECDSA</option>
                    </select>
                </div>
            </div>
            <div id="le-issue-webroot-row" class="flex flex-col hidden">
                <label class="text-xs text-slate-500 mb-1">Webroot path</label>
                <input id="le-issue-webroot" type="text" placeholder="/var/www/html" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500" />
            </div>
            <div id="le-issue-dns-cred-row" class="flex flex-col hidden">
                <label class="text-xs text-slate-500 mb-1">Saved DNS credential</label>
                <select id="le-issue-dns-credential" onchange="leIssueToggleSavedCred()" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                    <option value="">— enter manually below —</option>
                </select>
                <p class="text-[11px] text-slate-400 mt-1">Pick one of your tenant's saved credentials (manage via 🔑 DNS Credentials), or enter one manually below.</p>
            </div>
            <div id="le-issue-dns-provider-row" class="flex flex-col hidden">
                <label class="text-xs text-slate-500 mb-1">DNS provider</label>
                <select id="le-issue-dns-provider" onchange="leIssueUpdateDnsFields()" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">${dnsOpts}</select>
            </div>
            <div id="le-issue-dns-creds-row" class="flex flex-col hidden">
                <label class="text-xs text-slate-500 mb-1">DNS credentials <span class="text-slate-400">(written to /etc/lm-le/dns-&lt;provider&gt;.ini at 0600)</span></label>
                <!-- RFC 2136 family (rfc2136, Hurricane Electric): structured
                     key name + key secret — the only two values you actually
                     need. Server/port/algorithm are behind "Advanced". -->
                <div id="le-issue-dns-structured" class="space-y-2 hidden">
                    <div class="grid grid-cols-2 gap-3">
                        <div class="flex flex-col">
                            <label class="text-[11px] text-slate-500 mb-0.5">Key name <span class="text-red-500">*</span></label>
                            <input id="le-issue-dns-keyname" type="text" placeholder="YOUR_KEY_NAME" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm font-mono outline-none focus:ring-2 focus:ring-green-500" />
                        </div>
                        <div class="flex flex-col">
                            <label class="text-[11px] text-slate-500 mb-0.5">Key secret <span class="text-red-500">*</span></label>
                            <input id="le-issue-dns-keysecret" type="password" placeholder="YOUR_TSIG_SECRET" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm font-mono outline-none focus:ring-2 focus:ring-green-500" />
                        </div>
                    </div>
                    <details class="text-xs">
                        <summary class="cursor-pointer text-slate-500 hover:text-slate-700 select-none">Advanced — server / port / algorithm</summary>
                        <div class="grid grid-cols-3 gap-2 mt-2">
                            <div class="flex flex-col">
                                <label class="text-[11px] text-slate-400 mb-0.5">Server</label>
                                <input id="le-issue-dns-server" type="text" placeholder="216.218.130.2 (IP, not a hostname)" class="w-full bg-white border border-slate-300 rounded-md px-2 py-1.5 text-sm font-mono outline-none focus:ring-2 focus:ring-green-500" />
                            </div>
                            <div class="flex flex-col">
                                <label class="text-[11px] text-slate-400 mb-0.5">Port</label>
                                <input id="le-issue-dns-port" type="text" value="53" class="w-full bg-white border border-slate-300 rounded-md px-2 py-1.5 text-sm font-mono outline-none focus:ring-2 focus:ring-green-500" />
                            </div>
                            <div class="flex flex-col">
                                <label class="text-[11px] text-slate-400 mb-0.5">Algorithm</label>
                                <select id="le-issue-dns-algo" class="w-full bg-white border border-slate-300 rounded-md px-2 py-1.5 text-sm font-mono outline-none focus:ring-2 focus:ring-green-500">
                                    <option value="hmac-sha256">hmac-sha256</option>
                                    <option value="hmac-sha512">hmac-sha512</option>
                                    <option value="hmac-sha1">hmac-sha1</option>
                                    <option value="hmac-md5">hmac-md5</option>
                                </select>
                            </div>
                        </div>
                    </details>
                </div>
                <!-- Hurricane Electric ACCOUNT LOGIN (dns.he.net web panel; no
                     TSIG, no IP). Blank fields → use the saved HE account knob
                     (Setup → Certificates). -->
                <div id="le-issue-he-login" class="space-y-2 hidden">
                    <p class="text-[11px] text-slate-400">Sets the <span class="font-mono">_acme-challenge</span> TXT via the dns.he.net web panel with your HE account — no per-record TSIG keys. Leave blank to use the saved HE account (Setup → Certificates → Hurricane Electric login).</p>
                    <div class="grid grid-cols-2 gap-3">
                        <div class="flex flex-col">
                            <label class="text-[11px] text-slate-500 mb-0.5">HE account email</label>
                            <input id="le-issue-he-user" type="text" placeholder="(use saved account)" autocomplete="off" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500" />
                        </div>
                        <div class="flex flex-col">
                            <label class="text-[11px] text-slate-500 mb-0.5">HE account password</label>
                            <input id="le-issue-he-pass" type="password" placeholder="(use saved account)" autocomplete="new-password" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500" />
                        </div>
                    </div>
                </div>
                <!-- Non-rfc2136 providers: raw INI textarea (field shapes vary
                     per provider — sample shown as a grey placeholder). -->
                <textarea id="le-issue-dns-creds" rows="5" placeholder="" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm font-mono outline-none focus:ring-2 focus:ring-green-500 placeholder:text-slate-400 placeholder:font-mono placeholder:text-xs"></textarea>
            </div>
            <div class="flex items-center gap-4">
                <label class="flex items-center gap-2 text-sm text-slate-700">
                    <input id="le-issue-staging" type="checkbox" class="rounded border-slate-300" />
                    Use Let's Encrypt <b>staging</b> (untrusted — for testing)
                </label>
            </div>
            <div class="border-t border-slate-200 pt-3">
                <label class="text-xs text-slate-500 mb-1 block">Initial distribution targets (optional)</label>
                <div id="le-issue-targets-list" class="mb-2"></div>
                <div class="flex flex-wrap items-end gap-2">
                    <div class="flex flex-col">
                        <label class="text-[11px] text-slate-400 mb-0.5">Module type</label>
                        <select id="le-issue-tgt-mt" class="bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">${mtOpts}</select>
                    </div>
                    <div class="flex flex-col flex-1 min-w-[160px]">
                        <label class="text-[11px] text-slate-400 mb-0.5">Identifier (optional)</label>
                        <input id="le-issue-tgt-id" type="text" placeholder="e.g. edge-1" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500" onkeydown="if(event.key==='Enter'){event.preventDefault();leIssueAddTarget();}" />
                    </div>
                    <button onclick="leIssueAddTarget()" type="button" class="bg-slate-100 hover:bg-slate-200 text-slate-700 px-3 py-2 rounded-md text-sm font-medium">Add</button>
                </div>
            </div>
        </div>
        <div class="flex justify-end gap-2 mt-5">
            <button onclick="document.getElementById('le-issue-modal').remove()" class="bg-slate-100 hover:bg-slate-200 text-slate-700 px-4 py-2 rounded-md text-sm font-medium">Cancel</button>
            <button onclick="leIssueCert()" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-4 py-2 rounded-md text-sm font-bold">Issue certificate</button>
        </div>
    </div>`;
    document.body.appendChild(modal);
    leIssueRenderTargets();
    leIssueUpdateDnsFields();
}

// Toggle the DNS-01 input shape for the selected provider. RFC 2136 family
// (rfc2136, Hurricane Electric) gets the friendly key-name + key-secret form
// (server/port/algorithm under "Advanced"); every other provider gets the raw
// INI textarea with a per-provider sample placeholder.
function leIssueUpdateDnsFields() {
    const p = document.getElementById('le-issue-dns-provider')?.value;
    if (!p) return;
    const heLogin = p === 'he-login';
    const structured = LE_RFC2136_PROVIDERS.has(p);
    const setShown = (id, show) => { const el = document.getElementById(id); if (el) el.classList.toggle('hidden', !show); };
    setShown('le-issue-he-login', heLogin);
    setShown('le-issue-dns-structured', structured && !heLogin);
    setShown('le-issue-dns-creds', !structured && !heLogin);
    if (heLogin) {
        // nothing to prefill — creds come from the fields or the saved knob
    } else if (structured) {
        // Pre-fill the Advanced "Server" field with the provider default when
        // it's empty (Hurricane Electric → ns1.he.net) so the user only types
        // the two secrets. Don't clobber a value they already entered.
        const srv = document.getElementById('le-issue-dns-server');
        const def = LE_RFC2136_DEFAULT_SERVER[p] || '';
        if (srv && !srv.value) srv.value = def;
    } else {
        const ta = document.getElementById('le-issue-dns-creds');
        if (ta) ta.placeholder = LE_DNS_CREDS_HINT[p] || '';
    }
}

// Assemble the rfc2136 INI from the structured fields. Sent as `dns_creds` —
// the le spoke writes it to /etc/lm-le/dns-rfc2136.ini at 0600 (write_dns_creds).
function leIssueBuildRfc2136Ini() {
    const kn = document.getElementById('le-issue-dns-keyname')?.value?.trim() || '';
    const ks = document.getElementById('le-issue-dns-keysecret')?.value || '';
    const srv = document.getElementById('le-issue-dns-server')?.value?.trim() || '';
    const port = document.getElementById('le-issue-dns-port')?.value?.trim() || '53';
    const algo = document.getElementById('le-issue-dns-algo')?.value || 'hmac-sha256';
    let ini = '';
    if (srv) ini += `dns_rfc2136_server = ${srv}\n`;
    ini += `dns_rfc2136_port = ${port}\n`;
    // certbot-dns-rfc2136 property names are dns_rfc2136_name / _secret (NOT
    // _key_name / _key_secret) — the wrong keys produced "Property
    // dns_rfc2136_name not found" and the issue failed.
    ini += `dns_rfc2136_name = ${kn}\n`;
    ini += `dns_rfc2136_secret = ${ks}\n`;
    ini += `dns_rfc2136_algorithm = ${algo}\n`;
    return { ini, keyName: kn, keySecret: ks };
}

async function leIssueCert() {
    const domain = document.getElementById('le-issue-domain')?.value?.trim();
    const email = document.getElementById('le-issue-email')?.value?.trim();
    const chSel = document.getElementById('le-issue-challenge')?.value || 'http';
    const challenge = chSel === 'http-webroot' ? 'http' : chSel;
    const webroot = chSel === 'http-webroot' ? (document.getElementById('le-issue-webroot')?.value?.trim() || '') : '';
    // A saved (named) DNS credential wins — it supplies the provider + secrets
    // server-side, so the manual provider/creds inputs are skipped entirely.
    const savedCred = chSel === 'dns' ? (document.getElementById('le-issue-dns-credential')?.value || '') : '';
    const dnsProvider = chSel === 'dns' ? (document.getElementById('le-issue-dns-provider')?.value || '') : '';
    // For rfc2136-family providers the creds come from the structured key-name
    // / key-secret fields (assembled into an INI below); otherwise from the
    // raw INI textarea.
    const _heLogin = chSel === 'dns' && dnsProvider === 'he-login';
    const _rfc = chSel === 'dns' && dnsProvider && LE_RFC2136_PROVIDERS.has(dnsProvider);
    const _rfcIni = _rfc ? leIssueBuildRfc2136Ini() : null;
    const dnsCreds = _rfc ? _rfcIni.ini
        : (chSel === 'dns' ? (document.getElementById('le-issue-dns-creds')?.value || '') : '');
    const staging = !!document.getElementById('le-issue-staging')?.checked;
    const keyType = document.getElementById('le-issue-keytype')?.value || 'rsa';

    if (!domain) { alert('Domain is required'); return; }
    if (!email) { alert('ACME account email is required'); return; }
    if (chSel === 'http-webroot' && !webroot) { alert('Webroot path is required for HTTP-01 webroot'); return; }
    if (challenge === 'dns' && !savedCred) {
        if (!dnsProvider) { alert('Pick a saved DNS credential or a DNS provider for DNS-01'); return; }
        if (_rfc) {
            if (!_rfcIni.keyName) { alert('TSIG key name is required'); return; }
            if (!_rfcIni.keySecret) { alert('TSIG key secret is required'); return; }
        } else if (!_heLogin && !dnsCreds.trim()) {
            alert('DNS credentials INI is required for DNS-01'); return;
        }
    }

    const body = { domain, email, challenge, staging, key_type: keyType };
    if (chSel === 'http-webroot') body.webroot = webroot;
    // Resolve frontend provider aliases (e.g. Hurricane Electric → rfc2136) so
    // the spoke receives the real certbot plugin name.
    if (challenge === 'dns' && savedCred) {
        // Named tenant credential: the spoke resolves provider + secrets from it.
        body.dns_credential = savedCred;
    } else if (challenge === 'dns') {
        body.dns_provider = LE_DNS_PROVIDER_ALIAS[dnsProvider] || dnsProvider;
        if (_heLogin) {
            // HE account login: send per-request creds if typed, else the spoke
            // uses the saved knob. No dns_creds INI for this provider.
            const hu = document.getElementById('le-issue-he-user')?.value?.trim() || '';
            const hp = document.getElementById('le-issue-he-pass')?.value || '';
            if (hu) body.he_username = hu;
            if (hp) body.he_password = hp;
        } else {
            body.dns_creds = dnsCreds;
        }
    }
    if (_leIssueTargets.length) body.targets = _leIssueTargets;

    const btn = document.querySelector('#le-issue-modal button.bg-\\[\\#01A982\\]');
    if (btn) { btn.disabled = true; btn.textContent = 'Issuing…'; }
    try {
        const { ok, data, detail } = await _spokeFetch('/api/le/issue', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        if (!ok) {
            alert('Issue failed: ' + (detail || ''));
            if (btn) { btn.disabled = false; btn.textContent = 'Issue certificate'; }
            return;
        }
        // The spoke returns nested {status, data:{...}}; the hub adds
        // data.distribution (per-target push summary from net_services.py:le_issue_cert).
        const inner = (data && data.data) ? data.data : (data || {});
        const dist = inner.distribution || [];
        const distMsg = dist.length
            ? '\n\nDistribution:\n' + dist.map(d => {
                const st = d.status === 'SUCCESS' ? '✓' : '✗';
                return `  ${st} ${d.module_type || ''}${d.identifier ? '/' + d.identifier : ''}${d.message ? ' — ' + d.message : ''}`;
            }).join('\n')
            : '';
        alert('Issued ' + domain + (staging ? ' (staging)' : '') + '.' + distMsg);
        document.getElementById('le-issue-modal')?.remove();
        await loadLEData();
    } catch (e) {
        alert('Issue failed: ' + e.message);
        if (btn) { btn.disabled = false; btn.textContent = 'Issue certificate'; }
    }
}

// Hurricane Electric account-login knob — stored once on the le spoke (0600) and
// reused for every "Hurricane Electric (account login)" DNS-01 issue + renewal.
async function showHeLoginModal() {
    let cur = { configured: false, he_username: '' };
    try {
        const r = await _spokeFetch('/api/le/he-config', { method: 'GET' });
        if (r.ok) cur = (r.data && r.data.data) ? r.data.data : (r.data || cur);
    } catch (e) { /* spoke may be down; show empty form */ }
    const modal = document.createElement('div');
    modal.id = 'he-login-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm';
    const status = cur.configured
        ? `<span class="text-green-600">Currently configured${cur.he_username ? ' (' + escapeHtml(cur.he_username) + ')' : ''}.</span>`
        : '<span class="text-slate-400">Not configured yet.</span>';
    modal.innerHTML = `
      <div class="bg-white rounded-xl shadow-2xl w-full max-w-md overflow-hidden">
        <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50">
          <h3 class="text-lg font-bold text-[#263040]">Hurricane Electric account</h3>
          <button onclick="document.getElementById('he-login-modal').remove()" class="text-slate-400 hover:text-slate-600">✕</button>
        </div>
        <div class="p-6 space-y-3">
          <p class="text-xs text-slate-500">Stored once and reused for every <b>Hurricane Electric (account login)</b> DNS-01 issue &amp; renewal — no per-record TSIG keys or IP. ${status}</p>
          <div class="space-y-1"><label class="text-xs text-slate-500 uppercase font-bold">Account email</label><input id="he-cfg-user" type="text" value="${escapeHtml(cur.he_username || '')}" autocomplete="off" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"></div>
          <div class="space-y-1"><label class="text-xs text-slate-500 uppercase font-bold">Account password</label><input id="he-cfg-pass" type="password" placeholder="${cur.configured ? 're-enter to change' : ''}" autocomplete="new-password" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"></div>
        </div>
        <div class="px-6 py-4 bg-slate-50 border-t border-slate-200 flex justify-end gap-3">
          <button onclick="document.getElementById('he-login-modal').remove()" class="px-4 py-2 text-sm font-medium text-slate-600 hover:text-slate-800">Cancel</button>
          <button onclick="saveHeLogin()" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-6 py-2 rounded-md text-sm font-bold">Save</button>
        </div>
      </div>`;
    document.body.appendChild(modal);
}

async function saveHeLogin() {
    const u = document.getElementById('he-cfg-user')?.value?.trim() || '';
    const p = document.getElementById('he-cfg-pass')?.value || '';
    if (!u || !p) { alert('Both account email and password are required.'); return; }
    try {
        const r = await _spokeFetch('/api/le/he-config', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ he_username: u, he_password: p }),
        });
        if (!r.ok) { alert('Save failed: ' + (r.detail || '')); return; }
        showToast('Hurricane Electric login saved', 'success');
        document.getElementById('he-login-modal')?.remove();
    } catch (e) { alert('Save failed: ' + e.message); }
}

// ── Per-tenant DNS-01 credential manager (settings screen) ───────────────────
// Multi-tenant, multi-provider: each tenant keeps named credentials for
// he-login / cloudflare / rfc2136 / route53. Certs pick one BY NAME at issue.
const DNS_CRED_PROVIDERS = {
    'he-login':   { label: 'Hurricane Electric (account login)', fields: [
        { k: 'username', label: 'Account email', type: 'text' },
        { k: 'password', label: 'Account password', type: 'password', secret: true } ] },
    'cloudflare': { label: 'Cloudflare (API token)', fields: [
        { k: 'api_token', label: 'API token (Zone.DNS edit)', type: 'password', secret: true } ] },
    'rfc2136':    { label: 'RFC2136 dynamic DNS (TSIG)', fields: [
        { k: 'server', label: 'DNS server (IP address)', type: 'text', placeholder: 'e.g. 192.0.2.53' },
        { k: 'name', label: 'TSIG key name', type: 'text' },
        { k: 'secret', label: 'TSIG key secret', type: 'password', secret: true },
        { k: 'algorithm', label: 'Algorithm', type: 'text', placeholder: 'HMAC-SHA512' } ] },
    'route53':    { label: 'AWS Route 53', fields: [
        { k: 'access_key_id', label: 'AWS access key ID', type: 'text' },
        { k: 'secret_access_key', label: 'AWS secret access key', type: 'password', secret: true } ] },
};

async function showDnsCredentialsModal() {
    const modal = document.createElement('div');
    modal.id = 'dns-creds-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm';
    const provOpts = Object.entries(DNS_CRED_PROVIDERS).map(([k, v]) => `<option value="${k}">${escapeHtml(v.label)}</option>`).join('');
    modal.innerHTML = `
      <div class="bg-white rounded-xl shadow-2xl w-full max-w-2xl overflow-hidden max-h-[90vh] flex flex-col">
        <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50">
          <h3 class="text-lg font-bold text-[#263040]">DNS-01 credentials</h3>
          <button onclick="document.getElementById('dns-creds-modal').remove()" class="text-slate-400 hover:text-slate-600">✕</button>
        </div>
        <div class="p-6 space-y-4 overflow-y-auto">
          <p class="text-xs text-slate-500">Saved DNS-01 credentials for <b>your tenant</b>. A certificate picks one by name when issuing via DNS-01. Secrets are stored on the le spoke (0600) and never shown again — leave a secret blank when editing to keep it.</p>
          <div id="dns-creds-list" class="space-y-2"><p class="text-sm text-slate-400 italic">Loading…</p></div>
          <div class="border-t border-slate-200 pt-4">
            <h4 id="dns-cred-form-title" class="text-sm font-bold text-slate-600 mb-2">Add a credential</h4>
            <div class="grid grid-cols-2 gap-3">
              <div class="flex flex-col"><label class="text-[11px] text-slate-500 mb-0.5">Name</label>
                <input id="dns-cred-name" type="text" placeholder="e.g. HE - lrbtech" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"></div>
              <div class="flex flex-col"><label class="text-[11px] text-slate-500 mb-0.5">Provider</label>
                <select id="dns-cred-provider" onchange="dnsCredRenderFields()" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">${provOpts}</select></div>
            </div>
            <div id="dns-cred-fields" class="grid grid-cols-2 gap-3 mt-3"></div>
            <div class="flex justify-end gap-2 mt-3">
              <button onclick="dnsCredResetForm()" class="px-3 py-1.5 text-sm text-slate-600 hover:text-slate-800">Clear</button>
              <button onclick="saveDnsCredential()" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-4 py-1.5 rounded-md text-sm font-bold">Save credential</button>
            </div>
          </div>
        </div>
      </div>`;
    document.body.appendChild(modal);
    dnsCredRenderFields();
    await dnsCredReloadList();
}

function dnsCredRenderFields(values) {
    const p = document.getElementById('dns-cred-provider')?.value;
    const def = DNS_CRED_PROVIDERS[p];
    const box = document.getElementById('dns-cred-fields');
    if (!def || !box) return;
    values = values || {};
    const secretsSet = values.__secrets__ || {};
    box.innerHTML = def.fields.map(f => `
      <div class="flex flex-col">
        <label class="text-[11px] text-slate-500 mb-0.5">${escapeHtml(f.label)}</label>
        <input id="dns-cred-f-${f.k}" type="${f.type}" value="${f.secret ? '' : escapeHtml(values[f.k] || '')}"
               placeholder="${f.secret && secretsSet[f.k] ? '(keep stored)' : (f.placeholder ? escapeHtml(f.placeholder) : '')}"
               autocomplete="off" class="w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
      </div>`).join('');
}

async function dnsCredReloadList() {
    const box = document.getElementById('dns-creds-list');
    if (!box) return;
    let creds = [];
    try {
        const r = await _spokeFetch('/api/le/dns-credentials', { method: 'GET' });
        const d = (r.data && r.data.data) ? r.data.data : (r.data || {});
        creds = d.credentials || [];
    } catch (e) { box.innerHTML = `<p class="text-sm text-red-500">Could not load: ${escapeHtml(e.message)}</p>`; return; }
    if (!creds.length) { box.innerHTML = '<p class="text-sm text-slate-400 italic">No credentials yet — add one below.</p>'; return; }
    box.innerHTML = creds.map(c => {
        const label = (DNS_CRED_PROVIDERS[c.provider] || {}).label || c.provider;
        return `<div class="flex items-center justify-between border border-slate-200 rounded-md px-3 py-2">
          <div><span class="text-sm font-medium text-slate-700">${escapeHtml(c.name)}</span>
            <span class="text-[11px] text-slate-400 ml-2">${escapeHtml(label)}</span></div>
          <div class="flex gap-2">
            <button onclick='dnsCredEdit(${escapeHtml(JSON.stringify(c))})' class="text-xs text-slate-600 hover:text-slate-800 border border-slate-200 rounded px-2 py-1">Edit</button>
            <button onclick="deleteDnsCredential(${escapeHtml(JSON.stringify(c.name))})" class="text-xs text-red-500 hover:text-red-700 border border-red-200 rounded px-2 py-1">Delete</button>
          </div></div>`;
    }).join('');
}

function dnsCredEdit(c) {
    const nameEl = document.getElementById('dns-cred-name');
    const provEl = document.getElementById('dns-cred-provider');
    if (nameEl) nameEl.value = c.name || '';
    if (provEl) provEl.value = c.provider || 'he-login';
    const title = document.getElementById('dns-cred-form-title');
    if (title) title.textContent = 'Edit "' + (c.name || '') + '"';
    dnsCredRenderFields({ ...(c.fields || {}), __secrets__: c.secrets_set || {} });
}

function dnsCredResetForm() {
    const nameEl = document.getElementById('dns-cred-name'); if (nameEl) nameEl.value = '';
    const title = document.getElementById('dns-cred-form-title'); if (title) title.textContent = 'Add a credential';
    dnsCredRenderFields();
}

async function saveDnsCredential() {
    const name = document.getElementById('dns-cred-name')?.value?.trim() || '';
    const provider = document.getElementById('dns-cred-provider')?.value || '';
    if (!name) { alert('Credential name is required.'); return; }
    const def = DNS_CRED_PROVIDERS[provider];
    const fields = {};
    def.fields.forEach(f => {
        const v = document.getElementById('dns-cred-f-' + f.k)?.value ?? '';
        if (v !== '' || !f.secret) fields[f.k] = v;  // empty secret → omit (keep stored)
    });
    try {
        const r = await _spokeFetch('/api/le/dns-credentials', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, provider, fields }),
        });
        const d = (r.data && r.data.data) ? r.data.data : (r.data || {});
        if (!r.ok || d.status === 'ERROR') { alert('Save failed: ' + (d.message || r.detail || '')); return; }
        showToast('DNS credential saved', 'success');
        dnsCredResetForm();
        await dnsCredReloadList();
    } catch (e) { alert('Save failed: ' + e.message); }
}

async function deleteDnsCredential(name) {
    if (!confirm('Delete DNS credential "' + name + '"?')) return;
    try {
        const r = await _spokeFetch('/api/le/dns-credentials', {
            method: 'DELETE', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name }),
        });
        const d = (r.data && r.data.data) ? r.data.data : (r.data || {});
        if (!r.ok || d.status === 'ERROR') { alert('Delete failed: ' + (d.message || r.detail || '')); return; }
        showToast('DNS credential deleted', 'success');
        await dnsCredReloadList();
    } catch (e) { alert('Delete failed: ' + e.message); }
}

async function leRenewCert(domain) {
    if (!confirm(`Renew ${domain} now? This runs "certbot renew" on the le spoke and re-pushes new material to its targets.`)) return;
    try {
        const { ok, data, detail } = await _spokeFetch('/api/le/renew', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain }),
        });
        if (!ok) { alert('Renew failed: ' + (detail || '')); return; }
        const inner = (data && data.data) ? data.data : (data || {});
        const r = (inner.renewed || [])[0] || {};
        if (r.renewed) alert(`Renewed ${domain}.` + (r.error ? '' : ''));
        else alert(`Renewal did not complete for ${domain}: ${r.error || inner.message || 'unknown error'}`);
        await loadLEData();
    } catch (e) { alert('Renew failed: ' + e.message); }
}

async function leRenewAll() {
    const cnt = (window._leCerts || []).length;
    if (cnt === 0) { alert('No managed certificates to renew.'); return; }
    if (!confirm(`Renew all ${cnt} managed certificate(s) now? This runs "certbot renew" for each on the le spoke and re-pushes new material to their targets.`)) return;
    try {
        const { ok, data, detail } = await _spokeFetch('/api/le/renew', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({}),
        });
        if (!ok) { alert('Renew all failed: ' + (detail || '')); return; }
        const inner = (data && data.data) ? data.data : (data || {});
        const r = inner.renewed || [];
        const okN = r.filter(x => x.renewed).length;
        const failN = r.length - okN;
        let msg = `Renewed ${okN}/${r.length} certificate(s).`;
        if (failN > 0) msg += `\n${failN} failed:\n` + r.filter(x => !x.renewed).map(x => `  ${x.domain}: ${x.error || 'unknown'}`).join('\n');
        alert(msg);
        await loadLEData();
    } catch (e) { alert('Renew all failed: ' + e.message); }
}

async function leRevokeCert(domain) {
    const del = confirm(`Revoke ${domain}?\n\nThis revokes the certificate with Let's Encrypt and removes it from the managed list. The certbot cert material on the le spoke is deleted.\n\nNote: revocation does NOT un-install the cert from existing distribution targets — they keep serving it until it expires. Remove the targets first if you want them to stop serving it immediately.`);
    if (!del) return;
    try {
        const { ok, detail } = await _spokeFetch('/api/le/revoke', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain, delete: true }),
        });
        if (!ok) { alert('Revoke failed: ' + (detail || '')); return; }
        alert(`Revoked ${domain}.`);
        await loadLEData();
    } catch (e) { alert('Revoke failed: ' + e.message); }
}

function editDnsRecord(name, rtype) {
    const item = (window._dnsRecords || []).find(r => r.name === name && r.type === rtype);
    if (!item) { showToast('Row data not found — refresh and try again', 'error'); return; }
    showDnsRecordModal(item);
}

function showDnsRecordModal(editItem) {
    const editing = !!editItem;
    const val = v => (v == null ? '' : String(v).replace(/"/g, '&quot;'));
    const inputCls = 'w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500';
    const selectCls = inputCls;
    const typeOpts = ['A', 'AAAA', 'CNAME', 'PTR'].map(t =>
        `<option value="${t}"${editing && editItem.type === t ? ' selected' : ''}>${t}</option>`).join('');
    const modal = document.createElement('div');
    modal.id = 'dns-record-modal';
    modal.className = 'fixed inset-0 bg-black/50 flex items-center justify-center z-50';
    if (editing) { modal.dataset.editName = editItem.name; modal.dataset.editType = editItem.type; }
    modal.innerHTML = `<div class="bg-white rounded-xl shadow-xl w-full max-w-md p-6 space-y-4">
        <h3 class="text-lg font-bold text-[#263040]">${editing ? 'Edit' : 'Add'} DNS Record</h3>
        <div class="space-y-3">
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Name</label><input id="dns-r-name" value="${val(editItem?.name)}" class="${inputCls}" placeholder="host.example.com" ${editing ? 'readonly' : ''}></div>
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Type</label><select id="dns-r-type" class="${selectCls}" ${editing ? 'disabled' : ''}>${typeOpts}</select></div>
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Value</label><input id="dns-r-value" value="${val(editItem?.value)}" class="${inputCls}" placeholder="10.0.1.5"></div>
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">TTL</label><input id="dns-r-ttl" type="number" min="60" value="${val(editItem?.ttl) || 300}" class="${inputCls}"></div>
        </div>
        <div class="flex gap-2 pt-2">
            <button onclick="saveDnsRecord()" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-6 py-2 rounded-md text-sm font-bold">${editing ? 'Save Changes' : 'Add Record'}</button>
            <button onclick="document.getElementById('dns-record-modal').remove()" class="bg-slate-100 hover:bg-slate-200 text-slate-700 px-4 py-2 rounded-md text-sm">Cancel</button>
        </div>
    </div>`;
    document.body.appendChild(modal);
}

async function saveDnsRecord() {
    const modal = document.getElementById('dns-record-modal');
    const editing = modal && modal.dataset.editName;
    const get = id => document.getElementById(id)?.value?.trim() || '';
    const payload = {
        name: editing ? modal.dataset.editName : get('dns-r-name'),
        type: editing ? modal.dataset.editType : get('dns-r-type'),
        value: get('dns-r-value'),
        ttl: parseInt(get('dns-r-ttl')) || 300,
    };
    if (!payload.name || !payload.value) { alert('Name and Value are required'); return; }
    try {
        const { ok, data: d, detail } = await _spokeFetch('/api/dns/record' + _taTenantQuery(), {
            method: editing ? 'PUT' : 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        if (ok && d.status === 'SUCCESS') { modal.remove(); loadDNSData('Records'); }
        else alert('Error: ' + (detail || d?.message || 'Operation failed'));
    } catch (e) { alert('Error: ' + e.message); }
}

async function deleteDnsRecord(name, rtype) {
    if (!await showConfirmToast(`Delete DNS record ${name} (${rtype})?`)) return;
    try {
        const { ok, data: d, detail } = await _spokeFetch('/api/dns/record' + _taTenantQuery(), {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, type: rtype }),
        });
        if (ok && d.status === 'SUCCESS') loadDNSData('Records');
        else alert('Error: ' + (detail || d?.message || 'Delete failed'));
    } catch (e) { alert('Error: ' + e.message); }
}

// ─── DHCP (Kea) ──────────────────────────────────────────────────────────────

async function loadDHCPData(subMenu) {
    const container = document.getElementById('dhcp-content');
    if (!container) return;
    container.innerHTML = '<p class="text-sm text-slate-400 italic p-4">Loading…</p>';
    const addBtn = document.getElementById('dhcp-add-btn');
    if (addBtn) addBtn.classList.toggle('hidden', subMenu !== 'Reservations');

    const th = cols => `<thead class="bg-slate-50 text-xs text-slate-500 uppercase"><tr>${cols.map(c => `<th class="px-4 py-2 text-left font-medium">${c}</th>`).join('')}</tr></thead>`;
    const tw = html => `<div class="overflow-x-auto"><table class="w-full text-sm">${html}</table></div>`;
    const editIcon = `<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"></path></svg>`;
    const delIcon  = `<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>`;

    try {
        // ── Overview: Kea pool utilization + packet counters (OPNsense-grade) ─
        if (subMenu === 'Overview') {
            const { ok, data: d, detail } = await _spokeFetch('/api/dhcp/stats');
            if (!ok) { container.innerHTML = _spokeErrorBanner(detail, 'DHCP spoke not connected'); return; }
            if (d.status && d.status !== 'SUCCESS') {
                container.innerHTML = _spokeErrorBanner(d.message, 'Kea statistics unavailable'); return;
            }
            const g = d.global || {};
            const subnets = d.subnets || [];
            // Kea CA not running on this spoke → the spoke returns a SUCCESS
            // idle result (kea_running:false + note) instead of an ERROR, so
            // show a neutral info banner rather than the red "Error: Kea CA
            // unreachable …" the stats-ERROR path used to render. Empty stats
            // tiles + "No subnets configured." follow naturally below.
            const idleNote = (d.kea_running === false && d.note)
                ? `<div class="mb-4 p-3 rounded-lg bg-slate-50 border border-slate-200 text-sm text-slate-500">${escapeHtml(d.note)}</div>` : '';
            const syncLine = await _ddSyncStatusLine('dhcp');
            const tiles = [
                _ddTile('Pool Utilization', `${g.utilization_pct || 0}%`, `${(g.assigned_addresses || 0).toLocaleString()} / ${(g.total_addresses || 0).toLocaleString()} addresses`,
                        (g.utilization_pct || 0) >= 90 ? 'text-red-600' : (g.utilization_pct || 0) >= 70 ? 'text-amber-600' : 'text-emerald-600'),
                _ddTile('Assigned Leases', (g.assigned_addresses || 0).toLocaleString(), `${(g.declined_addresses || 0).toLocaleString()} declined`),
                _ddTile('DISCOVER / REQUEST', `${(g.pkt4_discover || 0).toLocaleString()} / ${(g.pkt4_request || 0).toLocaleString()}`, `${(g.pkt4_received || 0).toLocaleString()} received`),
                _ddTile('OFFER / ACK / NAK', `${(g.pkt4_offer_sent || 0).toLocaleString()} / ${(g.pkt4_ack_sent || 0).toLocaleString()} / ${(g.pkt4_nak_sent || 0).toLocaleString()}`),
            ].join('');
            const subnetRows = subnets.map(s => `
                <div class="py-2 border-b border-slate-100 last:border-0">
                    <div class="flex items-center justify-between mb-1">
                        <span class="font-mono text-sm font-medium text-slate-700">${escapeHtml(s.subnet || `subnet ${s.subnet_id}`)}</span>
                        <span class="text-xs text-slate-500">${(s.assigned_addresses || 0).toLocaleString()} / ${(s.total_addresses || 0).toLocaleString()}${s.declined_addresses ? ` · ${s.declined_addresses} declined` : ''}</span>
                    </div>
                    ${_ddBar(s.utilization_pct)}
                </div>`).join('');
            container.innerHTML = `
                ${idleNote}
                <div class="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-4">${tiles}</div>
                <div class="bg-white border border-slate-200 rounded-lg p-4">
                    <div class="text-sm font-semibold text-slate-700 mb-2">Scope Utilization</div>
                    ${subnetRows || '<p class="text-slate-400 italic text-sm">No subnets configured.</p>'}
                </div>
                ${syncLine}`;
            return;
        }

        if (subMenu === 'Subnets') {
            const { ok, data: d, detail } = await _spokeFetch('/api/dhcp/subnets');
            if (!ok) { container.innerHTML = _spokeErrorBanner(detail, 'DHCP spoke not connected'); return; }
            const subnets = d.subnets || [];
            const cols = ['ID', 'Subnet', 'Pools'];
            const rows = subnets.map(s => {
                const pools = (s.pools || []).map(p => p.pool || p).join(', ');
                return `<tr class="border-b border-slate-100 hover:bg-slate-50">
                    <td class="px-4 py-2 text-center text-xs">${escapeHtml(String(s.id))}</td>
                    <td class="px-4 py-2 font-mono font-medium">${escapeHtml(s.subnet)}</td>
                    <td class="px-4 py-2 font-mono text-xs">${escapeHtml(pools || '—')}</td>
                </tr>`;
            }).join('');
            container.innerHTML = subnets.length === 0
                ? '<p class="p-4 text-slate-400 italic text-sm">No subnets configured.</p>'
                : tw(th(cols) + `<tbody>${rows}</tbody>`);

        } else if (subMenu === 'Leases') {
            const { ok, data: d, detail } = await _spokeFetch('/api/dhcp/leases');
            if (!ok) { container.innerHTML = _spokeErrorBanner(detail, 'DHCP spoke not connected'); return; }
            const leases = d.leases || [];
            const cols = ['IP Address', 'MAC', 'Hostname', 'State', 'Valid Until'];
            const rows = leases.map(l => `<tr class="border-b border-slate-100 hover:bg-slate-50">
                <td class="px-4 py-2 font-mono font-medium">${escapeHtml(l['ip-address'] || l.ip || '—')}</td>
                <td class="px-4 py-2 font-mono text-xs">${escapeHtml(l['hw-address'] || l.mac || '—')}</td>
                <td class="px-4 py-2 text-xs">${escapeHtml(l.hostname || '—')}</td>
                <td class="px-4 py-2 text-xs">${escapeHtml(l.state || (l['state'] === 0 ? 'default' : (l['state'] === 1 ? 'declined' : 'expired')))}</td>
                <td class="px-4 py-2 font-mono text-xs">${escapeHtml(String(l['valid-lft'] || '—'))}</td>
            </tr>`).join('');
            container.innerHTML = leases.length === 0
                ? '<p class="p-4 text-slate-400 italic text-sm">No active leases.</p>'
                : tw(th(cols) + `<tbody>${rows}</tbody>`);

        } else if (subMenu === 'Reservations') {
            const { ok, data: d, detail } = await _spokeFetch('/api/dhcp/reservations');
            if (!ok) { container.innerHTML = _spokeErrorBanner(detail, 'DHCP spoke not connected'); if (addBtn) addBtn.classList.add('hidden'); return; }
            const res = d.reservations || [];
            window._dhcpReservations = res;
            const cols = ['IP Address', 'MAC', 'Hostname', 'Subnet', ''];
            const rows = res.map(r => {
                const eIp = escJsAttr(r.ip);
                return `<tr class="border-b border-slate-100 hover:bg-slate-50">
                    <td class="px-4 py-2 font-mono font-medium">${escapeHtml(r.ip)}</td>
                    <td class="px-4 py-2 font-mono text-xs">${escapeHtml(r.mac)}</td>
                    <td class="px-4 py-2 text-xs">${escapeHtml(r.hostname || '—')}</td>
                    <td class="px-4 py-2 font-mono text-xs">${escapeHtml(r.subnet || '—')}</td>
                    <td class="px-4 py-2 whitespace-nowrap">
                        <button onclick="editDhcpReservation('${eIp}')" title="Edit" class="p-1 text-slate-400 hover:text-blue-600 transition-colors">${editIcon}</button>
                        <button onclick="deleteDhcpReservation('${eIp}')" title="Delete" class="p-1 text-slate-300 hover:text-red-500 transition-colors">${delIcon}</button>
                    </td>
                </tr>`;
            }).join('');
            container.innerHTML = res.length === 0
                ? '<p class="p-4 text-slate-400 italic text-sm">No static reservations configured.</p>'
                : tw(th(cols) + `<tbody>${rows}</tbody>`);
        }
    } catch (err) {
        container.innerHTML = `<p class="p-4 text-red-500 text-sm">Error: ${err.message}</p>`;
    }
}

async function _loadDhcpSubnetOptions(selId) {
    const sel = document.getElementById(selId);
    if (!sel) return;
    sel.innerHTML = '<option value="">Loading…</option>';
    try {
        const { ok, data: d, detail } = await _spokeFetch('/api/dhcp/subnets');
        const subnets = ok ? (d.subnets || []) : [];
        sel.innerHTML = subnets.length
            ? subnets.map(s => `<option value="${escapeHtml(String(s.id))}">${escapeHtml(String(s.id))} — ${escapeHtml(s.subnet)}</option>`).join('')
            : `<option value="">${ok ? 'No subnets configured' : (detail || 'Could not load subnets')}</option>`;
    } catch (err) {
        console.error('_loadDhcpSubnetOptions: could not load subnets', err);
        sel.innerHTML = '<option value="">Could not load subnets</option>';
    }
}

function editDhcpReservation(ip) {
    const item = (window._dhcpReservations || []).find(r => r.ip === ip);
    if (!item) { showToast('Row data not found — refresh and try again', 'error'); return; }
    showDhcpReservationModal(item);
}

function showDhcpReservationModal(editItem) {
    const editing = !!editItem;
    const val = v => (v == null ? '' : String(v).replace(/"/g, '&quot;'));
    const inputCls = 'w-full bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500';
    const modal = document.createElement('div');
    modal.id = 'dhcp-res-modal';
    modal.className = 'fixed inset-0 bg-black/50 flex items-center justify-center z-50';
    if (editing) modal.dataset.editIp = editItem.ip;
    modal.innerHTML = `<div class="bg-white rounded-xl shadow-xl w-full max-w-md p-6 space-y-4">
        <h3 class="text-lg font-bold text-[#263040]">${editing ? 'Edit' : 'Add'} DHCP Reservation</h3>
        <div class="space-y-3">
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Subnet</label><select id="dhcp-res-subnet" class="${inputCls}"><option value="">Loading…</option></select></div>
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">IP Address</label><input id="dhcp-res-ip" value="${val(editItem?.ip)}" class="${inputCls}" placeholder="10.0.0.50"></div>
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">MAC Address</label><input id="dhcp-res-mac" value="${val(editItem?.mac)}" class="${inputCls}" placeholder="aa:bb:cc:dd:ee:ff"></div>
            <div class="space-y-1"><label class="text-xs text-slate-500 font-bold uppercase">Hostname (optional)</label><input id="dhcp-res-host" value="${val(editItem?.hostname)}" class="${inputCls}" placeholder="printer-01"></div>
        </div>
        <div class="flex gap-2 pt-2">
            <button onclick="saveDhcpReservation()" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-6 py-2 rounded-md text-sm font-bold">${editing ? 'Save Changes' : 'Add Reservation'}</button>
            <button onclick="document.getElementById('dhcp-res-modal').remove()" class="bg-slate-100 hover:bg-slate-200 text-slate-700 px-4 py-2 rounded-md text-sm">Cancel</button>
        </div>
    </div>`;
    document.body.appendChild(modal);
    _loadDhcpSubnetOptions('dhcp-res-subnet').then(() => {
        if (editing && editItem.subnet_id != null) {
            const sel = document.getElementById('dhcp-res-subnet');
            if (sel) sel.value = String(editItem.subnet_id);
        }
    });
}

async function saveDhcpReservation() {
    const modal = document.getElementById('dhcp-res-modal');
    const editing = modal && modal.dataset.editIp;
    const get = id => document.getElementById(id)?.value?.trim() || '';
    const payload = {
        subnet_id: get('dhcp-res-subnet'),
        ip: get('dhcp-res-ip'),
        mac: get('dhcp-res-mac'),
        hostname: get('dhcp-res-host'),
    };
    if (!payload.subnet_id || !payload.ip || !payload.mac) {
        alert('Subnet, IP, and MAC are required');
        return;
    }
    if (editing) payload.old_ip = modal.dataset.editIp;
    try {
        const { ok, data: d, detail } = await _spokeFetch('/api/dhcp/reservation' + _taTenantQuery(), {
            method: editing ? 'PUT' : 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        if (ok && d.status === 'SUCCESS') { modal.remove(); loadDHCPData('Reservations'); }
        else alert('Error: ' + (detail || d?.message || 'Operation failed'));
    } catch (e) { alert('Error: ' + e.message); }
}

async function deleteDhcpReservation(ip) {
    if (!await showConfirmToast(`Delete reservation for ${ip}?`)) return;
    try {
        const { ok, data: d, detail } = await _spokeFetch('/api/dhcp/reservation' + _taTenantQuery(), {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip }),
        });
        if (ok && d.status === 'SUCCESS') loadDHCPData('Reservations');
        else alert('Error: ' + (detail || d?.message || 'Delete failed'));
    } catch (e) { alert('Error: ' + e.message); }
}

// ─── CPPM / NAC ──────────────────────────────────────────────────────────────

// Shared 403 hint rendered under a ClearPass API error card. CPPM requires an
// OAuth2 API Client; a 403 almost always means one isn't configured or the
// credentials in Setup → Security/NAC don't match. Used by loadCPPMData() in
// both the sessions branch (NAC Status / Access Tracker) and the devices
// branch (My Devices / Unknown Devices).
// Routes: GET /api/cppm/sessions, /api/cppm/devices, /api/cppm/unknown-devices
// — see core/src/api.py get_cppm_sessions / get_cppm_devices.
function _cppm403Hint(status) {
    return status === 403
        ? '<p class="mt-3 text-xs text-amber-600">ClearPass returned 403 — check that an OAuth2 API Client is configured in CPPM and that the credentials in Setup → Security/NAC match.</p>'
        : '';
}

async function loadCPPMNACStatus() {
    try {
        const r = await fetch('/api/cppm/nac-status');
        if (r.ok) {
            const d = await r.json();
            const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v ?? '—'; };
            set('nac-sessions', d.active_sessions);
            set('nac-total', d.total_devices);
            set('nac-known', d.known_devices);
            set('nac-unknown', d.unknown_devices);
        }
    } catch (err) { console.error('loadCPPMNACStatus: nac-status fetch failed', err); }
    loadCPPMData('NAC Status');
}

// _renderCppmSessions() — the Access Tracker / NAC Status branch of
// loadCPPMData. Extracted from the loader; the fetch lives here, the loading
// placeholder + th/tableWrap helpers stay in the caller. Output HTML preserved.
async function _renderCppmSessions(container, subMenu, th, tableWrap) {
    const limit = window._cppmSessionLimit || 200;
    const tparam = currentTenant && currentTenant !== 'default' ? `&tenant=${encodeURIComponent(currentTenant)}` : '';
    const r = await fetch(`/api/cppm/sessions?limit=${limit}${tparam}`);
    if (!r.ok) {
        const e = await r.json().catch(() => ({}));
        container.innerHTML = `<div class="p-6 text-center">
            <p class="text-red-500 font-medium text-sm mb-1">ClearPass API Error (${r.status})</p>
            <p class="text-xs text-slate-500 font-mono">${e.detail || r.statusText}</p>
            ${_cppm403Hint(r.status)}
        </div>`;
        return;
    }
    const d = await r.json();
    // Server scopes by the selected tenant's subnets (incl. admins); no
    // client re-filter (its session-tenant prefixes are wrong once a
    // tenant is switched).
    const sessions = d.sessions || [];
    const cols = ['Username', 'MAC / Station', 'IP', 'Role', 'NAS', 'Port', 'Service', 'Start Time', 'State'];
    const rows = sessions.map(s => `<tr class="border-b border-slate-100 hover:bg-slate-50">
        <td class="px-4 py-2 font-medium">${s.username || '—'}</td>
        <td class="px-4 py-2 font-mono text-xs">${s.calling_station || s.mac || '—'}</td>
        <td class="px-4 py-2 font-mono text-xs">${s.ip || '—'}</td>
        <td class="px-4 py-2">${s.role || '—'}</td>
        <td class="px-4 py-2 text-xs">${s.nas_name || '—'}</td>
        <td class="px-4 py-2 text-xs font-mono" title="${s.nas_port_type || ''}">${s.nas_port || '—'}</td>
        <td class="px-4 py-2 text-xs">${s.service || '—'}</td>
        <td class="px-4 py-2 text-xs">${fmtSessionStart(s.start_time)}</td>
        <td class="px-4 py-2"><span class="px-2 py-0.5 rounded-full text-xs font-medium ${s.state === 'active' ? 'bg-green-100 text-green-700' : 'bg-slate-100 text-slate-500'}">${s.state || '—'}</span></td>
    </tr>`).join('');
    const sessRefreshBtn = !isAdmin() ? `<button onclick="refreshModuleCache('cppm_sessions').then(()=>loadCPPMData('${subMenu}'))"
        class="text-xs text-slate-400 hover:text-slate-600 flex items-center gap-1">
        <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
        Refresh</button>` : '';
    const limitSel = `<select onchange="window._cppmSessionLimit=+this.value; loadCPPMData('${subMenu}')"
        class="text-xs border border-slate-200 rounded px-2 py-0.5 text-slate-500 bg-white">
        ${[50,100,200,500,1000].map(n => `<option value="${n}"${n===limit?' selected':''}>${n} records</option>`).join('')}
    </select>`;
    container.innerHTML = `<div class="flex justify-between items-center mb-1 px-1">
        <h3 class="text-base font-semibold text-[#263040]">Access Tracker <span class="text-xs text-slate-400 font-normal">(${sessions.length} of ${d.total ?? sessions.length})</span> ${helpIcon('cppm', null, 'NAC help')}</h3>
        <div class="flex items-center gap-2">${limitSel}${sessRefreshBtn}</div>
    </div>` + tableWrap(th(cols) + `<tbody>${rows || '<tr><td colspan="9" class="px-4 py-6 text-center text-slate-400">No active sessions</td></tr>'}</tbody>`);
}

// _renderCppmDevices() — the My Devices / Unknown Devices branch of
// loadCPPMData. Extracted from the loader; fetch + row click wiring live here.
// Output HTML preserved.
async function _renderCppmDevices(container, subMenu, th, tableWrap) {
    const isUnknown = subMenu === 'Unknown Devices';
    const tparam = currentTenant && currentTenant !== 'default' ? `?tenant=${encodeURIComponent(currentTenant)}` : '';
    const r = await fetch(isUnknown ? `/api/cppm/unknown-devices${tparam}` : `/api/cppm/devices${tparam}`);
    if (!r.ok) {
        const e = await r.json().catch(() => ({}));
        container.innerHTML = `<div class="p-6 text-center">
            <p class="text-red-500 font-medium text-sm mb-1">ClearPass API Error (${r.status})</p>
            <p class="text-xs text-slate-500 font-mono">${e.detail || r.statusText}</p>
            ${_cppm403Hint(r.status)}
        </div>`;
        return;
    }
    const d = await r.json();
    const allDevices = d.devices || d.items || (Array.isArray(d) ? d : []);
    // Server scopes by the selected tenant (incl. admins); no client
    // re-filter — its session-tenant prefixes are wrong once a tenant
    // is switched. 'Unknown Devices' are untagged endpoints (assigned to
    // no tenant), subnet-scoped to the selected tenant's network.
    const devices = allDevices;
    const cols = ['MAC Address', 'Status', 'Hostname', 'IP', 'Vendor', 'OS', 'Type', 'Attributes'];
    const statusBadge = s => {
        const cls = s === 'Known' ? 'bg-green-100 text-green-700' : s === 'Unknown' ? 'bg-amber-100 text-amber-700' : 'bg-red-100 text-red-700';
        return `<span class="px-2 py-0.5 rounded-full text-xs font-medium ${cls}">${s || '—'}</span>`;
    };
    // Compact chip list of an endpoint's attributes (key: value). Pinned
    // tenant tags render first so the tenant is visible at a glance; the
    // rest follow. Capped with a scroll so profiler-heavy endpoints don't
    // blow out the row height.
    const esc = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
    // Tenant identity is NOT shown in the list — the list is filtered
    // server-side by the logged-in user's tenant ID (/api/cppm/devices),
    // so showing the tenant tags here would be noise for a user (only
    // ever their own tenant) and an unwanted label for admins. Other
    // endpoint attributes still render as chips.
    const HIDDEN_ATTRS = new Set(['Tenant', 'Tenant_Slug', 'NetBox_Tenant_Slug', 'NetBox_Tenant_Name', 'NetBox_Tenant_ID']);
    const attrChips = attrs => {
        const entries = Object.entries(attrs || {})
            .filter(([k, v]) => v != null && v !== '' && !HIDDEN_ATTRS.has(k))
            .sort((a, b) => a[0].localeCompare(b[0]));
        if (!entries.length) return '<span class="text-slate-300">—</span>';
        return `<div class="flex flex-wrap gap-1 max-h-16 overflow-y-auto pr-1">${entries.map(([k, v]) =>
            `<span class="text-[10px] px-1.5 py-0.5 rounded bg-slate-100 text-slate-600 font-mono whitespace-nowrap" title="${esc(k)}: ${esc(v)}"><span class="text-slate-400">${esc(k)}</span>:${esc(v)}</span>`
        ).join('')}</div>`;
    };
    window._cppmDeviceMap = Object.fromEntries(devices.map(d => [d.mac, d]));
    const rows = devices.map(d => `<tr class="border-b border-slate-100 hover:bg-slate-50 cursor-pointer cppm-dev-row" data-mac="${d.mac || ''}">
        <td class="px-4 py-2 font-mono text-xs text-[#01A982] hover:underline">${d.mac || '—'}</td>
        <td class="px-4 py-2">${statusBadge(d.status)}</td>
        <td class="px-4 py-2 text-xs">${d.hostname || '—'}</td>
        <td class="px-4 py-2 font-mono text-xs">${d.ip || '—'}</td>
        <td class="px-4 py-2 text-xs">${d.device_vendor || '—'}</td>
        <td class="px-4 py-2 text-xs">${d.device_os || '—'}</td>
        <td class="px-4 py-2 text-xs">${d.device_type || '—'}</td>
        <td class="px-4 py-2">${attrChips(d.attributes)}</td>
    </tr>`).join('');
    const devRefreshBtn = !isAdmin() ? `<button id="cppm-dev-refresh"
        class="text-xs text-slate-400 hover:text-slate-600 flex items-center gap-1">
        <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
        Refresh</button>` : '';
    const devTitle = isUnknown ? 'Unknown Devices' : 'My Devices';
    container.innerHTML = `<div class="flex justify-between items-center mb-1 px-1">
        <h3 class="text-base font-semibold text-[#263040]">${devTitle} <span class="text-xs text-slate-400 font-normal">(${devices.length} devices)</span> ${helpIcon('cppm', null, 'NAC help')}</h3>
        ${devRefreshBtn}
    </div>` + tableWrap(th(cols) + `<tbody>${rows || '<tr><td colspan="8" class="px-4 py-6 text-center text-slate-400">No devices found</td></tr>'}</tbody>`);
    document.getElementById('cppm-dev-refresh')?.addEventListener('click', () => refreshModuleCache('cppm_devices').then(() => loadCPPMData(subMenu)));
    container.querySelectorAll('.cppm-dev-row').forEach(tr => {
        tr.addEventListener('click', () => showCPPMDeviceDetail(tr.dataset.mac));
    });
}

async function loadCPPMData(subMenu) {
    const container = document.getElementById('cppm-content');
    if (!container) return;
    container.innerHTML = '<p class="text-sm text-slate-400 italic p-4">Loading…</p>';

    const th = cols => `<thead class="bg-slate-50 text-xs text-slate-500 uppercase"><tr>${cols.map(c => `<th class="px-4 py-2 text-left font-medium">${c}</th>`).join('')}</tr></thead>`;
    const tableWrap = html => `<div class="overflow-x-auto"><table class="w-full text-sm">${html}</table></div>`;

    try {
        if (subMenu === 'NAC Status' || subMenu === 'Access Tracker') {
            await _renderCppmSessions(container, subMenu, th, tableWrap);
        } else if (subMenu === 'My Devices' || subMenu === 'Unknown Devices') {
            await _renderCppmDevices(container, subMenu, th, tableWrap);
        }
    } catch (err) {
        container.innerHTML = `<p class="p-4 text-red-500 text-sm">Error loading ${subMenu}: ${err.message}</p>`;
    }
}

async function deleteOpnsenseItem(fwId, subMenu, itemId) {
    if (!await showConfirmToast(`Delete this ${subMenu.replace(/s$/, '')}?`)) return;
    let url = '';
    if (subMenu === 'Firewall Rules') url = `/api/firewall/${fwId}/rules/${encodeURIComponent(itemId)}`;
    else if (subMenu === 'NAT Policies') url = `/api/firewall/${fwId}/nat/${encodeURIComponent(itemId)}`;
    else if (subMenu === 'DNS Records') url = `/api/firewall/${fwId}/dns/${encodeURIComponent(itemId)}`;
    else if (subMenu === 'Aliases') url = `/api/firewall/${fwId}/aliases/${encodeURIComponent(itemId)}`;
    else return;
    try {
        const r = await fetch(url + _taTenantQuery(), { method: 'DELETE' });
        if (!r.ok) { const e = await r.json(); throw new Error(e.detail || r.statusText); }
        loadOpnsenseManagement();
    } catch (e) {
        alert('Error deleting: ' + e.message);
    }
}

function showOpnsenseAddModal(subMenu) {
    const existing = document.getElementById('opn-add-modal');
    if (existing) existing.remove();

    const input = 'w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500 text-slate-800';
    const label = 'text-xs text-slate-500 uppercase font-bold';

    // Target firewall: auto-select when only one is configured, otherwise show a
    // picker as the first field. submitOpnsenseAdd reads #add-opn-fw (or falls
    // back to the single configured firewall).
    const fwPicker = _opnFirewalls.length > 1
        ? `<div class="space-y-1"><label class="${label}">Firewall</label><select id="add-opn-fw" class="${input}">${_opnFirewalls.map(fw => `<option value="${fw.id}">${fw.name || fw.id}</option>`).join('')}</select></div>`
        : '';

    let fields = '';
    let submitFn = '';

    if (subMenu === 'Firewall Rules') {
        fields = `
            <div class="grid grid-cols-2 gap-4">
                <div class="space-y-1"><label class="${label}">Interface</label><input type="text" id="add-opn-iface" placeholder="lan" class="${input}"></div>
                <div class="space-y-1"><label class="${label}">Action</label><select id="add-opn-action" class="${input}"><option value="pass">Pass</option><option value="block">Block</option><option value="reject">Reject</option></select></div>
                <div class="space-y-1"><label class="${label}">Protocol</label><select id="add-opn-proto" class="${input}"><option>TCP</option><option>UDP</option><option>TCP/UDP</option><option>ICMP</option><option>any</option></select></div>
                <div class="space-y-1"><label class="${label}">Source</label><input type="text" id="add-opn-source" placeholder="any" class="${input}"></div>
                <div class="space-y-1"><label class="${label}">Destination</label><input type="text" id="add-opn-dest" placeholder="any" class="${input}"></div>
                <div class="space-y-1"><label class="${label}">Dest Port</label><input type="text" id="add-opn-dport" placeholder="any" class="${input}"></div>
            </div>
            <div class="space-y-1"><label class="${label}">Description</label><input type="text" id="add-opn-desc" placeholder="Rule description" class="${input}"></div>`;
        submitFn = `submitOpnsenseAdd('${subMenu}')`;
    } else if (subMenu === 'Aliases') {
        fields = `
            <div class="space-y-1"><label class="${label}">Name</label><input type="text" id="add-opn-name" placeholder="my_alias" class="${input}"></div>
            <div class="space-y-1"><label class="${label}">Type</label><select id="add-opn-type" class="${input}"><option value="host">Host</option><option value="network">Network</option><option value="port">Port</option><option value="url">URL</option></select></div>
            <div class="space-y-1"><label class="${label}">Content (comma-separated)</label><input type="text" id="add-opn-content" placeholder="192.168.1.10, 192.168.1.20" class="${input}"></div>
            <div class="space-y-1"><label class="${label}">Category</label><input type="text" id="add-opn-category" placeholder="tenant name (optional, attributes this alias to a tenant)" class="${input}"></div>
            <div class="space-y-1"><label class="${label}">Description</label><input type="text" id="add-opn-desc" placeholder="Optional description" class="${input}"></div>`;
        submitFn = `submitOpnsenseAdd('${subMenu}')`;
    } else if (subMenu === 'NAT Policies') {
        fields = `
            <div class="grid grid-cols-2 gap-4">
                <div class="space-y-1"><label class="${label}">NAT Type</label><select id="add-opn-nat-type" class="${input}"><option value="d_nat">Destination NAT (Port Forward)</option><option value="source_nat">Source NAT (Outbound)</option><option value="nat_1to1">1:1 NAT</option></select></div>
                <div class="space-y-1"><label class="${label}">Protocol</label><select id="add-opn-proto" class="${input}"><option>TCP</option><option>UDP</option><option>TCP/UDP</option><option>any</option></select></div>
                <div class="space-y-1"><label class="${label}">External IP</label><input type="text" id="add-opn-ext-ip" placeholder="any" class="${input}"></div>
                <div class="space-y-1"><label class="${label}">External Port</label><input type="text" id="add-opn-ext-port" placeholder="80" class="${input}"></div>
                <div class="space-y-1"><label class="${label}">Internal IP</label><input type="text" id="add-opn-int-ip" placeholder="192.168.1.100" class="${input}"></div>
                <div class="space-y-1"><label class="${label}">Internal Port</label><input type="text" id="add-opn-int-port" placeholder="80" class="${input}"></div>
            </div>
            <div class="space-y-1"><label class="${label}">Description</label><input type="text" id="add-opn-desc" placeholder="NAT rule description" class="${input}"></div>`;
        submitFn = `submitOpnsenseAdd('${subMenu}')`;
    } else if (subMenu === 'DNS Records') {
        fields = `
            <div class="grid grid-cols-2 gap-4">
                <div class="space-y-1"><label class="${label}">Hostname</label><input type="text" id="add-opn-hostname" placeholder="myserver" class="${input}"></div>
                <div class="space-y-1"><label class="${label}">Domain</label><input type="text" id="add-opn-domain" placeholder="example.com" class="${input}"></div>
                <div class="space-y-1 col-span-2"><label class="${label}">IP Address</label><input type="text" id="add-opn-ip" placeholder="192.168.1.100" class="${input}"></div>
            </div>
            <div class="space-y-1"><label class="${label}">Description</label><input type="text" id="add-opn-desc" placeholder="Optional description" class="${input}"></div>`;
        submitFn = `submitOpnsenseAdd('${subMenu}')`;
    }

    const modal = document.createElement('div');
    modal.id = 'opn-add-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm';
    modal.innerHTML = `
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-lg overflow-hidden">
            <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50">
                <h3 class="text-lg font-bold text-[#263040]">Add ${subMenu.replace(/s$/, '')}</h3>
                <button onclick="document.getElementById('opn-add-modal').remove()" class="text-slate-400 hover:text-slate-600"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg></button>
            </div>
            <div class="p-6 space-y-4">${fwPicker}${fields}</div>
            <div class="px-6 py-4 bg-slate-50 border-t border-slate-200 flex justify-end gap-3">
                <button onclick="document.getElementById('opn-add-modal').remove()" class="px-4 py-2 text-sm font-medium text-slate-600 hover:text-slate-800">Cancel</button>
                <button onclick="${submitFn}" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm">Add</button>
            </div>
        </div>`;
    document.body.appendChild(modal);
}

async function submitOpnsenseAdd(subMenu) {
    const g = id => { const el = document.getElementById(id); return el ? el.value.trim() : ''; };
    const btn = document.querySelector('#opn-add-modal button:last-child');
    if (btn) { btn.disabled = true; btn.textContent = 'Adding…'; }
    const fwSel = document.getElementById('add-opn-fw');
    const fwId = (fwSel && fwSel.value) || (_opnFirewalls[0] && _opnFirewalls[0].id);
    if (!fwId) { alert('No firewall selected.'); return; }
    let url = '', body = {};

    try {
        if (subMenu === 'Firewall Rules') {
            url = `/api/firewall/${fwId}/rules`;
            body = { rule: {
                interface: g('add-opn-iface') || 'lan',
                action: g('add-opn-action') || 'pass',
                protocol: g('add-opn-proto') || 'any',
                source_net: g('add-opn-source') || 'any',
                destination_net: g('add-opn-dest') || 'any',
                destination_port: g('add-opn-dport') || 'any',
                description: g('add-opn-desc'),
                enabled: '1',
            }};
        } else if (subMenu === 'Aliases') {
            url = `/api/firewall/${fwId}/aliases`;
            body = { name: g('add-opn-name'), type: g('add-opn-type'), content: g('add-opn-content'), description: g('add-opn-desc'), category: g('add-opn-category') };
            if (!body.name) { alert('Name is required.'); return; }
        } else if (subMenu === 'NAT Policies') {
            url = `/api/firewall/${fwId}/nat`;
            body = {
                nat_type: g('add-opn-nat-type') || 'd_nat',
                rule: {
                    protocol: g('add-opn-proto'),
                    'destination.network': g('add-opn-ext-ip') || 'any',
                    destination_port: g('add-opn-ext-port'),
                    target: g('add-opn-int-ip'),
                    'local-port': g('add-opn-int-port'),
                    descr: g('add-opn-desc'),
                    enabled: '1',
                }
            };
        } else if (subMenu === 'DNS Records') {
            url = `/api/firewall/${fwId}/dns`;
            body = { hostname: g('add-opn-hostname'), domain: g('add-opn-domain'), ip: g('add-opn-ip'), description: g('add-opn-desc') };
            if (!body.hostname || !body.ip) { alert('Hostname and IP are required.'); return; }
        } else return;

        const r = await fetch(url + _taTenantQuery(), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        if (!r.ok) { const e = await r.json(); throw new Error(e.detail || r.statusText); }
        document.getElementById('opn-add-modal')?.remove();
        loadOpnsenseManagement();
    } catch (e) {
        alert('Error: ' + e.message);
    }
}

function showOpnsenseEditModal(fwId, subMenu, itemIdx) {
    const item = _opnCurrentItems[itemIdx];
    if (!item) { alert('Item data not found — try refreshing the page.'); return; }
    const itemId = item.id || item.uuid || '';

    const existing = document.getElementById('opn-add-modal');
    if (existing) existing.remove();

    const input = 'w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500 text-slate-800';
    const label = 'text-xs text-slate-500 uppercase font-bold';
    const v = k => (item[k] !== undefined && item[k] !== null ? String(item[k]) : '').replace(/"/g, '&quot;');

    let fields = '';
    if (subMenu === 'Firewall Rules') {
        fields = `
            <div class="grid grid-cols-2 gap-4">
                <div class="space-y-1"><label class="${label}">Interface</label><input type="text" id="add-opn-iface" value="${v('interface')}" class="${input}"></div>
                <div class="space-y-1"><label class="${label}">Action</label><select id="add-opn-action" class="${input}"><option value="pass" ${item.action==='pass'?'selected':''}>Pass</option><option value="block" ${item.action==='block'?'selected':''}>Block</option><option value="reject" ${item.action==='reject'?'selected':''}>Reject</option></select></div>
                <div class="space-y-1"><label class="${label}">Protocol</label><select id="add-opn-proto" class="${input}"><option ${item.protocol==='TCP'?'selected':''}>TCP</option><option ${item.protocol==='UDP'?'selected':''}>UDP</option><option ${item.protocol==='TCP/UDP'?'selected':''}>TCP/UDP</option><option ${item.protocol==='ICMP'?'selected':''}>ICMP</option><option ${item.protocol==='any'?'selected':''}>any</option></select></div>
                <div class="space-y-1"><label class="${label}">Source</label><input type="text" id="add-opn-source" value="${v('source')}" class="${input}"></div>
                <div class="space-y-1"><label class="${label}">Destination</label><input type="text" id="add-opn-dest" value="${v('destination')}" class="${input}"></div>
                <div class="space-y-1"><label class="${label}">Dest Port</label><input type="text" id="add-opn-dport" value="${v('destination_port')}" class="${input}"></div>
            </div>
            <div class="space-y-1"><label class="${label}">Description</label><input type="text" id="add-opn-desc" value="${v('description')}" class="${input}"></div>`;
    } else if (subMenu === 'Aliases') {
        fields = `
            <div class="space-y-1"><label class="${label}">Name</label><input type="text" id="add-opn-name" value="${v('name')}" class="${input}"></div>
            <div class="space-y-1"><label class="${label}">Type</label><select id="add-opn-type" class="${input}"><option value="host" ${item.type==='host'?'selected':''}>Host</option><option value="network" ${item.type==='network'?'selected':''}>Network</option><option value="port" ${item.type==='port'?'selected':''}>Port</option><option value="url" ${item.type==='url'?'selected':''}>URL</option></select></div>
            <div class="space-y-1"><label class="${label}">Content (comma-separated)</label><input type="text" id="add-opn-content" value="${v('content')}" class="${input}"></div>
            <div class="space-y-1"><label class="${label}">Category</label><input type="text" id="add-opn-category" value="${v('category')}" class="${input}"></div>
            <div class="space-y-1"><label class="${label}">Description</label><input type="text" id="add-opn-desc" value="${v('description')}" class="${input}"></div>`;
    } else if (subMenu === 'NAT Policies') {
        const natType = item.type || 'd_nat';
        fields = `
            <div class="grid grid-cols-2 gap-4">
                <div class="space-y-1"><label class="${label}">NAT Type</label><select id="add-opn-nat-type" class="${input}"><option value="d_nat" ${natType==='d_nat'?'selected':''}>Destination NAT (Port Forward)</option><option value="source_nat" ${natType==='source_nat'?'selected':''}>Source NAT (Outbound)</option><option value="nat_1to1" ${natType==='nat_1to1'?'selected':''}>1:1 NAT</option></select></div>
                <div class="space-y-1"><label class="${label}">Protocol</label><select id="add-opn-proto" class="${input}"><option ${item.protocol==='TCP'?'selected':''}>TCP</option><option ${item.protocol==='UDP'?'selected':''}>UDP</option><option ${item.protocol==='TCP/UDP'?'selected':''}>TCP/UDP</option><option ${item.protocol==='any'?'selected':''}>any</option></select></div>
                <div class="space-y-1"><label class="${label}">External IP</label><input type="text" id="add-opn-ext-ip" value="${v('external_ip')}" class="${input}"></div>
                <div class="space-y-1"><label class="${label}">External Port</label><input type="text" id="add-opn-ext-port" value="${v('external_port')}" class="${input}"></div>
                <div class="space-y-1"><label class="${label}">Internal IP</label><input type="text" id="add-opn-int-ip" value="${v('internal_ip')}" class="${input}"></div>
                <div class="space-y-1"><label class="${label}">Internal Port</label><input type="text" id="add-opn-int-port" value="${v('internal_port')}" class="${input}"></div>
            </div>
            <div class="space-y-1"><label class="${label}">Description</label><input type="text" id="add-opn-desc" value="${v('description')}" class="${input}"></div>`;
    } else if (subMenu === 'DNS Records') {
        const hostParts = (item.hostname || '').split('.');
        const hostname = hostParts[0] || '';
        const domain = item.domain || (hostParts.length > 1 ? hostParts.slice(1).join('.') : '');
        fields = `
            <div class="grid grid-cols-2 gap-4">
                <div class="space-y-1"><label class="${label}">Hostname</label><input type="text" id="add-opn-hostname" value="${hostname.replace(/"/g,'&quot;')}" class="${input}"></div>
                <div class="space-y-1"><label class="${label}">Domain</label><input type="text" id="add-opn-domain" value="${domain.replace(/"/g,'&quot;')}" class="${input}"></div>
                <div class="space-y-1 col-span-2"><label class="${label}">IP Address</label><input type="text" id="add-opn-ip" value="${v('ip')}" class="${input}"></div>
            </div>
            <div class="space-y-1"><label class="${label}">Description</label><input type="text" id="add-opn-desc" value="${v('description')}" class="${input}"></div>`;
    } else return;

    const modal = document.createElement('div');
    modal.id = 'opn-add-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm';
    modal.innerHTML = `
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-lg overflow-hidden">
            <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50">
                <h3 class="text-lg font-bold text-[#263040]">Edit ${subMenu.replace(/s$/, '')}</h3>
                <button onclick="document.getElementById('opn-add-modal').remove()" class="text-slate-400 hover:text-slate-600"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg></button>
            </div>
            <div class="p-6 space-y-4">${fields}</div>
            <div class="px-6 py-4 bg-slate-50 border-t border-slate-200 flex justify-end gap-3">
                <button onclick="document.getElementById('opn-add-modal').remove()" class="px-4 py-2 text-sm font-medium text-slate-600 hover:text-slate-800">Cancel</button>
                <button onclick="submitOpnsenseEdit('${fwId}','${subMenu}','${itemId.replace(/'/g,"\\'")}')" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm">Save</button>
            </div>
        </div>`;
    document.body.appendChild(modal);
}

async function submitOpnsenseEdit(fwId, subMenu, itemId) {
    const g = id => { const el = document.getElementById(id); return el ? el.value.trim() : ''; };
    const btn = document.querySelector('#opn-add-modal button:last-child');
    if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
    let url = '', body = {};

    try {
        const encodedId = encodeURIComponent(itemId);
        if (subMenu === 'Firewall Rules') {
            url = `/api/firewall/${fwId}/rules/${encodedId}`;
            body = { rule: {
                interface: g('add-opn-iface') || 'lan',
                action: g('add-opn-action') || 'pass',
                protocol: g('add-opn-proto') || 'any',
                source_net: g('add-opn-source') || 'any',
                destination_net: g('add-opn-dest') || 'any',
                destination_port: g('add-opn-dport') || 'any',
                description: g('add-opn-desc'),
                enabled: '1',
            }};
        } else if (subMenu === 'Aliases') {
            url = `/api/firewall/${fwId}/aliases/${encodedId}`;
            body = { name: g('add-opn-name'), type: g('add-opn-type'), content: g('add-opn-content'), description: g('add-opn-desc'), category: g('add-opn-category') };
            if (!body.name) { alert('Name is required.'); return; }
        } else if (subMenu === 'NAT Policies') {
            url = `/api/firewall/${fwId}/nat/${encodedId}`;
            body = {
                nat_type: g('add-opn-nat-type') || 'd_nat',
                rule: {
                    protocol: g('add-opn-proto'),
                    'destination.network': g('add-opn-ext-ip') || 'any',
                    destination_port: g('add-opn-ext-port'),
                    target: g('add-opn-int-ip'),
                    'local-port': g('add-opn-int-port'),
                    descr: g('add-opn-desc'),
                    enabled: '1',
                }
            };
        } else if (subMenu === 'DNS Records') {
            url = `/api/firewall/${fwId}/dns/${encodedId}`;
            body = { hostname: g('add-opn-hostname'), domain: g('add-opn-domain'), ip: g('add-opn-ip'), description: g('add-opn-desc') };
            if (!body.hostname || !body.ip) { alert('Hostname and IP are required.'); return; }
        } else return;

        const r = await fetch(url + _taTenantQuery(), { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        if (!r.ok) { const e = await r.json(); throw new Error(e.detail || r.statusText); }
        document.getElementById('opn-add-modal')?.remove();
        loadOpnsenseManagement();
    } catch (e) {
        alert('Error: ' + e.message);
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
            headers = ['Name', 'DN', 'Members', 'Actions'];
        }

        headEl.innerHTML = `<tr>${headers.map(h => `<th class="px-4 py-3 font-bold">${h}</th>`).join('')}</tr>`;
        bodyEl.innerHTML = `<tr><td colspan="100%" class="px-4 py-8 text-center text-slate-400 italic">Fetching ${subMenu}...</td></tr>`;

        const response = await fetch(endpoint);
        if (!response.ok) throw new Error(`Failed to fetch ${subMenu}`);
        const data = await response.json();
        const items = data.data || [];
        // Cache rows so the Edit button can look up the entity by DN without
        // encoding all fields into the onclick handler.
        window._ldapRows = items;

        if (items.length === 0) {
            bodyEl.innerHTML = `<tr><td colspan="100%" class="px-4 py-8 text-center text-slate-400 italic">No ${subMenu.toLowerCase()} found.</td></tr>`;
            return;
        }

        const editIcon = `<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"></path></svg>`;
        const delIcon  = `<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>`;
        const pwIcon   = `<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"></path></svg>`;

        bodyEl.innerHTML = items.map(item => {
            const eDn = String(item.dn).replace(/'/g, "\\'");
            const actions = `<td class="px-4 py-3 text-right whitespace-nowrap">
                <button onclick="editLDAPEntity('${subMenu}','${eDn}')" title="Edit" class="p-1 text-slate-400 hover:text-blue-600 transition-colors">${editIcon}</button>
                ${subMenu === 'Users' ? `<button onclick="showLDAPPasswordModal('${eDn}')" title="Change Password" class="p-1 text-slate-400 hover:text-blue-600 transition-colors">${pwIcon}</button>` : ''}
                <button onclick="deleteLDAPEntity('${eDn}')" title="Delete" class="p-1 text-slate-400 hover:text-red-600 transition-colors">${delIcon}</button>
            </td>`;
            let cells = '';
            if (subMenu === 'OUs') {
                cells = `<td class="px-4 py-3 text-slate-700">${item.name}</td><td class="px-4 py-3 font-mono text-xs text-slate-500">${item.dn}</td>`;
            } else if (subMenu === 'Users') {
                cells = `<td class="px-4 py-3 text-slate-700 font-medium">${item.username || ''}</td><td class="px-4 py-3 text-slate-600">${item.first_name || ''}</td><td class="px-4 py-3 text-slate-600">${item.last_name || ''}</td><td class="px-4 py-3 text-slate-600">${item.email || ''}</td><td class="px-4 py-3 font-mono text-xs text-slate-500 max-w-xs truncate">${item.dn}</td>`;
            } else if (subMenu === 'Groups') {
                cells = `<td class="px-4 py-3 text-slate-700">${item.name || ''}</td><td class="px-4 py-3 font-mono text-xs text-slate-500">${item.dn}</td><td class="px-4 py-3 text-slate-500 text-xs">${item.member_count || 0} members</td>`;
            }
            return `<tr class="hover:bg-slate-50 transition-colors">${cells}${actions}</tr>`;
        }).join('');
    } catch (err) {
        bodyEl.innerHTML = `<tr><td colspan="100%" class="px-4 py-8 text-center text-red-500">${err.message}</td></tr>`;
    }
}

function editLDAPEntity(subMenu, dn) {
    const item = (window._ldapRows || []).find(r => r.dn === dn);
    if (!item) { showToast('Row data not found — refresh and try again', 'error'); return; }
    showLDAPModal(subMenu, item);
}

function showLDAPModal(subMenu, editItem) {
    const editing = !!editItem;
    const modal = document.createElement('div');
    modal.className = 'fixed inset-0 bg-slate-900/50 backdrop-blur-sm flex items-center justify-center z-50';
    if (editing) modal.dataset.dn = editItem.dn;

    const label = subMenu === 'OUs' ? 'OU' : (subMenu === 'Users' ? 'User' : 'Group');
    const inp = 'w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500';
    const val = v => (v == null ? '' : String(v).replace(/"/g, '&quot;'));

    let fields = '';
    if (subMenu === 'OUs') {
        fields = `
            <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">OU Name</label><input type="text" id="ldap-ou-name" value="${val(editItem?.name)}" class="${inp}"></div>
            ${editing ? '' : `<div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Parent DN</label><input type="text" id="ldap-ou-parent" placeholder="dc=example,dc=org" class="${inp}"></div>`}
        `;
    } else if (subMenu === 'Users') {
        fields = `
            <div class="grid grid-cols-2 gap-4">
                <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Username</label><input type="text" id="ldap-user-username" value="${val(editItem?.username)}" class="${inp}"></div>
                <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">First Name</label><input type="text" id="ldap-user-first" value="${val(editItem?.first_name)}" class="${inp}"></div>
                <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Last Name</label><input type="text" id="ldap-user-last" value="${val(editItem?.last_name)}" class="${inp}"></div>
                <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Email</label><input type="text" id="ldap-user-email" value="${val(editItem?.email)}" class="${inp}"></div>
            </div>
            ${editing ? '' : `<div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">OU DN</label><input type="text" id="ldap-user-ou" placeholder="ou=Users,dc=example,dc=org" class="${inp}"></div>
            <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Password <span class="text-slate-400 normal-case font-normal">(leave blank to auto-generate)</span></label><input type="password" id="ldap-user-password" class="${inp}"></div>`}
        `;
    } else if (subMenu === 'Groups') {
        fields = `
            <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Group Name</label><input type="text" id="ldap-group-name" value="${val(editItem?.name)}" class="${inp}"></div>
            ${editing ? '' : `<div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">OU DN</label><input type="text" id="ldap-group-ou" placeholder="ou=Groups,dc=example,dc=org" class="${inp}"></div>`}
        `;
    }

    modal.innerHTML = `
        <div class="bg-white rounded-lg shadow-2xl w-full max-w-md overflow-hidden border border-slate-200">
            <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center">
                <h3 class="text-lg font-bold text-slate-800">${editing ? 'Edit' : 'Add'} ${label}</h3>
                <button onclick="this.closest('.fixed').remove()" class="text-slate-400 hover:text-slate-600"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg></button>
            </div>
            <div class="p-6 space-y-4">${fields}</div>
            <div class="px-6 py-4 bg-slate-50 border-t border-slate-200 flex justify-end gap-3">
                <button onclick="this.closest('.fixed').remove()" class="px-4 py-2 text-sm font-medium text-slate-600 hover:text-slate-800">Cancel</button>
                <button onclick="saveLDAPEntity('${subMenu}')" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-6 py-2 rounded-md text-sm font-bold transition-all">${editing ? 'Save Changes' : 'Save Entity'}</button>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
}

async function saveLDAPEntity(subMenu) {
    const modal = document.querySelector('.fixed');
    const editing = modal && modal.dataset.dn;
    const body = {};
    if (subMenu === 'OUs') {
        body.name = document.getElementById('ldap-ou-name').value.trim();
        if (!editing) body.parent_dn = document.getElementById('ldap-ou-parent')?.value || '';
    } else if (subMenu === 'Users') {
        body.username = document.getElementById('ldap-user-username').value.trim();
        body.first_name = document.getElementById('ldap-user-first').value.trim();
        body.last_name = document.getElementById('ldap-user-last').value.trim();
        body.email = document.getElementById('ldap-user-email').value.trim();
        if (!editing) {
            body.ou_dn = document.getElementById('ldap-user-ou')?.value || '';
            const pw = document.getElementById('ldap-user-password')?.value;
            if (pw) body.password = pw;
        }
    } else if (subMenu === 'Groups') {
        body.name = document.getElementById('ldap-group-name').value.trim();
        if (!editing) body.ou_dn = document.getElementById('ldap-group-ou')?.value || '';
    }

    if (!body.name && subMenu !== 'Users' && !body.username) {
        alert('Name is required');
        return;
    }

    if (editing) body.dn = modal.dataset.dn;

    try {
        const endpoint = subMenu === 'OUs' ? '/api/ldap/ous' : (subMenu === 'Users' ? '/api/ldap/users' : '/api/ldap/groups');
        const response = await fetch(endpoint, {
            method: editing ? 'PUT' : 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        if (response.ok) {
            const result = await response.json();
            if (!editing && result.password) {
                alert(`User created!\n\nGenerated password: ${result.password}\n\nPlease record this — it will not be shown again.`);
            } else {
                alert(editing ? 'Entity updated successfully!' : 'Entity created successfully!');
            }
            document.querySelector('.fixed').remove();
            loadLDAPData(subMenu);
        } else {
            const err = await response.json().catch(() => ({}));
            alert('Error: ' + (err.message || (editing ? 'Failed to update entity' : 'Failed to create entity')));
        }
    } catch (e) {
        alert('Request failed: ' + e.message);
    }
}

async function deleteLDAPEntity(dn) {
    if (!await showConfirmToast(`Are you sure you want to delete ${dn}?`)) return;
    try {
        const response = await fetch('/api/ldap/entity', {
            method: 'DELETE',
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

function showLDAPPasswordModal(userDn) {
    const modal = document.createElement('div');
    modal.className = 'fixed inset-0 bg-slate-900/50 backdrop-blur-sm flex items-center justify-center z-50';
    const inputCls = 'w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500';
    modal.innerHTML = `
        <div class="bg-white rounded-lg shadow-2xl w-full max-w-md overflow-hidden border border-slate-200">
            <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center">
                <h3 class="text-lg font-bold text-slate-800">Change Password</h3>
                <button onclick="this.closest('.fixed').remove()" class="text-slate-400 hover:text-slate-600">✕</button>
            </div>
            <div class="p-6 space-y-4">
                <p class="text-xs text-slate-500 font-mono">${userDn}</p>
                <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">New Password</label><input type="password" id="ldap-new-password" class="${inputCls}" autocomplete="new-password"></div>
                <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Confirm Password</label><input type="password" id="ldap-confirm-password" class="${inputCls}" autocomplete="new-password"></div>
            </div>
            <div class="px-6 py-4 bg-slate-50 border-t border-slate-200 flex justify-end gap-3">
                <button onclick="this.closest('.fixed').remove()" class="px-4 py-2 text-sm text-slate-600">Cancel</button>
                <button onclick="changeUserPassword('${userDn.replace(/'/g, "\\'")}')" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-6 py-2 rounded-md text-sm font-bold transition-all">Set Password</button>
            </div>
        </div>`;
    document.body.appendChild(modal);
}

async function changeUserPassword(userDn) {
    const pw = document.getElementById('ldap-new-password')?.value;
    const confirm = document.getElementById('ldap-confirm-password')?.value;
    if (!pw) { alert('Password cannot be empty'); return; }
    if (pw !== confirm) { alert('Passwords do not match'); return; }
    try {
        const r = await fetch('/api/ldap/users/password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ user_dn: userDn, password: pw })
        });
        if (r.ok) {
            alert('Password changed successfully.');
            document.querySelector('.fixed')?.remove();
        } else {
            const err = await r.json();
            alert('Error: ' + (err.detail || err.message || 'Failed to change password'));
        }
    } catch (e) {
        alert('Request failed: ' + e.message);
    }
}

async function showAddUserModal() {
    const tadm = isTenantAdmin();
    // Tenant picklist for the Assigned Tenants multi-select (Global admins only —
    // a Tenant Admin creates users in their OWN tenant, no picker). Required when
    // "Admin (tenant)" is checked; the backend rejects a tenant_admin with none.
    if (!tadm) { try { await ensureTenants(); } catch (e) {} }
    const _tenants = tadm ? [] : (window._allTenants || []);
    const _tenantRows = _tenants.length
        ? _tenants.map(t => `<label class="flex items-center gap-2 text-sm text-slate-600 py-1"><input type="checkbox" value="${escapeHtml(t.id)}" class="new-user-tenant w-4 h-4 text-amber-600 border-slate-300 rounded focus:ring-amber-500"> ${escapeHtml(t.name || t.id)}</label>`).join('')
        : '<span class="text-[11px] text-slate-400 italic">No tenants defined yet.</span>';
    const modal = document.createElement('div');
    modal.id = 'add-user-modal';
    modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm';
    modal.innerHTML = `
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-2xl overflow-hidden">
            <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50">
                <h3 class="text-lg font-bold text-[#263040]">Add New User</h3>
                <button onclick="closeAddUserModal()" class="text-slate-400 hover:text-slate-600 transition-colors"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg></button>
            </div>
            <div class="p-6 space-y-4">
                <div class="grid grid-cols-2 gap-4">
                    <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">User ID / Username</label><input type="text" id="new-user-id" placeholder="e.g. jsmith" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"></div>
                    <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Auth Type</label>
                        <select id="new-user-auth-type" onchange="document.getElementById('new-user-password-wrap').classList.toggle('hidden', this.value==='ldap')" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                            <option value="local">Local</option>
                            <option value="ldap">LDAP</option>
                        </select>
                    </div>
                </div>
                <div id="new-user-password-wrap" class="space-y-2">
                    <label class="text-xs text-slate-500 uppercase font-bold">Password <span class="text-slate-400 normal-case font-normal">(leave blank to set later)</span></label>
                    <input type="password" id="new-user-password" placeholder="••••••••" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">
                </div>
                <div class="grid grid-cols-4 gap-3">
                    ${tadm ? '' : `<div><label class="text-xs text-slate-500 uppercase font-bold" title="System-wide admin (all tenants + system config)">Global Admin</label><div class="flex items-center gap-2 py-2"><input type="checkbox" id="perm-admin" onchange="document.getElementById('perm-tenant_admin').checked = false" class="w-4 h-4 text-green-600 border-slate-300 rounded focus:ring-green-500"></div></div>
                    <div><label class="text-xs text-slate-500 uppercase font-bold" title="Tenant-level admin (admin within assigned tenants only)">Admin (tenant)</label><div class="flex items-center gap-2 py-2"><input type="checkbox" id="perm-tenant_admin" onchange="document.getElementById('perm-admin').checked = false" class="w-4 h-4 text-amber-600 border-slate-300 rounded focus:ring-amber-500"></div></div>`}
                    <div><label class="text-xs text-slate-500 uppercase font-bold">View</label><div class="flex items-center gap-2 py-2"><input type="checkbox" id="perm-view" class="w-4 h-4 text-green-600 border-slate-300 rounded focus:ring-green-500"></div></div>
                    <div><label class="text-xs text-slate-500 uppercase font-bold">Edit</label><div class="flex items-center gap-2 py-2"><input type="checkbox" id="perm-edit" class="w-4 h-4 text-green-600 border-slate-300 rounded focus:ring-green-500"></div></div>
                    <div><label class="text-xs text-slate-500 uppercase font-bold">Hypervisor</label><div class="flex items-center gap-2 py-2"><input type="checkbox" id="perm-pxmx" class="w-4 h-4 text-green-600 border-slate-300 rounded focus:ring-green-500"></div></div>
                    <div><label class="text-xs text-slate-500 uppercase font-bold">Firewall</label><div class="flex items-center gap-2 py-2"><input type="checkbox" id="perm-firewall" class="w-4 h-4 text-green-600 border-slate-300 rounded focus:ring-green-500"></div></div>
                    <div><label class="text-xs text-slate-500 uppercase font-bold">DNS</label><div class="flex items-center gap-2 py-2"><input type="checkbox" id="perm-dns" class="w-4 h-4 text-green-600 border-slate-300 rounded focus:ring-green-500"></div></div>
                    <div><label class="text-xs text-slate-500 uppercase font-bold">DHCP</label><div class="flex items-center gap-2 py-2"><input type="checkbox" id="perm-dhcp" class="w-4 h-4 text-green-600 border-slate-300 rounded focus:ring-green-500"></div></div>
                    <div><label class="text-xs text-slate-500 uppercase font-bold">NAC</label><div class="flex items-center gap-2 py-2"><input type="checkbox" id="perm-security" class="w-4 h-4 text-green-600 border-slate-300 rounded focus:ring-green-500"></div></div>
                    <div><label class="text-xs text-slate-500 uppercase font-bold">Network Devices</label><div class="flex items-center gap-2 py-2"><input type="checkbox" id="perm-nw" class="w-4 h-4 text-green-600 border-slate-300 rounded focus:ring-green-500"></div></div>
                    <div><label class="text-xs text-slate-500 uppercase font-bold">IPAM</label><div class="flex items-center gap-2 py-2"><input type="checkbox" id="perm-ipam" class="w-4 h-4 text-green-600 border-slate-300 rounded focus:ring-green-500"></div></div>
                    <div><label class="text-xs text-slate-500 uppercase font-bold">Simulations</label><div class="flex items-center gap-2 py-2"><input type="checkbox" id="perm-cs" class="w-4 h-4 text-green-600 border-slate-300 rounded focus:ring-green-500"></div></div>
                    <div><label class="text-xs text-slate-500 uppercase font-bold">Console</label><div class="flex items-center gap-2 py-2"><input type="checkbox" id="perm-console" class="w-4 h-4 text-green-600 border-slate-300 rounded focus:ring-green-500"></div></div>
                    <div><label class="text-xs text-slate-500 uppercase font-bold">Console Write</label><div class="flex items-center gap-2 py-2"><input type="checkbox" id="perm-console_write" class="w-4 h-4 text-green-600 border-slate-300 rounded focus:ring-green-500"></div></div>
                </div>
                ${tadm ? `<div class="space-y-2 border-t border-slate-200 pt-3"><label class="text-xs text-slate-500 uppercase font-bold">Tenant</label><div class="text-sm text-slate-600">User is created in <span class="font-mono font-bold text-green-700">${escapeHtml(currentTenant || 'default')}</span> (your tenant). Module rights only — admin roles are Global-Admin-only.</div></div>` : `<div class="space-y-2 border-t border-slate-200 pt-3">
                    <label class="text-xs text-slate-500 uppercase font-bold">Assigned Tenants <span class="text-slate-400 normal-case font-normal">(required for Tenant Admin; also confines a regular user)</span></label>
                    <div id="new-user-tenants" class="grid grid-cols-3 gap-x-4 gap-y-1 mt-1 max-h-36 overflow-y-auto pr-1">${_tenantRows}</div>
                </div>
                <div class="space-y-2 border-t border-slate-200 pt-3">
                    <label class="text-xs text-slate-500 uppercase font-bold">Permission Groups <span class="text-slate-400 normal-case font-normal">(bundle access; unioned with the flags above)</span></label>
                    <div id="new-user-groups" class="flex flex-wrap gap-2 text-sm text-slate-400 italic">Loading groups…</div>
                </div>`}
            </div>
            <div class="px-6 py-4 bg-slate-50 border-t border-slate-200 flex justify-end gap-3">
                <button onclick="closeAddUserModal()" class="px-4 py-2 text-sm font-medium text-slate-600 hover:text-slate-800 transition-colors">Cancel</button>
                <button onclick="saveUser()" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm">Create User</button>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
    if (document.getElementById('new-user-groups')) {
        _populateUserGroupChecklist('new-user-groups', []);
    }
}

function closeAddUserModal() {
    const modal = document.getElementById('add-user-modal');
    if (modal) modal.remove();
}

async function saveUser() {
    const userId = document.getElementById('new-user-id').value.trim();
    if (!userId) { alert('Please enter a User ID'); return; }

    const tadm = isTenantAdmin();
    // A tenant Admin may only grant module rights — never an admin tier. The
    // role checkboxes are hidden in the modal for tenant_admin, but force the
    // keys false regardless so a crafted client value can't escalate.
    const permissions = {
        admin: tadm ? false : document.getElementById('perm-admin')?.checked,
        tenant_admin: tadm ? false : document.getElementById('perm-tenant_admin')?.checked,
        view: document.getElementById('perm-view').checked,
        edit: document.getElementById('perm-edit').checked,
        pxmx: document.getElementById('perm-pxmx').checked,
        firewall: document.getElementById('perm-firewall').checked,
        dns: document.getElementById('perm-dns').checked,
        dhcp: document.getElementById('perm-dhcp').checked,
        security: document.getElementById('perm-security').checked,
        nw: document.getElementById('perm-nw').checked,
        ipam: document.getElementById('perm-ipam').checked,
        cs: document.getElementById('perm-cs').checked,
        console: document.getElementById('perm-console').checked,
        console_write: document.getElementById('perm-console_write').checked,
    };
    const auth_type = document.getElementById('new-user-auth-type')?.value || 'local';
    const password = document.getElementById('new-user-password')?.value || '';
    const groups = tadm ? undefined : _collectCheckedGroups('new-user-groups');
    // Assigned tenants (Global-admin path). A Tenant Admin MUST have ≥1 — guard
    // client-side for a clear message before the backend 400s.
    const tenants = tadm ? undefined : Array.from(
        document.querySelectorAll('#new-user-tenants input.new-user-tenant:checked')).map(el => el.value);
    if (!tadm && permissions.tenant_admin && (!tenants || tenants.length === 0)) {
        alert('Tenant Admin requires at least one assigned tenant — select one under "Assigned Tenants".');
        return;
    }
    const base = _taUsersBase();

    try {
        const response = await setupFetch(base ? base : '/setup/users', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(base
                ? { user_id: userId, permissions, auth_type, password }
                : { user_id: userId, permissions, auth_type, password, groups, tenants, create: true })
        });
        if (response.ok) {
            alert('User created successfully');
            closeAddUserModal();
            await loadUsers();
        } else {
            const d = await response.json().catch(() => ({}));
            alert(d.detail || 'Failed to create user');
        }
    } catch (err) {
        alert('Error creating user: ' + err.message);
    }
}

async function editUser(userId) {
    try {
        const tadm = isTenantAdmin();
        const base = _taUsersBase();
        // Tenant Admins use the tenant-scoped user list + their own allowed
        // tenants (the /setup/tenants + /setup/groups routes are Global-only).
        const fetches = tadm
            ? [setupFetch(base)]
            : [setupFetch('/setup/users'), setupFetch('/setup/tenants'), setupFetch('/setup/groups')];
        const results = await Promise.all(fetches);
        const userResp = results[0];
        const tenantResp = tadm ? null : results[1];
        const groupResp = tadm ? null : results[2];
        if (!userResp.ok) throw new Error('Failed to load user data');

        const userData = await userResp.json();
        const tenantData = tenantResp ? await tenantResp.json() : { tenants: (userAllowedTenants() || []).map(id => ({ id, name: id })) };
        const groupData = groupResp && groupResp.ok ? await groupResp.json() : { groups: {} };

        const users = userData.users || {};
        const user = users[userId];
        if (!user) throw new Error('User not found');
        if (user.protected) { alert('This account is protected and cannot be edited.'); return; }

        const tenants = tenantData.tenants || [];
        const userTenants = user.tenants || [];
        const allGroups = groupData.groups || {};
        const userGroups = user.groups || [];

        const modal = document.createElement('div');
        modal.id = 'edit-user-modal';
        modal.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm';

        const perms = user.effective_permissions || user.permissions || {};
        // Tenant Admins may only edit module rights — hide the Global Admin /
        // tenant Admin tier checkboxes (the backend rejects them anyway).
        const permFields = [
            ...(tadm ? [] : [{id: 'admin', label: 'Global Admin'}, {id: 'tenant_admin', label: 'Admin (tenant)'}]),
            {id: 'view', label: 'View'},
            {id: 'edit', label: 'Edit'},
            {id: 'pxmx', label: 'Hypervisor'},
            {id: 'firewall', label: 'Firewall'},
            {id: 'dns', label: 'DNS'},
            {id: 'dhcp', label: 'DHCP'},
            {id: 'security', label: 'NAC'},
            {id: 'nw', label: 'Network Devices'},
            {id: 'ipam', label: 'IPAM'},
            {id: 'cs', label: 'Simulations'},
            {id: 'console', label: 'Console'},
            {id: 'console_write', label: 'Console Write'},
        ];

        const permHtml = permFields.map(p => {
            // Admin uses two equivalent forms; check the box if either is set so
            // editing a role-only admin shows it checked (and saving preserves it).
            // The two admin tiers (Global Admin / tenant Admin) are mutually
            // exclusive — checking one unchecks the other.
            const isChecked = p.id === 'admin'
                ? (perms.admin === true || perms.role === 'admin')
                : p.id === 'tenant_admin'
                    ? (perms.role === 'tenant_admin')
                    : !!perms[p.id];
            const onchange = p.id === 'admin'
                ? `onchange="document.getElementById('edit-perm-tenant_admin').checked = false"`
                : p.id === 'tenant_admin'
                    ? `onchange="document.getElementById('edit-perm-admin').checked = false"`
                    : '';
            return `
            <div class="space-y-2">
                <label class="text-xs text-slate-500 uppercase font-bold">${p.label}</label>
                <div class="flex items-center gap-2 py-2">
                    <input type="checkbox" id="edit-perm-${p.id}" ${isChecked ? 'checked' : ''} ${onchange} class="w-4 h-4 text-green-600 border-slate-300 rounded focus:ring-green-500">
                </div>
            </div>
        `;
        }).join('');

        const tenantHtml = tenants.map(t => `
            <div class="flex items-center gap-3 p-2 hover:bg-slate-100 rounded-md transition-colors cursor-pointer">
                <input type="checkbox" id="edit-tenant-${t.id}" ${userTenants.includes(t.id) ? 'checked' : ''} value="${t.id}" class="w-4 h-4 text-green-600 border-slate-300 rounded focus:ring-green-500">
                <label for="edit-tenant-${t.id}" class="text-sm text-slate-700 cursor-pointer flex-1">${t.name}</label>
            </div>
        `).join('');

        const groupHtml = Object.entries(allGroups).map(([gid, g]) => `
            <div class="flex items-center gap-3 p-2 hover:bg-slate-100 rounded-md transition-colors cursor-pointer">
                <input type="checkbox" id="edit-grp-${gid}" ${userGroups.includes(gid) ? 'checked' : ''} value="${gid}" class="w-4 h-4 text-indigo-600 border-slate-300 rounded focus:ring-indigo-500">
                <label for="edit-grp-${gid}" class="text-sm text-slate-700 cursor-pointer flex-1">${g.name || gid}<span class="text-[10px] text-slate-400 ml-1">${Object.keys(g.permissions || {}).filter(k => k !== 'role').join(', ')}</span></label>
            </div>
        `).join('');

        modal.innerHTML = `
            <div class="bg-white rounded-xl shadow-2xl w-full max-w-2xl overflow-hidden">
                <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50">
                    <h3 class="text-lg font-bold text-[#263040]">Edit User: ${userId}</h3>
                    <button onclick="closeEditUserModal()" class="text-slate-400 hover:text-slate-600 transition-colors"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg></button>
                </div>
                <div class="p-6 grid grid-cols-1 md:grid-cols-2 gap-8">
                    <div class="space-y-6"><div><h4 class="text-xs font-bold text-slate-400 uppercase mb-4">Permissions</h4><div class="grid grid-cols-2 gap-4">${permHtml}</div></div></div>
                    <div class="space-y-6">
                        ${tadm ? '' : `<div><h4 class="text-xs font-bold text-slate-400 uppercase mb-4">Permission Groups</h4><div class="border border-slate-200 rounded-lg overflow-hidden bg-slate-50 max-h-40 overflow-y-auto p-2 space-y-1">${groupHtml || '<div class="text-xs text-slate-400 italic p-2">No groups defined.</div>'}</div></div>`}
                        <div><h4 class="text-xs font-bold text-slate-400 uppercase mb-4">Tenant Associations</h4><div class="border border-slate-200 rounded-lg overflow-hidden bg-slate-50 max-h-40 overflow-y-auto p-2 space-y-1">${tenantHtml || '<div class="text-xs text-slate-400 italic p-2">No tenants available.</div>'}</div></div>
                    </div>
                </div>
                <div class="px-6 py-4 bg-slate-50 border-t border-slate-200 flex justify-between items-center gap-3">
                    <button onclick="promptSetPassword('${userId}')" class="text-xs text-slate-500 hover:text-blue-600 transition-colors">Set Password</button>
                    <div class="flex gap-3">
                        <button onclick="closeEditUserModal()" class="px-4 py-2 text-sm font-medium text-slate-600 hover:text-slate-800 transition-colors">Cancel</button>
                        <button onclick="saveUserEdits('${userId}')" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm">Save Changes</button>
                    </div>
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
        const tadm = isTenantAdmin();
        const base = _taUsersBase();
        // The admin-tier checkboxes are absent for a tenant Admin; use optional
        // chaining so the read is false (and force false regardless — a tenant
        // admin must never grant an admin tier; the backend rejects it too).
        const permissions = {
            admin: tadm ? false : document.getElementById('edit-perm-admin')?.checked,
            tenant_admin: tadm ? false : document.getElementById('edit-perm-tenant_admin')?.checked,
            view: document.getElementById('edit-perm-view').checked,
            edit: document.getElementById('edit-perm-edit').checked,
            pxmx: document.getElementById('edit-perm-pxmx').checked,
            firewall: document.getElementById('edit-perm-firewall').checked,
            dns: document.getElementById('edit-perm-dns').checked,
            dhcp: document.getElementById('edit-perm-dhcp').checked,
            security: document.getElementById('edit-perm-security').checked,
            nw: document.getElementById('edit-perm-nw').checked,
            ipam: document.getElementById('edit-perm-ipam').checked,
            cs: document.getElementById('edit-perm-cs').checked,
            console: document.getElementById('edit-perm-console').checked,
            console_write: document.getElementById('edit-perm-console_write').checked,
        };

        const tenantCheckboxes = document.querySelectorAll('input[id^="edit-tenant-"]');
        const selectedTenants = Array.from(tenantCheckboxes).filter(cb => cb.checked).map(cb => cb.value);

        if (tadm) {
            // One tenant-scoped POST: permissions + tenant membership (the route
            // intersects the requested tenants with the admin's owned tenants and
            // always retains the path tenant). No groups, no separate
            // assign/remove-tenant calls.
            const resp = await setupFetch(`${base}/${encodeURIComponent(userId)}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ permissions, tenants: selectedTenants })
            });
            if (!resp.ok) {
                const d = await resp.json().catch(() => ({}));
                throw new Error(d.detail || 'Failed to update user');
            }
            alert('User updated successfully');
            closeEditUserModal();
            await loadUsers();
            return;
        }

        const groupCheckboxes = document.querySelectorAll('input[id^="edit-grp-"]');
        const selectedGroups = Array.from(groupCheckboxes).filter(cb => cb.checked).map(cb => cb.value);

        const updateResp = await setupFetch('/setup/users', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ user_id: userId, permissions: permissions, groups: selectedGroups })
        });
        if (!updateResp.ok) throw new Error('Failed to update user permissions');

        const userResp = await setupFetch('/setup/users');
        const userData = await userResp.json();
        const currentTenants = userData.users[userId].tenants || [];

        const tenantsToAssign = selectedTenants.filter(t => !currentTenants.includes(t));
        const tenantsToRemove = currentTenants.filter(t => !selectedTenants.includes(t));

        const requests = [];
        for (const tId of tenantsToAssign) {
            requests.push(setupFetch('/setup/users/assign-tenant', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ user_id: userId, tenant_id: tId }) }));
        }
        for (const tId of tenantsToRemove) {
            requests.push(setupFetch('/setup/users/remove-tenant', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ user_id: userId, tenant_id: tId }) }));
        }
        await Promise.all(requests);

        alert('User updated successfully');
        closeEditUserModal();
        await loadUsers();
    } catch (err) {
        alert('Error saving user edits: ' + err.message);
    }
}

async function promptSetPassword(userId) {
    const pw = prompt(`Set password for ${userId}:`);
    if (!pw) return;
    try {
        const base = _taUsersBase();
        const url = base
            ? `${base}/${encodeURIComponent(userId)}/set-password`
            : `/setup/users/${encodeURIComponent(userId)}/set-password`;
        const resp = await setupFetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password: pw }),
        });
        if (resp.ok) {
            alert('Password updated.');
        } else {
            const d = await resp.json().catch(() => ({}));
            alert('Failed: ' + (d.detail || resp.statusText));
        }
    } catch (err) {
        alert('Error: ' + err.message);
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
                <button onclick="closeFirewallModal()" class="text-slate-400 hover:text-slate-600 transition-colors"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg></button>
            </div>
            <div class="p-6 space-y-4">
                <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Firewall Name</label><input type="text" id="fw-name" placeholder="e.g. Core Firewall" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"></div>
                <div class="grid grid-cols-2 gap-4">
                    <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Model</label><select id="fw-model" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"><option value="opnsense">OPNsense</option><option value="juniper">Juniper</option><option value="fortigate">Fortigate</option><option value="pfsense">pfSense</option></select></div>
                    <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Associated Spoke</label><select id="fw-spoke" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"><option value="">Loading spokes...</option></select></div>
                </div>
                <div class="grid grid-cols-2 gap-4">
                    <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Host/IP</label><input type="text" id="fw-host" placeholder="172.16.1.1" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"></div>
                    <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Port</label><input type="text" id="fw-port" placeholder="8443" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"></div>
                </div>
                <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">API Key</label><input type="text" id="fw-api-key" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"></div>
                <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">API Secret</label><input type="password" id="fw-api-secret" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"></div>
            </div>
            <div class="px-6 py-4 bg-slate-50 border-t border-slate-200 flex justify-end gap-3">
                <button onclick="closeFirewallModal()" class="px-4 py-2 text-sm font-medium text-slate-600 hover:text-slate-800 transition-colors">Cancel</button>
                <button onclick="saveFirewall()" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm">Save Firewall</button>
            </div>
        </div>
    `;
    document.body.appendChild(modal);

    loadApprovedSpokes().then(spokes => {
        const selector = document.getElementById('fw-spoke');
        if (selector) {
            const fwSpokes = spokes.filter(s =>
                (s.module_type === 'firewall' ||
                 /^(opn|fw|firewall|pfsense|fortigate|juniper)/.test(s.spoke_id))
                && _spokeBindable(s)
            );
            selector.innerHTML = fwSpokes.length > 0
                ? '<option value="">— select spoke —</option>' + fwSpokes.map(s => `<option value="${s.spoke_id}">${s.spoke_id}</option>`).join('')
                : '<option value="">No firewall spokes found</option>';
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

    setTimeout(() => {
        const selector = document.getElementById('fw-spoke');
        if (selector) selector.value = fw.spoke_id || '';
    }, 100);

    document.getElementById('firewall-modal').dataset.firewallId = id;
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
        const response = await setupFetch(url, {
            method: method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        if (response.ok) {
            alert(`Firewall ${id ? 'updated' : 'added'} successfully!`);
            closeFirewallModal();
            setView(currentView);
        } else {
            const err = await response.json().catch(() => ({}));
            alert('Failed to save firewall configuration: ' + (err.detail || response.status));
        }
    } catch (err) {
        alert('Error saving firewall: ' + err.message);
    }
}

function closeFirewallModal() {
    const modal = document.getElementById('firewall-modal');
    if (modal) modal.remove();
}

// ─── Network Devices: add/edit modal (mirrors the firewall modal) ───────────
// Fields: name, object_type (AOS/CX/EX/Gateway), transport (ssh/rest/snmp/auto),
// address, port, username, password, enable_secret, api_token, snmp_community,
// spoke (filtered to nw spokes). Creds are stored in runtime system.json only.
function showAddNwDeviceModal() {
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
                <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Address / Host IP</label><input type="text" id="nw-address" placeholder="10.0.0.1" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"></div>
                <div class="grid grid-cols-2 gap-4">
                    <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Username</label><input type="text" id="nw-username" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"></div>
                    <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Password</label><input type="password" id="nw-password" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"></div>
                </div>
                <div class="grid grid-cols-2 gap-4">
                    <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Enable Secret</label><input type="password" id="nw-enable-secret" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"></div>
                    <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">API Token</label><input type="password" id="nw-api-token" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"></div>
                </div>
                <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">SNMP Community</label><input type="text" id="nw-snmp-community" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"></div>
            </div>
            <div class="px-6 py-4 bg-slate-50 border-t border-slate-200 flex justify-end gap-3 sticky bottom-0">
                <button onclick="closeNwDeviceModal()" class="px-4 py-2 text-sm font-medium text-slate-600 hover:text-slate-800 transition-colors">Cancel</button>
                <button onclick="saveNwDevice()" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm">Save Device</button>
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
                ? '<option value="">— select spoke —</option>' + nwSpokes.map(s => `<option value="${s.spoke_id}">${s.spoke_id}</option>`).join('')
                : '<option value="">No network spokes found</option>';
        }
    });
}

async function editNwDevice(id) {
    const devices = _nwDevicesCache.length ? _nwDevicesCache : await loadNwDevices();
    const d = devices.find(x => x.id === id);
    if (!d) return;

    showAddNwDeviceModal();
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

    setTimeout(() => {
        const selector = document.getElementById('nw-spoke');
        if (selector) selector.value = d.spoke_id || '';
    }, 100);

    document.getElementById('nw-device-modal').dataset.deviceId = id;
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
    };
    if (!config.name || !config.object_type) {
        alert('Device name and object type are required.');
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
            alert(`Network device ${id ? 'updated' : 'added'} successfully!`);
            closeNwDeviceModal();
            loadNwDevicesList();
        } else {
            const err = await response.json().catch(() => ({}));
            alert('Failed to save network device: ' + (err.detail || response.status));
        }
    } catch (err) {
        alert('Error saving network device: ' + err.message);
    }
}

function closeNwDeviceModal() {
    const modal = document.getElementById('nw-device-modal');
    if (modal) modal.remove();
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
        rowSummary: inst => `${inst.host || '—'}`,
        fields: [
            { id: 'host', label: 'CPPM Host', placeholder: 'https://clearpass.example.com' },
            { id: 'client_id', label: 'OAuth2 Client ID', placeholder: 'API client ID' },
            { id: 'client_secret', label: 'OAuth2 Client Secret', type: 'password', placeholder: 'Client secret' },
            { id: 'user', label: 'Fallback Username', placeholder: 'admin' },
            { id: 'password', label: 'Fallback Password', type: 'password', placeholder: 'Password' },
        ],
    },
    ipam: {
        title: 'IPAM / NetBox Instance',
        endpoint: '/setup/ipam-instances',
        listId: 'ipam-instances-list',
        moduleType: 'ipam',
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
        rowSummary: inst => `${inst.server_url || '—'}`,
        fields: [
            { id: 'server_url', label: 'Server URL', placeholder: 'ldap://localhost:389' },
            { id: 'base_dn', label: 'Base DN', placeholder: 'dc=example,dc=org' },
            { id: 'admin_dn', label: 'Admin DN', placeholder: 'cn=admin,dc=example,dc=org' },
            { id: 'admin_pw', label: 'Admin Password', type: 'password', placeholder: 'Password' },
        ],
    },
    dns: {
        title: 'DNS / Unbound Instance',
        endpoint: '/setup/dns-instances',
        listId: 'dns-instances-list',
        moduleType: 'dns',
        rowSummary: inst => `${inst.host || '—'}`,
        fields: [
            { id: 'host', label: 'DNS Server Host / IP', placeholder: '10.0.0.1' },
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
        ],
    },
    nac:   Object.assign({}, INSTANCE_PRODUCTS.nac,   { badgeLabel: 'NAC',  payloadKey: 'instance', responseKey: 'instances', spokeFilter: s => s.module_type === 'nac' }),
    ipam:  Object.assign({}, INSTANCE_PRODUCTS.ipam,  { badgeLabel: 'IPAM', payloadKey: 'instance', responseKey: 'instances', spokeFilter: s => s.module_type === 'ipam' }),
    ldap:  Object.assign({}, INSTANCE_PRODUCTS.ldap,  { badgeLabel: 'LDAP', payloadKey: 'instance', responseKey: 'instances', spokeFilter: s => s.module_type === 'directory' }),
    dns:   Object.assign({}, INSTANCE_PRODUCTS.dns,   { badgeLabel: 'DNS',  payloadKey: 'instance', responseKey: 'instances', spokeFilter: s => s.module_type === 'dns' }),
    dhcp:  Object.assign({}, INSTANCE_PRODUCTS.dhcp,  { badgeLabel: 'DHCP', payloadKey: 'instance', responseKey: 'instances', spokeFilter: s => s.module_type === 'dhcp' }),
};

async function loadInstances(productKey) {
    const p = INSTANCE_PRODUCTS[productKey];
    if (!p) return;
    const listEl = document.getElementById(p.listId);
    if (!listEl) return;
    try {
        const r = await setupFetch(p.endpoint);
        if (!r.ok) throw new Error('Failed to fetch instances');
        const instances = (await r.json()).instances || [];
        window._instances = window._instances || {};
        window._instances[productKey] = instances;
        if (instances.length === 0) {
            listEl.innerHTML = '<p class="text-xs text-slate-400 italic">No instances configured.</p>';
            return;
        }
        listEl.innerHTML = instances.map(inst => `
            <div class="flex items-center justify-between p-3 rounded-md bg-slate-50 border border-slate-200">
                <div><span class="text-sm font-medium text-slate-700">${inst.name || inst.id}</span><span class="ml-2 text-xs text-slate-400">${p.rowSummary(inst)}${inst.spoke_id ? ' · ' + inst.spoke_id : ''}</span></div>
                <div class="flex gap-2">
                    <button onclick="editInstance('${productKey}','${inst.id}')" class="text-xs text-blue-500 hover:text-blue-700 font-medium">Edit</button>
                    <button onclick="deleteInstance('${productKey}','${inst.id}')" class="text-xs text-red-400 hover:text-red-600 font-medium">Delete</button>
                </div>
            </div>`).join('');
    } catch (e) {
        listEl.innerHTML = `<p class="text-xs text-red-500">Error loading instances: ${e.message}</p>`;
    }
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
${schemaBtnHtml}
            </div>
            <div class="px-6 py-4 bg-slate-50 border-t border-slate-200 flex justify-end gap-3">
                <button onclick="closeInstanceModal()" class="px-4 py-2 text-sm font-medium text-slate-600 hover:text-slate-800 transition-colors">Cancel</button>
                <button onclick="saveInstance('${productKey}')" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm">Save</button>
            </div>
        </div>`;
    document.body.appendChild(modal);
    modal.dataset.product = productKey;
    if (editItem) modal.dataset.instanceId = editItem.id;

    loadApprovedSpokes().then(spokes => {
        const selector = document.getElementById('inst-spoke');
        if (!selector) return;
        const matched = spokes.filter(s => s.module_type === p.moduleType && _spokeBindable(s));
        selector.innerHTML = matched.length > 0
            ? '<option value="">— select spoke —</option>' + matched.map(s => `<option value="${s.spoke_id}">${s.spoke_id}</option>`).join('')
            : `<option value="">No ${p.moduleType} spokes found</option>`;
        if (editItem) selector.value = editItem.spoke_id || '';
    });

    if (editItem) {
        document.getElementById('inst-name').value = editItem.name || '';
        p.fields.forEach(f => {
            const el = document.getElementById('inst-' + f.id);
            if (!el) return;
            // For a <select>, only override the default (first option) when the
            // instance has a stored value — an old instance with no verify_ssl
            // then keeps the secure "Verify" default instead of going blank.
            if (el.tagName === 'SELECT') { if (editItem[f.id]) el.value = editItem[f.id]; }
            else el.value = editItem[f.id] || '';
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
    p.fields.forEach(f => { config[f.id] = document.getElementById('inst-' + f.id).value; });
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
            alert(`Instance ${id ? 'updated' : 'added'} successfully!`);
            closeInstanceModal();
            loadInstances(productKey);
        } else {
            const err = await r.json().catch(() => ({}));
            alert('Failed to save instance: ' + (err.detail || r.status));
        }
    } catch (e) {
        alert('Error saving instance: ' + e.message);
    }
}

async function deleteInstance(productKey, id) {
    const p = INSTANCE_PRODUCTS[productKey];
    if (!p) return;
    if (!await showConfirmToast(`Delete this ${p.title.toLowerCase()}?`)) return;
    try {
        const r = await setupFetch(`${p.endpoint}/${id}`, { method: 'DELETE' });
        if (!r.ok) throw new Error(await r.text());
        loadInstances(productKey);
    } catch (e) {
        alert('Error: ' + e.message);
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
        listEl.innerHTML = '<p class="text-xs text-slate-400 italic">No managed devices yet. Click <strong>Add Device</strong> to attach one.</p>';
        return;
    }
    listEl.innerHTML = all.map(d => {
        const t = DEVICE_TYPES[d._typeKey];
        const name = d.name || d.id;
        const summary = t.rowSummary(d);
        const spoke = d.spoke_id ? ' · ' + escapeHtml(d.spoke_id) : '';
        const eId = String(d._id).replace(/'/g, "\\'");
        return `<div class="flex items-center justify-between p-3 rounded-md bg-slate-50 border border-slate-200">
            <div><span class="text-sm font-medium text-slate-700">${escapeHtml(name)}</span><span class="ml-2 px-2 py-0.5 rounded-full text-[10px] font-bold bg-blue-100 text-blue-700">${t.badgeLabel}</span><span class="ml-2 text-xs text-slate-400">${escapeHtml(summary)}${spoke}</span></div>
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
        const opts = (field.options || []).map(([v, lbl]) => `<option value="${v}"${v === val ? ' selected' : ''}>${lbl}</option>`).join('');
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
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-md max-h-[90vh] overflow-y-auto">
            <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50 sticky top-0">
                <h3 class="text-lg font-bold text-[#263040]">${editItem ? 'Edit' : 'Add'} Managed Device</h3>
                <button onclick="closeDeviceModal()" class="text-slate-400 hover:text-slate-600 transition-colors"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg></button>
            </div>
            <div class="p-6 space-y-4">
                <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Device Name</label><input type="text" id="dev-name" placeholder="e.g. Core Firewall" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"></div>
                <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Module Type</label><select id="dev-type" ${editItem ? 'disabled' : ''} onchange="_onDeviceTypeChange()" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500">${typeKeys.map(k => `<option value="${k}"${k === editTypeKey ? ' selected' : ''}>${DEVICE_TYPES[k].title}</option>`).join('')}</select></div>
                <div class="space-y-2"><label class="text-xs text-slate-500 uppercase font-bold">Associated Spoke</label><select id="dev-spoke" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"><option value="">Loading spokes...</option></select></div>
                <div id="dev-fields" class="space-y-4"></div>
            </div>
            <div class="px-6 py-4 bg-slate-50 border-t border-slate-200 flex justify-end gap-3 sticky bottom-0">
                <button onclick="closeDeviceModal()" class="px-4 py-2 text-sm font-medium text-slate-600 hover:text-slate-800 transition-colors">Cancel</button>
                <button onclick="saveDevice()" class="bg-[#01A982] hover:bg-[#008c6a] text-white px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm">Save</button>
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
    // Name is only auto-filled from the edit item (top-level field), not fields.
    if (values && values.name) {
        const nameEl = document.getElementById('dev-name');
        if (nameEl) nameEl.value = values.name;
    }
    loadApprovedSpokes().then(spokes => {
        const selector = document.getElementById('dev-spoke');
        if (!selector) return;
        const matched = spokes.filter(s => t.moduleType ? s.module_type === t.moduleType : true)
                              .filter(s => t.spokeFilter ? t.spokeFilter(s) : true)
                              .filter(_spokeBindable);
        const current = values ? values.spoke_id : '';
        selector.innerHTML = matched.length > 0
            ? '<option value="">— select spoke —</option>' + matched.map(s => `<option value="${s.spoke_id}"${s.spoke_id === current ? ' selected' : ''}>${s.spoke_id}</option>`).join('')
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
    if (!config.name) { alert('Device name is required.'); return; }
    t.fields.forEach(f => {
        const el = document.getElementById('dev-' + f.id);
        let v = el ? el.value : '';
        if (f.coerce === 'int') v = parseInt(v, 10) || (f.default != null ? f.default : null);
        config[f.id] = v;
    });
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
        const r = await setupFetch(`${_devEndpoint(t)}/${encodeURIComponent(id)}`, { method: 'DELETE' });
        if (!r.ok) throw new Error(await r.text().catch(() => r.status));
        loadAllDevices();
    } catch (e) {
        alert('Error: ' + e.message);
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
    try {
        // Pick the active tenant: user's first assigned tenant > localStorage > default.
        // Non-admin users with assigned tenants cannot switch outside their list.
        // Protected admins (no tenant assignments) always start on 'default' so a
        // stale localStorage value from a previous session doesn't scope their view.
        const allowed = userAllowedTenants();
        let resolved;
        if (currentUser?.protected && !allowed.length) {
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
        let pickerTenants = allowed.map(id => ({ id, name: id }));
        if (isAdmin()) {
            try {
                const r = await fetch('/setup/tenants', { credentials: 'same-origin' });
                if (r.ok) {
                    const td = await r.json();
                    pickerTenants = (td.tenants || []).map(t => ({ id: t.id, name: t.name || t.id }));
                }
            } catch (e) { console.error('_initApp: tenant picker fetch failed — falling back to allowed tenants', e); }
        }
        const tenantNameMap = {};
        pickerTenants.forEach(t => { tenantNameMap[t.id] = t.name; });
        window._lmTenantPicker = pickerTenants;

        // Build the user chip in the header
        const chip = document.getElementById('user-chip');
        const nameEl = document.getElementById('user-chip-name');
        const wrap = document.getElementById('user-chip-tenant-wrap');
        if (chip && currentUser) {
            if (nameEl) nameEl.textContent = currentUser.user_id;
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
                            <div id="tenant-picker-menu" class="hidden absolute top-full left-0 mt-1 bg-slate-800 border border-slate-600 rounded-lg shadow-xl z-50 min-w-[140px] max-h-[60vh] overflow-y-auto py-1">
                                ${pickerTenants.map(t => `
                                    <button data-tid="${escapeHtml(t.id)}" onclick="viewAsTenant('${escapeHtml(t.id)}')" class="w-full text-left px-3 py-1.5 text-[11px] text-slate-200 hover:bg-[#01A982] hover:text-white transition-colors ${t.id===currentTenant?'font-bold text-[#01A982]':''}">${escapeHtml(t.name)}</button>
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
        setView('dashboard');
        _startCacheStatusPolling();
        setInterval(updateStatus, 10000);
        // Re-validate the session periodically. /status (above) is public and
        // stays 200 even after auth expires, so it can't signal expiry on its
        // own. A 401 here is caught by the global fetch override, which sends
        // the user back to login instead of leaving a cached view rendering.
        setInterval(_pingSession, 60000);
        console.log("Lab Manager UI: Initialization complete.");
    } catch (err) {
        console.error("Lab Manager UI: Critical initialization error:", err);
        alert("UI Initialization failed: " + err.message);
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

// ─── Tenant Aggregate Dashboard (Phase 5) ────────────────────────────────────

async function loadAllTenantsOverview(forceRefresh = false) {
    const container = document.getElementById('all-tenants-overview');
    if (!container) return;
    container.innerHTML = '<p class="text-sm text-slate-400 italic">Loading tenants…</p>';
    try {
        const url = '/api/dashboard/all-tenants' + (forceRefresh ? '?refresh=1' : '');
        const r = await fetch(url);
        // Read the body as text first so a non-JSON response (e.g. the SPA
        // catch-all serving index.html when the hub hasn't loaded the new
        // route yet) surfaces a clear message instead of Safari's cryptic
        // "The string did not match the expected pattern." from r.json().
        const text = await r.text();
        let d;
        try { d = JSON.parse(text); }
        catch (_) {
            throw new Error(`HTTP ${r.status} — non-JSON response${text ? ' (' + text.slice(0, 120).replace(/\s+/g, ' ') + ')' : ''}. Hub may need a restart to load the all-tenants route.`);
        }
        if (!r.ok) throw new Error(`HTTP ${r.status}: ${d.detail || text.slice(0, 120)}`);
        const tenants = (d.tenants || []).slice().sort((a, b) => a.name.localeCompare(b.name));
        if (!tenants.length) {
            container.innerHTML = '<p class="text-sm text-slate-400 italic">No tenants configured.</p>';
            return;
        }
        const esc = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
        const num = v => (v == null || v === '' ? '—' : v);
        const cell = 'px-4 py-2 text-sm text-slate-700';
        const rows = tenants.map(t => {
            const active = t.id === currentTenant;
            return `<tr class="border-b border-slate-100 hover:bg-slate-50 cursor-pointer at-row ${active ? 'bg-green-50/60' : ''}" data-tid="${esc(t.id)}">
                <td class="px-4 py-2 text-sm">
                    <span class="font-medium text-[#263040] ${active ? 'text-[#01A982]' : ''}">${esc(t.name)}</span>
                    ${t.description ? `<span class="block text-xs text-slate-400">${esc(t.description)}</span>` : ''}
                </td>
                <td class="${cell}">${num(t.devices)}</td>
                <td class="${cell}">${num(t.vms)}</td>
                <td class="${cell}">${num(t.sessions)}</td>
                <td class="${cell}">${num(t.prefixes)}</td>
                <td class="${cell}">${num(t.ips_used)}</td>
                <td class="px-4 py-2 text-xs text-slate-400 text-right">${active ? '<span class="text-[#01A982] font-medium">viewing</span>' : 'View →'}</td>
            </tr>`;
        }).join('');
        container.innerHTML = `<table class="w-full text-left">
            <thead class="text-slate-400 uppercase text-xs border-b border-slate-200"><tr>
                <th class="px-4 py-2">Tenant</th>
                <th class="px-4 py-2">Devices</th>
                <th class="px-4 py-2">VMs</th>
                <th class="px-4 py-2">NAC Sessions</th>
                <th class="px-4 py-2">Prefixes</th>
                <th class="px-4 py-2">IPs Used</th>
                <th class="px-4 py-2"></th>
            </tr></thead>
            <tbody>${rows}</tbody>
        </table>
        <p class="mt-2 text-xs text-slate-400">Click a row to view as that tenant. Counts are cached for 60s — use Refresh for live numbers.</p>`;
        container.querySelectorAll('.at-row').forEach(tr => {
            tr.addEventListener('click', () => viewAsTenant(tr.dataset.tid));
        });
    } catch (err) {
        container.innerHTML = `<p class="text-sm text-red-500">Overview unavailable: ${err.message}</p>`;
        console.warn('All-tenants overview failed:', err.message);
    }
}

async function loadDashboardSummary() {
    const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };

    const nameEl = document.getElementById('dash-tenant-name');
    if (nameEl) nameEl.textContent = currentTenant;

    // Mark loading
    ['dash-devices','dash-vms','dash-sessions','dash-prefixes','dash-ips'].forEach(id => set(id, '…'));

    try {
        const r = await fetch(`/api/dashboard/summary?tenant=${encodeURIComponent(currentTenant)}`);
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const d = await r.json();

        set('dash-devices',  d.devices  ?? '—');
        set('dash-vms',      d.vms      ?? '—');
        set('dash-sessions', d.sessions ?? '—');
        set('dash-prefixes', d.prefixes ?? '—');
        set('dash-ips',      d.ips_used ?? '—');
    } catch (err) {
        ['dash-devices','dash-vms','dash-sessions','dash-prefixes','dash-ips'].forEach(id => set(id, '—'));
        console.warn('Dashboard summary unavailable:', err.message);
    }
}

// ─── Global Cross-System Search ──────────────────────────────────────────────

let _searchTimer = null;

function handleSearch(value) {
    clearTimeout(_searchTimer);
    const dropdown = document.getElementById('search-results');
    if (!value || value.trim().length < 2) {
        dropdown.classList.add('hidden');
        dropdown.innerHTML = '';
        return;
    }
    dropdown.classList.remove('hidden');
    dropdown.innerHTML = '<p class="text-xs text-slate-400 italic px-2 py-1">Searching…</p>';

    _searchTimer = setTimeout(async () => {
        try {
            const r = await fetch(`/api/search?q=${encodeURIComponent(value.trim())}`);
            const d = r.ok ? await r.json() : null;
            if (!d) { dropdown.innerHTML = '<p class="text-xs text-red-400 px-2 py-1">Search failed</p>'; return; }

            if (d.total === 0) {
                dropdown.innerHTML = '<p class="text-xs text-slate-400 italic px-2 py-1">No results</p>';
                return;
            }

            const sourceIcon = {
                netbox:    '📦',
                pxmx:      '🖥️',
                cppm:      '🔐',
                ldap:      '👤',
                opnsense:  '🔥',
            };
            const typeLabel = {
                device:     'Device',
                ip:         'IP Address',
                prefix:     'Prefix',
                vm:         'VM',
                lxc:        'Container',
                session:    'NAC Session',
                endpoint:   'Endpoint',
                user:       'User',
                computer:   'Computer',
                dhcp_lease: 'DHCP Lease',
            };

            const rows = d.results.slice(0, 12).map(item => {
                const icon  = sourceIcon[item.source] || '•';
                const label = typeLabel[item.type]    || item.type;
                const sub   = [item.ip, item.mac, item.cluster, item.dn].filter(Boolean).join(' · ');
                return `<div class="flex items-start gap-2 px-2 py-1.5 rounded-lg hover:bg-slate-50 cursor-pointer"
                             onclick="openSearchResult(${JSON.stringify(item).replace(/"/g, '&quot;')})">
                    <span class="text-base leading-none mt-0.5">${icon}</span>
                    <div class="min-w-0">
                        <div class="text-xs font-medium text-slate-800 truncate">${item.name || item.ip || '—'}</div>
                        <div class="text-[10px] text-slate-400 truncate">${label} · ${item.source}${sub ? ' · ' + sub : ''}</div>
                    </div>
                </div>`;
            }).join('');

            const more = d.total > 12 ? `<p class="text-[10px] text-slate-400 px-2 pt-1 border-t border-slate-100">${d.total - 12} more — narrow your search</p>` : '';
            dropdown.innerHTML = rows + more;
        } catch (err) {
            dropdown.innerHTML = `<p class="text-xs text-red-400 px-2 py-1">Error: ${err.message}</p>`;
        }
    }, 300);
}

function openSearchResult(item) {
    const inp = document.getElementById('global-search');
    const dd  = document.getElementById('search-results');
    if (inp) inp.value = '';
    if (dd)  { dd.classList.add('hidden'); dd.innerHTML = ''; }
    showDeviceDashboard(item);
}

async function showDeviceDashboard(item) {
    document.getElementById('device-dashboard-modal')?.remove();

    const modal = document.createElement('div');
    modal.id = 'device-dashboard-modal';
    modal.className = 'fixed inset-0 bg-black/50 flex items-start justify-center z-50 pt-12 overflow-y-auto';

    const panel = document.createElement('div');
    panel.className = 'bg-white rounded-xl shadow-2xl w-full max-w-3xl mx-4 mb-12';
    panel.innerHTML = `
        <div class="flex items-center justify-between px-6 py-4 border-b border-slate-100">
            <div>
                <p class="text-xs text-slate-400 uppercase font-bold tracking-widest mb-0.5">Device Dashboard</p>
                <p class="text-base font-bold text-[#263040] font-mono" id="dd-identity">Searching…</p>
            </div>
            <button class="dd-close text-slate-400 hover:text-slate-600 text-2xl leading-none">&times;</button>
        </div>
        <div id="dd-body" class="p-6 grid grid-cols-1 gap-4">
            <p class="text-sm text-slate-400 italic col-span-full">Loading data from all modules…</p>
        </div>`;
    modal.appendChild(panel);
    modal.addEventListener('click', e => { if (e.target === modal) modal.remove(); });
    panel.querySelector('.dd-close').addEventListener('click', () => modal.remove());
    document.body.appendChild(modal);

    const params = new URLSearchParams();
    if (item.mac)  params.set('mac', item.mac);
    if (item.ip)   params.set('ip', item.ip);
    const nameAsHostname = !item.mac && !item.ip && item.name;
    if (nameAsHostname) params.set('hostname', item.name);

    try {
        const r = await fetch(`/api/device-detail?${params}`);
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const d = await r.json();

        const id = d.identity || {};
        const identParts = [id.mac, id.ip, id.hostname].filter(Boolean);
        document.getElementById('dd-identity').textContent = identParts.join('  ·  ') || item.name || '—';

        const badge = (label, cls) => `<span class="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase ${cls}">${label}</span>`;
        const row = (label, val) => val ? `<div class="flex justify-between text-xs py-1 border-b border-slate-50"><span class="text-slate-400">${label}</span><span class="font-medium text-slate-700 font-mono">${val}</span></div>` : '';

        const card = (title, color, content) => `
            <div class="rounded-lg border border-slate-100 overflow-hidden">
                <div class="px-4 py-2 ${color} flex items-center gap-2">
                    <span class="text-xs font-bold uppercase tracking-wide">${title}</span>
                </div>
                <div class="px-4 py-3">${content}</div>
            </div>`;

        const empty = '<p class="text-xs text-slate-400 italic">No data from this module.</p>';
        const cards = [];

        // NAC / ClearPass
        const nac = d.nac;
        if (nac) {
            const statusCls = nac.status_val === 'Known' ? 'bg-green-100 text-green-700' : nac.status_val === 'Unknown' ? 'bg-amber-100 text-amber-700' : 'bg-slate-100 text-slate-500';
            const sessCount = (nac.sessions || []).length;
            cards.push(card('ClearPass NAC', 'bg-purple-50 text-purple-700', `
                ${nac.status_val ? badge(nac.status_val, statusCls) : ''}
                <div class="mt-2">
                    ${row('Vendor', nac.device_vendor)}
                    ${row('OS', nac.device_os)}
                    ${row('Type', nac.device_type)}
                    ${row('Description', nac.description)}
                    ${row('RADIUS Sessions', sessCount > 0 ? `${sessCount} found` : 'None')}
                </div>`));
        } else {
            cards.push(card('ClearPass NAC', 'bg-slate-50 text-slate-400', empty));
        }

        // DHCP
        const dhcp = d.dhcp;
        cards.push(card('DHCP', dhcp ? 'bg-blue-50 text-blue-700' : 'bg-slate-50 text-slate-400', dhcp ? `
            ${row('IP Address', dhcp.ip)}
            ${row('Hostname', dhcp.hostname !== 'unknown' ? dhcp.hostname : null)}
            ${row('MAC', dhcp.mac)}
            ${row('Lease Expires', dhcp.lease_end)}` : empty));

        // NetBox
        const nb = d.netbox || [];
        cards.push(card('NetBox', nb.length ? 'bg-green-50 text-green-700' : 'bg-slate-50 text-slate-400',
            nb.length ? nb.slice(0, 5).map(n => `
                <div class="text-xs py-1 border-b border-slate-50 last:border-0">
                    <span class="font-medium text-slate-700">${n.name || n.ip || '—'}</span>
                    <span class="text-slate-400 ml-2">${n.type || ''} ${n.ip ? '· ' + n.ip : ''}</span>
                </div>`).join('') : empty));

        // Proxmox
        const px = d.proxmox || [];
        cards.push(card('Proxmox', px.length ? 'bg-orange-50 text-orange-700' : 'bg-slate-50 text-slate-400',
            px.length ? px.slice(0, 3).map(v => `
                <div class="text-xs py-1 border-b border-slate-50 last:border-0">
                    <span class="font-medium text-slate-700">${v.name || '—'}</span>
                    <span class="text-slate-400 ml-2">${v.type || 'VM'} ${v.ip ? '· ' + v.ip : ''} ${v.cluster ? '· ' + v.cluster : ''}</span>
                </div>`).join('') : empty));

        // LDAP
        const ld = d.ldap || [];
        cards.push(card('Directory (LDAP)', ld.length ? 'bg-yellow-50 text-yellow-700' : 'bg-slate-50 text-slate-400',
            ld.length ? ld.slice(0, 3).map(u => `
                <div class="text-xs py-1 border-b border-slate-50 last:border-0">
                    <span class="font-medium text-slate-700">${u.name || u.dn || '—'}</span>
                    <span class="text-slate-400 ml-2">${u.type || ''}</span>
                </div>`).join('') : empty));

        document.getElementById('dd-body').innerHTML = `<div class="grid grid-cols-1 md:grid-cols-2 gap-4">${cards.join('')}</div>`;
    } catch (e) {
        const body = document.getElementById('dd-body');
        if (body) body.innerHTML = `<p class="text-sm text-red-400 italic">Error loading device data: ${e.message}</p>`;
    }
}

// Close dropdown when clicking outside
document.addEventListener('click', e => {
    const inp = document.getElementById('global-search');
    const dd  = document.getElementById('search-results');
    if (dd && inp && !inp.contains(e.target) && !dd.contains(e.target)) {
        dd.classList.add('hidden');
    }
});