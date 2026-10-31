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
// The rest of the app lives in WebUI/js/*.js: classic scripts loaded after this
// file by index.html (in the order listed there and in core/tests/webui_src.py).
// They share globals with this file. Only code that runs at load time is
// order-sensitive, which is why VIEW_LOADERS calls its loaders by name.
//
// Three fetch helpers are used (see the setupFetch JSDoc in
// js/reports-alerts-security.js for the full comparison):
//   fetch(url)        — public routes (no auth header, same-origin cookie only).
//   setupFetch(url)   — hub /setup/* + /api/* + /admin/* admin routes; adds
//                       JSON content-type + same-origin credentials.
//   csFetch(url)      — Simulations /sim/api/* routes (defined in sim-views.js);
//                       prepends /sim/api, injects tenant id, handles 401/404.
//
// Section index (names and files only — line numbers drift on every edit;
// grep the section or function name instead):
//   main.js:
//     Bug-report console capture (window.__lmBugBuffer ring buffer)
//     Global registries: MODULE_CLASSES, PRODUCT_MAP, VIEW_* registries
//     Auth helpers: isAdmin(), canSeeModule()
//     UI utilities: showToast(), fileBug(), submitBugReport()
//     refreshModuleCache() — per-module cache invalidation
//     updateStatus() + _updateMetrics/_applyHubHealth/_updateSpokeCount/
//            _rebuildMainNav/_renderDashboardLists + _renderSpokeAgentRow — the
//            periodic /status poll that drives dashboard tiles + sidebar lists
//     renderSpokeIndicators() — header status dots
//     Navigation: setView(), setSubView() + VIEW_LOADERS dispatch table
//   js/reports-alerts-security.js: setupFetch(), _renderLogsSection,
//          diagnostics & logs (loadRecoveryLogs, loadBugReports, showBugReport)
//   js/settings.js: _renderSettingsSection and the Settings tiles (OS Updates…)
//   js/sync-sources.js: _renderSetupSection (+ SETUP_TILES), Setup →
//          Simulations admin overview, setup data loaders (cache, firewalls)
//   js/fleet-admin.js: spokes/agents, users, loadModuleLogs, generic agents &
//          roles (loadApprovedSpokes, fetchLoadedRoles, showLoadRoleModal,
//          loadRole), OPNsense management (loadOpnsenseManagement)
//   js/nw.js, js/pxmx-console.js (loadPxmxData), js/netbox.js (loadNetboxData)
//   js/dns-dhcp-cluster.js: DNS (loadDNSData), clustered DNS / HA DHCP panels
//   js/certificates.js: certificate management (le), DNS record modals
//   js/external-dns-dhcp.js: DHCP (loadDHCPData + reservation modal), external DNS
//   js/cppm-ldap-users.js: CPPM/NAC (loadCPPMNACStatus, loadCPPMData, claim),
//          OPNsense add/edit modals + submit handlers, LDAP (loadLDAPData),
//          user/firewall modals (showAddUserModal, showAddFirewallModal)
//   js/module-management.js: instances (loadInstances, showAddInstanceModal),
//          Appearance (loadAppearance, saveAppearance), DOMContentLoaded startup
//   js/dashboard-search-login.js: Dashboard (loadAllTenantsOverview,
//          loadDashboardSummary, showDeviceDashboard); sets window.lmCoreLoaded
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
    // ── Real-time DHCP → DNS hook (System → Sync; global_config.dhcp_dns_hook) ──
    loadDnsHookConfig:         { m: 'GET',  p: '/setup/config',                    api: 'get_global_config' },
    saveDnsHookConfig:         { m: 'POST', p: '/setup/config',                    api: 'update_global_config' },

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

    // ── Console discovery sync (Console auto-identify → NetBox devices) ──
    loadConsoleNetboxSync:   { m: 'GET',  p: '/setup/console-netbox-sync',        api: 'get_console_netbox_sync' },
    saveConsoleNetboxSync:   { m: 'POST', p: '/setup/console-netbox-sync',        api: 'set_console_netbox_sync' },
    loadConsoleNetboxStatus: { m: 'GET',  p: '/setup/console-netbox-sync/status', api: 'console_netbox_sync_status' },

    // ── NetBox staleness sweep (cluster-wide; System → Sync) ──
    loadStalenessSweepConfig: { m: 'GET',  p: '/setup/config',                  api: 'get_global_config' },
    loadStalenessSweepStatus: { m: 'GET',  p: '/setup/staleness-sweep/status',  api: 'staleness_sweep_status' },
    runStalenessSweepNow:     { m: 'POST', p: '/setup/staleness-sweep/run',     api: 'run_staleness_sweep' },
    runNetboxDedupe:          { m: 'POST', p: '/setup/netbox-dedupe/run',        api: 'run_netbox_dedupe' },
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
    loadAlertDiagnostics:     { m: 'GET',  p: '/setup/alert-diagnostics',       api: 'alert_diagnostics' },

    // ── Source-of-truth per module (System → Sync; saved via /setup/config) ──
    loadSourceOfTruthConfig:  { m: 'GET',  p: '/setup/config',              api: 'get_global_config' },
    saveSourceOfTruthConfig:  { m: 'POST', p: '/setup/config',              api: 'update_global_config' },

    // ── Network Devices management ──
    loadNwDevices:          { m: 'GET',  p: '/setup/nw-devices',          api: 'get_nw_devices' },
    loadNwData:             { m: 'GET',  p: '/api/nw/{devices|info|macs|arp|interfaces}', api: 'nw_list_devices/nw_get_device_data' },
    submitNwConfig:         { m: 'POST', p: '/api/nw/{deviceId}/config',  api: 'nw_run_config' },
    showAddNwDeviceModal:   { m: 'POST', p: '/setup/nw-devices',          api: 'add_nw_device', via: 'saveNwDevice' },

    // ── Cache / subnet-filter / diagnostics / logs ──
    loadCacheStatus:        { m: 'GET',  p: '/admin/cache/status',        api: 'admin_cache_status' },
    refreshCacheNamespace:  { m: 'POST', p: '/admin/cache/refresh',       api: 'admin_cache_refresh' },
    purgeAllCaches:         { m: 'POST', p: '/admin/cache/purge',         api: 'admin_purge_cache' },
    loadSubnetFilterToggles:{ m: 'GET',  p: '/admin/subnet-filter-config',api: 'get_subnet_filter_config' },
    loadSpokesAndAgents:    { m: 'GET',  p: '/setup/pending_spokes + /api/pxmx/agents + /setup/diagnostics', api: 'get_pending_spokes / get_pxmx_agents / get_diagnostics' },
    ensureSpokeEventsLoaded:{ m: 'GET',  p: '/setup/diagnostics/{spoke_id}', api: 'get_diagnostics_detail' },
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
    deleteBugReport:        { m: 'DELETE', p: '/setup/bug-reports/{rid}', api: 'delete_bug_report' },
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
    // Excel rack-layout importer (admin-only): upload+detect → map columns → commit.
    rackImportXlsx:         { m: 'POST', p: '/api/netbox/racks/import-xlsx',       api: 'netbox_rack_import_xlsx' },
    rackImportCommit:       { m: 'POST', p: '/api/netbox/racks/import-commit',     api: 'netbox_rack_import_commit' },
    showRackImportModal:    { modal: true, via: 'commitRackImport' },
    // Rack elevation view (front+rear like NetBox): GET render model.
    rackElevation:          { m: 'GET',  p: '/api/netbox/racks/{rack_id}/elevation', api: 'netbox_get_rack_elevation' },
    showRackElevationModal: { modal: true, via: 'showRackElevationModal' },

    // ── DNS / DHCP ──
    loadDNSData:            { m: 'GET',  p: '/api/dns/records',           api: 'dns_list_records' },
    showDnsRecordModal:     { m: 'POST', p: '/api/dns/record',            api: 'dns_add_record/dns_update_record', via: 'saveDnsRecord' }, // (modal)
    showDnsForwarderModal:  { m: 'POST', p: () => '/api/dns/forwarders' + _tenantQS(), api: 'dns_add_forwarder', via: 'saveDnsForwarder' }, // (modal; p is a thunk, NEVER invoke it here — ROUTES is a top-level const evaluated at load, before `let currentTenant` initializes, so calling _tenantQS() eagerly throws a TDZ ReferenceError that aborts main.js and takes the whole UI down. saveDnsForwarder() builds its own tenant-scoped URL at call time; this thunk exists only so the tenant-scoping invariant test can verify the endpoint carries _tenantQS())
    showDnsOverrideProfileModal:{ m: 'PUT|DELETE', p: '/api/dns/overrides/profile', api: 'dns_override_profile_set/delete (admin)', via: 'saveDnsOverrideProfile' }, // (modal)
    showDnsOverrideAssignModal:{ m: 'POST|DELETE', p: '/api/dns/override-assignment', api: 'dns_override_assign/unassign', via: 'saveDnsOverrideAssignment' }, // (modal)
    loadDnsOverrideLiveCheck:{ m: 'GET', p: '/api/dns/overrides/verify', api: 'dns_overrides_verify' },
    loadDHCPData:           { m: 'GET',  p: '/api/dhcp/{subnets|leases|reservations}', api: 'dhcp_list_subnets/dhcp_list_leases/dhcp_list_reservations' },
    showDhcpReservationModal:{ m: 'GET', p: '/api/dhcp/subnets',          api: 'dhcp_list_subnets', via: '_loadDhcpSubnetOptions' }, // (modal)

    // ── CPPM / NAC ──
    loadCPPMNACStatus:      { m: 'GET',  p: '/api/cppm/nac-status',       api: 'get_cppm_nac_status' },
    loadCPPMData:           { m: 'GET',  p: '/api/cppm/{sessions|devices|unknown-devices|my-users}', api: 'get_cppm_sessions/get_cppm_devices/get_cppm_unknown_devices/list_my_users' },
    showCPPMDeviceDetail:   { m: 'GET',  p: '/api/cppm/{device-enrich|device-sessions}', api: 'get_cppm_device_enrich/get_cppm_device_sessions' },
    showClaimDeviceModal:   { m: 'GET',  p: '/api/netbox/claim-device/options', api: 'netbox_claim_device_options' },
    submitClaimDevice:      { m: 'POST', p: '/api/netbox/claim-device',   api: 'netbox_claim_device' },

    // ── Directory (LDAP/Entra) — tenant-scoped (tenant_slug server-injected) ──
    loadLDAPData:           { m: 'GET',  p: '/api/ldap/{users|groups}?tenant=', api: 'get_ldap_users/get_ldap_groups' },
    ensureLDAPTenants:      { m: 'GET',  p: '/api/ldap/tenants',              api: 'ldap_tenants' },
    showLDAPModal:          { m: 'POST|PUT', p: '/api/ldap/{users|groups}',   api: 'create/update_ldap_user, create_ldap_group', via: 'saveLDAPUser/saveLDAPGroup' }, // (modal)
    showLDAPMembersModal:   { m: 'POST|DELETE', p: '/api/ldap/groups/members', api: 'add/remove_ldap_member', via: 'addLDAPMember/removeLDAPMember' }, // (modal)
    showLDAPPasswordModal:  { m: 'POST', p: '/api/ldap/users/password',       api: 'set_ldap_user_password (local only)', via: 'changeUserPassword' }, // (modal)

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
    decommissionSpoke:     { m: 'POST', p: '/setup/spokes/{spokeId}/decommission',           api: 'decommission_spoke' },
    restoreSpoke:          { m: 'POST', p: '/setup/spokes/{spokeId}/restore',               api: 'restore_spoke' },
    resetSpokeSecret:       { m: 'POST', p: '/setup/spokes/{spokeId}/reset-secret',          api: 'reset_spoke_secret' },
    openSpokeMetadataModal: { m: 'GET',  p: '/setup/spoke-metadata/{spokeId}',               api: 'get_spoke_metadata' }, // (modal)
    saveSpokeMetadata:      { m: 'POST', p: '/setup/spoke-metadata',                         api: 'update_spoke_metadata',
                              m2: 'POST', p2: '/setup/spoke-name',                          api2: 'rename_spoke' },
    openSpokeAssignModal:   { m: 'GET',  p: '/setup/tenants',                                api: 'get_tenants' }, // (modal)
    saveSpokeAssign:        { m: 'POST', p: '/setup/approve_spoke',                          api: 'approve_spoke' },
    approveAgent:           { m: 'POST', p: '/setup/spokes/{spokeId}/agents/{agentId}/approve', api: 'approve_agent_under_spoke',
                              m2: 'GET', p2: '/api/pxmx/agents',                              api2: 'get_pxmx_agents' }, // resolves the agent's real owning spoke first (hypervisor OR simulation)
    revokeAgent:            { m: 'POST', p: '/api/pxmx/agents/{agentId}/revoke',             api: 'revoke_pxmx_agent' },
    openAgentConfigModal:   { m: 'GET',  p: '/api/pxmx/agents/{agentId}/config',             api: 'get_pxmx_agent_config',
                              m2: 'GET', p2: '/setup/tenants',                               api2: 'get_tenants' }, // (modal)
    saveAgentConfig:        { m: 'POST', p: '/api/pxmx/agents/{agentId}/config',             api: 'set_pxmx_agent_config' },
    openAgentAssignModal:   { m: 'GET',  p: '/api/pxmx/agents/{agentId}/config',             api: 'get_pxmx_agent_config',
                              m2: 'GET', p2: '/setup/tenants',                               api2: 'get_tenants' }, // (modal) dedicated Tenant button
    saveAgentTenant:        { m: 'POST', p: '/api/pxmx/agents/{agentId}/config',             api: 'set_pxmx_agent_config' },
    deleteAgent:            { m: 'DELETE', p: '/api/pxmx/agents/{agentId}',                  api: 'delete_pxmx_agent' },
    decommissionAgent:     { m: 'POST', p: '/api/pxmx/agents/{agentId}/decommission',        api: 'decommission_pxmx_agent' },
    restoreAgent:          { m: 'POST', p: '/api/pxmx/agents/{agentId}/restore',             api: 'restore_pxmx_agent' },

    // ── Tenants / users / sessions ──
    setTenant:              { m: 'POST', p: '/setup/tenant',                                 api: 'update_tenant' },
    editTenant:             { m: 'GET',  p: '/setup/tenants/{tenantId}',                     api: 'get_tenant_details' }, // (modal) form-save via saveTenantConfig
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
    toggleDebugLogging:     { m: 'GET',  p: '/setup/debug-mode',                             api: 'get_debug_mode',
                              m2: 'POST', p2: '/setup/debug-mode',                           api2: 'toggle_debug_mode' },
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

    // ── Directory (LDAP/Entra) CRUD ──
    saveLDAPUser:           { m: 'POST|PUT', p: '/api/ldap/users',                           api: 'create_ldap_user/update_ldap_user' }, // PUT when editing
    saveLDAPGroup:          { m: 'POST', p: '/api/ldap/groups',                              api: 'create_ldap_group' },
    deleteLDAPUser:         { m: 'DELETE', p: '/api/ldap/users',                             api: 'delete_ldap_user' },
    deleteLDAPGroup:        { m: 'DELETE', p: '/api/ldap/groups',                            api: 'delete_ldap_group' },
    changeUserPassword:     { m: 'POST', p: '/api/ldap/users/password',                      api: 'set_ldap_user_password (local only)' },

    // ── OPNsense delete ──
    deleteOpnsenseItem:     { m: 'DELETE', p: '/api/firewall/{fwId}/{rules|aliases|nat|dns}/{id}', api: 'delete_firewall_rule/delete_firewall_alias/delete_nat_rule/delete_dns_record' },

    // ── Proxmox ──
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
    // Chrome's "ResizeObserver loop completed with undelivered notifications."
    // is a benign frame-deferral notice, not a fault — keep it out of the
    // captured buffer so it can't dominate a bug report's console log.
    window.addEventListener('error', e => {
        if (/resizeobserver loop/i.test(String((e && e.message) || ''))) return;
        push('error', [e.message + ' (' + (e.filename || '') + ':' + (e.lineno || 0) + ')']);
    });
    window.addEventListener('unhandledrejection', e => push('error', ['Unhandled rejection: ' + (e.reason && e.reason.stack ? e.reason.stack : String(e.reason))]));
})();

const MODULE_CLASSES = {
    'Hypervisors': ['pxmx', 'kvm', 'vmware', 'utm'],
    'Firewalls': ['opnsense', 'pfsense', 'juniper', 'fortigate'],
    'IPAM': ['netbox', 'phpipam'],
    'NAC': ['cppm', 'ise'],
    'DNS': ['dns', 'henet'],
    'DHCP': ['dhcp'],
    'Network': ['nw'],
    'Simulations': ['cs'],
    'Certificates': ['le'],
    'Storage': ['truenas'],
    'Console': ['console']
};

// Multi-product classes that render ONE unified primary view, surfacing the
// other products as subtabs instead of as separate nav items. DNS is "all
// things DNS": the Unbound `dns` view (Overview/Records/Forwarders) plus an
// External DNS subtab (internet-facing providers like HE.NET). Such products
// have no standalone view — they always live under the `dns` view. See setView().
const CLASS_PRIMARY_VIEW = { 'DNS': 'dns' };

// Header module label: maps the active view/product to the nav class name shown
// in the header (Logo | Lab Manager | <Module>). e.g. opnsense -> 'Firewalls',
// cs -> 'Simulations'. Standalone views get an explicit label below.
const PRODUCT_LABEL = {};
for (const _cls of Object.keys(MODULE_CLASSES)) {
    for (const _p of MODULE_CLASSES[_cls]) PRODUCT_LABEL[_p] = _cls;
}
const VIEW_LABEL = {
    dashboard: 'Dashboard', setup: 'Setup', settings: 'System', logs: 'Logs', ldap: 'Directory', bugs: 'Bug Report', features: 'Feature Request', templates: 'Template Repo',
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

// Reload the active view's data — the footer "↻ Refresh" button (present on
// every view) calls this. Re-runs the current view's loader via the same
// dispatch setView/initView uses, so one footer button replaces the scattered
// per-page ↻ Refresh buttons AND the floating bottom-right FAB (which
// overlapped this footer). cs gets force=true to bypass the auto-refresh
// throttle, matching the former FAB.
function refreshCurrentView() {
    _lmNavSeq++;
    if (currentView === 'cs') {
        loadCSData(currentSubView, currentSubChild, true);
        return;
    }
    initView(currentView, currentSubView);
}

// Page-context actions rendered into the persistent footer slot rather than
// the page body (keeps the content frame clear). The global "↻ Refresh"
// (reload the current view) + "Update" (hub + spokes) actions live here —
// visible on every view; Update is admin-only, gated by isAdmin() and
// enforced server-side (POST /setup/update requires admin → 403 otherwise).
// The Firewalls page also puts its "Refresh Cache" button here (a different
// action — refreshes the opnsense module's remote cache, not the page).
function updateContextActions() {
    const fa = document.getElementById('footer-actions');
    if (!fa) return;
    const parts = [];
    parts.push(`<button onclick="refreshCurrentView()" title="Refresh this view" class="text-[10px] uppercase tracking-widest opacity-80 hover:opacity-100 border border-slate-500 hover:border-white px-2 py-0.5 rounded transition-all">↻ Refresh</button>`);
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
    'dns':        { name: 'DNS Management',  desc: 'Coordinator-only management spoke. Does not install or run Unbound locally; deploy "DNS Server" on each resolver worker, then configure those members here.', deploy: false },
    'henet':      { name: 'HE.NET (Hurricane Electric public DNS)', desc: 'Manages public DNS records at dns.he.net over HE\'s dynamic-DNS update API. No server to deploy — the account login credential (shared with certificates, DNS → "Hurricane Electric (account login)") powers Import/Sync (reading the zone); pushing a record\'s IP needs THAT record\'s own per-record DDNS key, entered when you add or edit it.', deploy: false },
    'dns-server': { name: 'DNS Server (Unbound)', desc: 'Deploys Unbound itself (server + remote-control + conf.d include). Runs as its own service on this host; does NOT create a spoke. Load "DNS Management" to manage it.', deploy: true },
    'dhcp':       { name: 'DHCP Management', desc: 'Coordinator-only management spoke. Does not install or run Kea locally; deploy "DHCP Server" on each Kea worker, then configure the HA pair here.', deploy: false },
    'dhcp-server':{ name: 'DHCP Server (Kea)', desc: 'Deploys Kea itself (kea-dhcp4-server + kea-ctrl-agent on :8001). Runs as its own service on this host; does NOT create a spoke. Load "DHCP Management" to manage it.', deploy: true },
    'network':    { name: 'Network Devices (nw)',  desc: 'Polls fleet switches for ARP/MAC topology and syncs device/MAC/ARP data into NetBox.', deploy: false },
    'netbox':     { name: 'IPAM/DCIM (NetBox)',    desc: 'Source-of-truth for sites, racks, devices, prefixes, IPs, VMs, tenants. Sinks every discovery sync and runs the NetBox→Kea DHCP scope sync. This is the API MODULE — it needs a running NetBox server (deploy the "NetBox Server" role, then point this module\'s connection settings at it).', deploy: false },
    'netbox-server': { name: 'NetBox Server', desc: 'Deploys the NetBox application itself — PostgreSQL, Redis, gunicorn, and nginx serving the WebUI on port 80. Runs as its own service on this host; does NOT create a spoke. Load the "IPAM/DCIM (NetBox)" module role to talk to it.', deploy: true },
    'opnsense':   { name: 'Firewall (OPNsense)',   desc: 'Manages an OPNsense firewall — aliases, filter/NAT rules, Unbound DNS, DHCP leases, ARP. Syncs DHCP/ARP into NetBox.', deploy: false },
    'ldap':       { name: 'Directory (LDAP)',      desc: 'Wraps an LDAP directory for identity/group lookups.', deploy: false },
    'ldap-server': { name: 'LDAP Server (OpenLDAP)', desc: 'Deploys OpenLDAP itself (slapd + ldaps). Joins the directory set in Setup → Directory (LDAP) and replicates with the other LDAP servers automatically. Runs as its own service on this host; does NOT create a spoke. Entra creds are sourced from the hub OIDC config automatically.', deploy: true },
    'simulation': { name: 'Client Simulator (cs)', desc: 'Client-sim engine, client registry, USB auto-provisioning relay, per-client override control panel, and the DHCP/client API for the isolated sim-client network.', deploy: false },
    'cppm':       { name: 'NAC (Aruba ClearPass)', desc: 'Syncs ClearPass sessions/endpoints (by-MAC / by-IP) into NetBox.', deploy: false },
    'proxmox':    { name: 'Hypervisor (Proxmox / pxmx)', desc: 'Proxmox spoke bridging the hub to per-host pxmx agents (VM lifecycle, VNC console, USB auto-provisioning).', deploy: false },
    'le':         { name: 'Certificate Management (Let\'s Encrypt)', desc: 'Issues/renews prod Let\'s Encrypt certs via certbot (HTTP-01 / DNS-01) and serves them to the hub for distribution to target spokes (e.g. OPNsense). Installs certbot + DNS-01 plugins.', deploy: false },
    'console':    { name: 'Console Server', desc: 'Serial console access to attached hardware (USB adapters + on-board UART). Auto-detects baud, auto-identifies devices, and relays an xterm.js terminal through the hub.', deploy: false },
    'truenas':    { name: 'Storage (TrueNAS)', desc: 'Polls and manages TrueNAS appliances over the official WebSocket JSON-RPC client — pools, datasets, shares (SMB/NFS), disks, alerts, services, capacity; gated management actions (create/delete datasets, create shares, take snapshots, run scrubs). Reports health + capacity and syncs into NetBox.', deploy: false },
    'statuspage': { name: 'Simulation Status Page', desc: 'Public, read-only status page for one tenant — cloud-provider style (overall banner, per-component status, 90-day uptime history) plus a Clients view whose demo dropdown lets visitors trigger a live 2h simulation. Bind it to a tenant; the hub pushes that tenant\'s redacted dashboard down. Serves its own HTTPS page (cert via the le role).', deploy: false },
    'proxy':      { name: 'Edge Proxy (per-tenant front door)', desc: 'Serves a local :443 WebUI front door with an LE server cert (no client-cert prompt) and reverse-proxies every request to the hub over mTLS. A dumb forwarding edge — all logic stays on the hub. Also load the "Certificate Management (Let\'s Encrypt)" role on this host so it can obtain/serve its HTTPS cert (proxy is a cert-distribution target).', deploy: false },
    'ab':   { name: 'AppBuilder', desc: 'Autonomous GitHub issue bot. Installs as a systemd service on this host and connects to the Hub as its own agent.', deploy: true },
};

// Roles that bind an inbound listener on the SAME host port. They CANNOT be
// stacked on one VM: whichever loads first wins the port and the others fail to
// bind (silently, on a retry loop) — the box then answers on the wrong service.
// Mirrors _LISTENER_PORT_ROLES in core/src/routes/agents.py, which is the
// authoritative check; this only keeps the UI from offering the broken combo.
const ROLE_LISTENER_PORTS = {
    'proxmox': 443,
    'simulation': 443,
    'proxy': 443,
    'statuspage': 443,
};

// The role among `roleIds` that would fight `candidate` for a port, else null.
function roleListenerConflict(roleIds, candidate) {
    const port = ROLE_LISTENER_PORTS[candidate];
    if (!port) return null;
    for (const other of (roleIds || [])) {
        if (other !== candidate && ROLE_LISTENER_PORTS[other] === port) return other;
    }
    return null;
}

function roleListenerConflictText(candidate, other) {
    const port = ROLE_LISTENER_PORTS[candidate];
    const name = id => (AGENT_ROLES[id] || {}).name || id;
    return `Conflicts with ${name(other)} — both bind port ${port} on this host. `
         + `Only one can own the port, so put ${name(candidate)} on a separate VM `
         + `or unload ${name(other)} first.`;
}

// Spoke UUID → friendly name, for the many places that render a spoke-keyed
// map. `spokeHealth` is the same map the header tray uses (/setup/diagnostics
// lists every approved spoke, including offline ones). Falls back to the raw id
// when the map isn't loaded yet, so a name never renders as "undefined".
function spokeDisplayName(spokeId) {
    const h = (window.spokeHealth || {})[spokeId];
    return (h && h.name && h.name !== spokeId) ? h.name : spokeId;
}

const PRODUCT_MAP = {
    'pxmx': 'pxmx',
    'opn': 'opnsense',
    'opnsense': 'opnsense',
    'cs': 'cs',
    'cppm': 'cppm',
    'netbox': 'netbox',
    'dns': 'dns',
    'henet': 'henet',
    'dhcp': 'dhcp',
    'nw': 'nw',
    'le': 'le',
    'console': 'console',
    'truenas': 'truenas',
};

// module_type -> nav product. A spoke's REGISTERED module_type is the
// authoritative signal that a module is actually loaded: a generic node
// (module_type "agent") with no role loaded must NOT light a product nav item
// even when its NAME resembles a product (e.g. an agent named "lm-opnsense").
// Only a real module spoke (module_type "firewall" / "dns" / ...) or a loaded
// role sub-spoke ("{base}-{role}", module_type = the role's) maps to a product.
// "agent" / "qa" have no product. "directory" (LDAP) maps to the 'ldap' product
// so a loaded directory spoke registers in activeProducts and lights the
// standalone "Directory" nav item (see _directoryNavHtml). It is NOT a
// MODULE_CLASSES class — it's a standalone view reached via setView('ldap').
const MODULE_TYPE_PRODUCT = {
    hypervisor: 'pxmx',
    firewall: 'opnsense',
    nac: 'cppm',
    simulation: 'cs',
    ipam: 'netbox',
    dns: 'dns',
    henet: 'henet',
    dhcp: 'dhcp',
    nw: 'nw',
    certificates: 'le',
    console: 'console',
    directory: 'ldap',
    storage: 'truenas',
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
    dns: 'dns', dhcp: 'dhcp', nw: 'nw', le: 'le', truenas: 'truenas',
    henet: 'henet',
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
    'cppm': 'NAC Logs',
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
// For a three-tier nav (Settings → Cloud → Azure/OCI → SSO/NSG/…), the active
// grandchild tab within the current child. '' when the current child has no
// grandchildren (see VIEW_GRANDCHILDREN).
let currentSubGrandchild = '';
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

function _consoleTenantQuery() {
    // The Credential Library follows the tenant picker for BOTH roles. A tenant
    // Admin is always scoped to an owned tenant (as with _taTenantQuery). A
    // Global Admin who has a specific tenant selected must see THAT tenant's
    // console logins — those live in the per-tenant vault bucket, not the shared
    // __admin__ slot — so send the tenant explicitly. The "all tenants" pick
    // (or none) sends nothing, so the hub returns the fleet-wide inventory.
    const t = currentTenant || '';
    if (!t || t === 'all' || t === '__all__') return '';
    return `?tenant=${encodeURIComponent(t)}`;
}

function hasConsoleWrite() {
    const p = currentUser?.permissions || {};
    return isAdmin() || isTenantAdmin() || p.console_write === true;
}

// Console VIEW tier: admin, tenant-admin, or any `console` user. Profiling
// (Profile Device / Profile All) is read-only device identification, so it is
// gated here — NOT at the write tier — matching the server's has_console_access
// guard on /api/console/identify-llm[-all] and the per-port tenant confinement.
function hasConsoleView() {
    const p = currentUser?.permissions || {};
    return isAdmin() || isTenantAdmin() || p.console === true;
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
let _lmActiveFetchCount = 0;
const _lmActiveFetchListeners = new Set();
function _lmNotifyFetchState() {
    for (const fn of _lmActiveFetchListeners) {
        try { fn(_lmActiveFetchCount); } catch (_) {}
    }
}
function _lmOnFetchCountChange(fn) {
    _lmActiveFetchListeners.add(fn);
    return () => _lmActiveFetchListeners.delete(fn);
}

// Navigation counter, bumped by every view/tab change (setView, setSubView,
// setSubChild, setSubGrandchild, refreshCurrentView). Page loaders render
// whatever their fetch returns into the page, so a slow response for a tab the
// user already left would paint over the tab they moved to. lmFetch drops such
// responses instead: the promise never settles, so the old loader just stops.
// 0 = before the first view render; boot-time requests are never dropped.
let _lmNavSeq = 0;

// True for a page read (GET) that started before the user's latest navigation.
// Background polls, boot-time requests and callers that pass
// `_keepOnNavigate: true` (downloads, shared state) always complete.
function _lmLeftPageSince(navAtStart, input, init) {
    if (navAtStart === 0 || navAtStart === _lmNavSeq) return false;
    if (init && init._keepOnNavigate) return false;
    const method = (init && init.method) || (input && input.method) || 'GET';
    return method.toUpperCase() === 'GET';
}

window.fetch = async function lmFetch(input, init) {
    const navAtStart = _lmNavSeq;
    let isBg = false;
    try {
        if (init && init._background) isBg = true;
        const u = typeof input === 'string' ? input : (input && input.url) || '';
        if (u.indexOf('/api/notifications/poll') !== -1 ||
            u.indexOf('/api/events/poll') !== -1 ||
            u.indexOf('/api/le/inflight') !== -1 ||
            u.indexOf('/api/health') !== -1) {
            isBg = true;
        }
    } catch (_) {}

    if (!isBg) {
        _lmActiveFetchCount++;
        _lmNotifyFetchState();
    }

    let res;
    try {
        res = await _lmOrigFetch(input, init);
    } catch (err) {
        if (!isBg && _lmLeftPageSince(navAtStart, input, init)) return new Promise(() => {});
        throw err;
    } finally {
        if (!isBg) {
            _lmActiveFetchCount = Math.max(0, _lmActiveFetchCount - 1);
            _lmNotifyFetchState();
        }
    }
    if (res && res.status === 401 && currentUser && !_lmIsAuthSubmitEndpoint(input)) {
        handleSessionExpired();
        throw new Error('Session expired');
    }
    if (!isBg && _lmLeftPageSince(navAtStart, input, init)) return new Promise(() => {});
    return res;
};

// ── pollManager — visibility-aware recurring timers ─────────────────────────
// Central registry for the UI's polling/render timers. Every registered poll
// SUSPENDS while the tab is hidden (document.hidden) and RESUMES with an
// immediate tick when it becomes visible again, so background tabs stop
// hammering the hub and re-rendering the DOM. Use pollManager.register(fn, ms)
// instead of a raw setInterval for any recurring poll; keep the returned id
// and call pollManager.unregister(id) where you would have clearInterval'd.
const pollManager = (() => {
    const polls = new Map();   // id -> { fn, ms, timer }
    let seq = 0;
    const start = p => { if (p.timer == null) p.timer = setInterval(p.fn, p.ms); };
    const stop = p => { if (p.timer != null) { clearInterval(p.timer); p.timer = null; } };
    document.addEventListener('visibilitychange', () => {
        if (document.hidden) {
            polls.forEach(stop);
        } else {
            polls.forEach(p => {
                try { p.fn(); } catch (e) { console.error('pollManager: resume tick failed', e); }
                start(p);
            });
        }
    });
    return {
        register(fn, ms) {
            const id = ++seq;
            const p = { fn, ms, timer: null };
            polls.set(id, p);
            if (!document.hidden) start(p);
            return id;
        },
        unregister(id) {
            const p = polls.get(id);
            if (p) { stop(p); polls.delete(id); }
        },
    };
})();

// Module visibility: admins see every module; a non-admin sees a module only if
// granted its explicit right. Today only the Simulations (cs) module is gated
// this way; other modules remain product-driven (visible when their spoke is
// connected). Add a key here to gate another module the same way.
const MODULE_RIGHT = { 'Simulations': 'cs', 'Network': 'nw', 'IPAM': 'ipam', 'Certificates': 'le', 'Console': 'console', 'Firewalls': 'firewall', 'NAC': 'nac', 'DNS': 'dns', 'HE.NET': 'henet', 'DHCP': 'dhcp', 'Hypervisors': 'pxmx', 'Directory': 'ldap', 'Reports': 'reports' };
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

// Single fixed top-right toast container. Toasts append as flex-column
// children so the stack REFLOWS automatically when one is dismissed — no
// per-toast fixed top offsets (the old `1.5 + stack*4.0rem` math overlapped
// the moment a toast between two others was removed (stack count dropped) or
// a multi-line toast grew past the 4rem step). Mirrors the cs local UI's
// #cs-toast-region. Lazily created on first toast.
function _lmToastRegion() {
    let el = document.getElementById('lm-toast-region');
    if (!el) {
        el = document.createElement('div');
        el.id = 'lm-toast-region';
        el.style.cssText = 'position:fixed;top:1.5rem;right:1.5rem;z-index:9999;' +
            'display:flex;flex-direction:column;gap:.5rem;max-width:22rem;';
        document.body.appendChild(el);
    }
    return el;
}

// ─── API-field reveal + copy (admin tier) ───────────────────────────────────
// Adds an eye (show/hide) + copy button to every API-CREDENTIAL password input
// so an admin can view/copy a stored token/key. Auto-detects by id/name/
// placeholder (EXCLUDES user login/admin passwords), is idempotent, gated to the
// admin tier, and a MutationObserver picks up dynamically-rendered Setup forms.
// Opt a field out with data-no-api-reveal="1"; force one in with data-api-field.
const _API_FIELD_RE = /(api|token|secret|apikey|access[-_ ]?key|client[-_ ]?secret|bearer|psk|credential|passphrase)/i;
const _API_FIELD_EXCLUDE = /(login|sign[-_ ]?in|confirm|current[-_ ]?pass|new[-_ ]?pass|admin[-_ ]?pass)/i;
const _EYE_SVG = '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7z"/><circle cx="12" cy="12" r="3"/></svg>';
const _EYE_OFF_SVG = '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.9 17.9A10.9 10.9 0 0 1 12 20C5 20 1 12 1 12a18.5 18.5 0 0 1 5.1-6M9.9 4.2A10.9 10.9 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.2 3.2M1 1l22 22"/></svg>';
const _COPY_SVG = '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';

function _isApiSecretInput(el) {
    if (!el || el.tagName !== 'INPUT') return false;
    if ((el.getAttribute('type') || '').toLowerCase() !== 'password') return false;
    if (el.getAttribute('data-no-api-reveal') === '1') return false;
    if (el.hasAttribute('data-api-field')) return true;
    const hay = [el.id, el.name, el.getAttribute('placeholder'),
                 el.getAttribute('aria-label'), el.className].filter(Boolean).join(' ');
    if (_API_FIELD_EXCLUDE.test(hay)) return false;
    return _API_FIELD_RE.test(hay);
}

// Who gets the reveal/copy control: the ADMIN TIER — a Global Admin or a tenant
// Admin. It was Global-Admin-only, which left a tenant Admin unable to read back
// a credential on a form they are otherwise allowed to manage.
//
// Widening this grants no data the user does not already hold: the eye only
// re-types the input that is ALREADY in their browser's DOM (it fetches
// nothing), so anyone who can load the form can read the same value from
// devtools regardless. The real boundary stays server-side, where a tenant
// Admin is confined to their own tenants. User login / admin passwords remain
// excluded by _API_FIELD_EXCLUDE for both tiers.
function _canRevealApiFields() {
    if (typeof isAdmin === 'function' && isAdmin()) return true;
    if (typeof isTenantAdmin === 'function' && isTenantAdmin()) return true;
    return false;
}

function _enhanceApiField(el) {
    if (el.dataset.apiEnhanced === '1') return;
    // Admin tier only. Don't mark enhanced yet if perms haven't loaded — a later
    // observer tick (after /auth/me) re-checks and wires it then.
    if (!_canRevealApiFields()) return;
    el.dataset.apiEnhanced = '1';
    const wrap = document.createElement('span');
    wrap.style.cssText = 'position:relative;display:block;';
    el.parentNode.insertBefore(wrap, el);
    wrap.appendChild(el);
    // Room for the two 1.5rem buttons at the right edge.
    el.style.paddingRight = '3.6rem';
    const bar = document.createElement('span');
    bar.style.cssText = 'position:absolute;top:50%;right:.4rem;transform:translateY(-50%);display:inline-flex;gap:.1rem;z-index:2;';
    const mk = (title, html, fn) => {
        const b = document.createElement('button');
        b.type = 'button'; b.title = title; b.tabIndex = -1; b.innerHTML = html;
        b.style.cssText = 'display:inline-flex;align-items:center;justify-content:center;width:1.5rem;height:1.5rem;color:#64748b;background:transparent;border:none;cursor:pointer;border-radius:.25rem;padding:0;';
        b.addEventListener('mouseover', () => { b.style.color = '#0f172a'; });
        b.addEventListener('mouseout', () => { b.style.color = '#64748b'; });
        b.addEventListener('click', (e) => { e.preventDefault(); e.stopPropagation(); fn(b); });
        return b;
    };
    const eye = mk('Show / hide', _EYE_SVG, (b) => {
        const show = el.getAttribute('type') === 'password';
        el.setAttribute('type', show ? 'text' : 'password');
        b.innerHTML = show ? _EYE_OFF_SVG : _EYE_SVG;
    });
    const copy = mk('Copy', _COPY_SVG, async () => {
        const v = el.value || '';
        try {
            if (navigator.clipboard && navigator.clipboard.writeText) await navigator.clipboard.writeText(v);
            else { const t = el.getAttribute('type'); el.setAttribute('type', 'text'); el.select(); document.execCommand('copy'); el.setAttribute('type', t); }
            if (typeof showToast === 'function') showToast('Copied', 'success');
        } catch (err) { if (typeof showToast === 'function') showToast('Copy failed', 'error'); }
    });
    bar.appendChild(eye); bar.appendChild(copy);
    wrap.appendChild(bar);
}

function wireApiFieldControls(root) {
    try {
        (root || document).querySelectorAll('input[type="password"]').forEach((el) => {
            if (_isApiSecretInput(el)) _enhanceApiField(el);
        });
    } catch (e) { /* never break a render */ }
}

let _apiFieldObserver = null;
function startApiFieldObserver() {
    wireApiFieldControls(document);
    if (_apiFieldObserver || typeof MutationObserver === 'undefined') return;
    let pending = false;
    _apiFieldObserver = new MutationObserver(() => {
        if (pending) return;
        pending = true;
        setTimeout(() => { pending = false; wireApiFieldControls(document); }, 150);
    });
    try { _apiFieldObserver.observe(document.body, { childList: true, subtree: true }); } catch (e) { /* noop */ }
}

function showToast(message, type = 'success') {
    // Swallow transient connectivity-failure error toasts. These fire the moment
    // the hub blinks out for an update/restart (a view's fetch rejects with
    // "Failed to fetch" / "Load failed" / etc.) and are pure noise — the sticky
    // "an update or restart is in progress — please wait…" toast already explains
    // the outage. Real, actionable errors (with a real message) still show.
    //
    // Match the BARE browser error only (optionally behind an "Error: " prefix),
    // never a phrase buried inside a longer one. A server-reported failure
    // routinely quotes a connection error of its OWN: a 502 from the DHCP
    // module reads "Kea CA unreachable: ... [Errno 111] Connection refused".
    // An unanchored search swallowed precisely the error the operator needed,
    // so "Add Reservation" looked like a dead button — no toast, no clue, and
    // the click retried against a Kea that was never going to answer.
    if (type === 'error') {
        const bare = String(message || '').replace(/^\s*error:\s*/i, '').trim();
        if (/^(load failed|failed to fetch|networkerror\b.*|could not connect\b.*|connection refused|err_connection\w*|net::\w+)\.?$/i.test(bare)) {
            return;
        }
    }
    // Green for everything except errors (red) — no grey/info toasts.
    const colors = { success: '#01A982', error: '#e53e3e', info: '#01A982' };
    const toast = document.createElement('div');
    toast.className = 'lm-toast';
    // Appended to the shared #lm-toast-region flex column — the container
    // handles position + stacking; each toast just styles itself.
    toast.style.cssText = `
        display:flex;align-items:center;gap:.75rem;
        background:${colors[type] || colors.info};color:#fff;
        padding:.75rem 1rem .75rem 1.25rem;border-radius:.5rem;font-size:.875rem;
        box-shadow:0 4px 12px rgba(0,0,0,.2);opacity:0;
        transition:opacity .2s ease;width:100%;box-sizing:border-box;`;
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
    _lmToastRegion().appendChild(toast);
    requestAnimationFrame(() => { toast.style.opacity = '1'; });
    setTimeout(dismiss, window.TOAST_DURATION_MS || 10000);
}

// Sticky toast — like showToast but it NEVER auto-dismisses; the caller holds
// the returned handle and dismisses it explicitly (or updates its text in
// place). Used for "an update/restart is in progress — please wait" while the
// hub is unreachable, so the user gets the same reassuring in-flight message we
// show for the button-driven update, instead of a silent blank screen. Only one
// is ever shown at a time (updateStatus reuses the single handle).
function showStickyToast(message, type = 'info') {
    // Brand green (#01A982) for the informative "please wait" case, matching the
    // other success/info toasts — it's a reassurance message, not an error.
    const colors = { success: '#01A982', error: '#e53e3e', info: '#01A982' };
    const toast = document.createElement('div');
    toast.className = 'lm-toast';
    toast.style.cssText = `
        display:flex;align-items:center;gap:.75rem;
        background:${colors[type] || colors.info};color:#fff;
        padding:.75rem 1rem .75rem 1.25rem;border-radius:.5rem;font-size:.875rem;
        box-shadow:0 4px 12px rgba(0,0,0,.2);opacity:0;
        transition:opacity .2s ease;width:100%;box-sizing:border-box;`;
    const spinner = document.createElement('span');
    spinner.style.cssText = 'width:.9rem;height:.9rem;border:2px solid rgba(255,255,255,.4);' +
        'border-top-color:#fff;border-radius:50%;flex:none;animation:lm-spin .8s linear infinite;';
    toast.appendChild(spinner);
    if (!document.getElementById('lm-spin-kf')) {
        const st = document.createElement('style');
        st.id = 'lm-spin-kf';
        st.textContent = '@keyframes lm-spin{to{transform:rotate(360deg)}}';
        document.head.appendChild(st);
    }
    const text = document.createElement('span');
    text.style.cssText = 'flex:1;white-space:pre-line;';
    text.textContent = message;
    toast.appendChild(text);
    _lmToastRegion().appendChild(toast);
    requestAnimationFrame(() => { toast.style.opacity = '1'; });
    let removed = false;
    return {
        update(msg) { text.textContent = msg; },
        dismiss() {
            if (removed) return;
            removed = true;
            toast.style.opacity = '0';
            toast.addEventListener('transitionend', () => toast.remove());
        },
    };
}

// Lightweight "we heard you" feedback toast fired the instant an actionable
// control is clicked, BEFORE its (sometimes slow) handler runs. Purpose is
// pure reassurance: a user reported clicking a button, seeing nothing happen
// for a beat on a slow load, and clicking again — this gives immediate visual
// acknowledgement that the click landed and the system is working.
//
// It is deliberately short-lived (LOADING_TOAST_MS) and de-duplicated: rapid
// repeat clicks on the same thing refresh the one toast in place instead of
// stacking a column of identical messages. Installed globally by
// installClickFeedback(); individual controls opt OUT with [data-no-loading].
function _lmLoadingToastRegion() {
    let el = document.getElementById('lm-loading-toast-region');
    if (!el) {
        el = document.createElement('div');
        el.id = 'lm-loading-toast-region';
        el.style.cssText = 'position:fixed;bottom:3.5rem;right:1.5rem;z-index:10000;pointer-events:none;display:flex;flex-direction:column;align-items:flex-end;';
        document.body.appendChild(el);
    }
    return el;
}

let _lmLoadingToast = null;
function showLoadingToast(label) {
    const text = `Loading ${label}…`;
    if (_lmLoadingToast && _lmLoadingToast.label === label &&
        document.body.contains(_lmLoadingToast.el)) {
        clearTimeout(_lmLoadingToast.timer);
        _lmLoadingToast.timer = setTimeout(_dismissLoadingToast, window.LOADING_TOAST_MS || 15000);
        return;
    }
    _dismissLoadingToast();
    const toast = document.createElement('div');
    toast.className = 'lm-toast';
    toast.style.cssText = `
        display:flex;align-items:center;gap:.75rem;
        background:var(--hpe-navy, #263040);color:#fff;
        padding:.75rem 1rem .75rem 1.25rem;border-radius:.5rem;font-size:.875rem;
        box-shadow:0 4px 12px rgba(0,0,0,.2);opacity:0;
        transition:opacity .2s ease;width:100%;max-width:24rem;min-width:18rem;box-sizing:border-box;pointer-events:auto;`;
    const spinner = document.createElement('span');
    spinner.style.cssText = 'width:.9rem;height:.9rem;border:2px solid rgba(255,255,255,.4);' +
        'border-top-color:#fff;border-radius:50%;flex:none;animation:lm-spin .8s linear infinite;';
    if (!document.getElementById('lm-spin-kf')) {
        const st = document.createElement('style');
        st.id = 'lm-spin-kf';
        st.textContent = '@keyframes lm-spin{to{transform:rotate(360deg)}}';
        document.head.appendChild(st);
    }
    toast.appendChild(spinner);
    const span = document.createElement('span');
    span.style.cssText = 'flex:1;white-space:pre-line;';
    span.textContent = text;
    toast.appendChild(span);
    _lmLoadingToastRegion().appendChild(toast);
    requestAnimationFrame(() => { toast.style.opacity = '1'; });

    const openTime = Date.now();
    let listenerUnsub = null;
    let fallbackTimer = null;
    let safetyTimer = null;
    let graceTimer = null;

    const attemptDismiss = () => {
        if (_lmActiveFetchCount === 0) {
            const elapsed = Date.now() - openTime;
            const delay = Math.max(0, 400 - elapsed);
            if (!graceTimer) {
                graceTimer = setTimeout(() => {
                    if (_lmActiveFetchCount === 0) _dismissLoadingToast();
                    graceTimer = null;
                }, Math.max(delay, 200));
            }
        } else if (graceTimer) {
            clearTimeout(graceTimer);
            graceTimer = null;
        }
    };

    listenerUnsub = _lmOnFetchCountChange(attemptDismiss);
    fallbackTimer = setTimeout(attemptDismiss, 800);
    safetyTimer = setTimeout(_dismissLoadingToast, window.LOADING_TOAST_MS || 15000);

    _lmLoadingToast = {
        el: toast,
        label,
        timer: safetyTimer,
        cleanup: () => {
            if (listenerUnsub) listenerUnsub();
            if (fallbackTimer) clearTimeout(fallbackTimer);
            if (_lmLoadingToast && _lmLoadingToast.timer) clearTimeout(_lmLoadingToast.timer);
            if (graceTimer) clearTimeout(graceTimer);
        }
    };
}

function _dismissLoadingToast() {
    if (!_lmLoadingToast) return;
    const { el, cleanup } = _lmLoadingToast;
    if (cleanup) cleanup();
    _lmLoadingToast = null;
    if (!el || !document.body.contains(el)) return;
    el.style.opacity = '0';
    el.addEventListener('transitionend', () => el.remove());
}
window.dismissLoadingToast = _dismissLoadingToast;
window.showLoadingToast = showLoadingToast;

// Derive a short human label for the clicked control: an explicit override
// wins, then aria-label/title, then its own visible text (icon glyphs and
// runaway length trimmed). Returns '' when there is nothing meaningful to say.
function _loadingLabelFor(el) {
    let label = el.getAttribute('data-loading-label')
        || el.getAttribute('aria-label')
        || el.getAttribute('title')
        || (el.textContent || '');
    // Collapse whitespace and drop lone icon/glyph characters (Font Awesome
    // ligatures render as private-use glyphs; ×/✓/etc. carry no words).
    label = label.replace(/\s+/g, ' ').trim();
    label = label.replace(/[\u2000-\u3300\uE000-\uF8FF\uF000-\uFFFF]/g, '').trim();
    if (label.length > 40) label = label.slice(0, 39).trim() + '…';
    return label;
}

// A control we should NOT announce: dismissers, copy/reveal affordances,
// toggles, in-toast buttons, anything the page explicitly opts out, and
// disabled controls (their handler never runs).
const _NO_LOADING_TEXT = /^(×|✕|✓|close|dismiss|cancel|copy|copied|show|hide|expand|collapse|previous|next|prev|▲|▼|◀|▶|‹|›|«|»)$/i;
function _skipLoadingFeedback(el) {
    if (el.closest('[data-no-loading]')) return true;
    if (el.closest('#lm-toast-region')) return true;               // toast's own buttons
    if (el.disabled || el.getAttribute('aria-disabled') === 'true') return true;
    if (el.getAttribute('role') === 'switch') return true;         // toggle switches
    if (el.type === 'checkbox' || el.type === 'radio') return true;
    const aria = (el.getAttribute('aria-label') || '').trim();
    const txt = (el.textContent || '').replace(/\s+/g, ' ').trim();
    if (_NO_LOADING_TEXT.test(aria) || _NO_LOADING_TEXT.test(txt)) return true;
    return false;
}

// Global click-feedback: on ANY actionable control (buttons, nav items,
// role=button), pop the short "Loading …" toast immediately. Runs in the
// CAPTURE phase so it fires even when the real handler calls stopPropagation,
// and before that handler's (possibly slow) work begins. Installed once.
function installClickFeedback() {
    if (window._lmClickFeedbackInstalled) return;
    window._lmClickFeedbackInstalled = true;
    document.addEventListener('click', (e) => {
        if (window.LM_CLICK_FEEDBACK === false) return;   // runtime kill-switch
        const el = e.target.closest(
            'button, [role="button"], .nav-item, [data-loading-label]');
        if (!el) return;
        if (_skipLoadingFeedback(el)) return;
        const label = _loadingLabelFor(el);
        if (!label) return;
        try { showLoadingToast(label); } catch (_) { /* never block the click */ }
    }, true);
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
        toast.style.cssText = `
            display:flex;flex-direction:column;gap:.6rem;
            background:#263040;color:#fff;
            padding:.85rem 1rem;border-radius:.5rem;font-size:.875rem;
            box-shadow:0 4px 12px rgba(0,0,0,.25);opacity:0;
            transition:opacity .2s ease;width:100%;box-sizing:border-box;`;
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

        _lmToastRegion().appendChild(toast);
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
        toast.style.cssText = `
            display:flex;flex-direction:column;gap:.6rem;
            background:#263040;color:#fff;
            padding:.85rem 1rem;border-radius:.5rem;font-size:.875rem;
            box-shadow:0 4px 12px rgba(0,0,0,.25);opacity:0;
            transition:opacity .2s ease;width:100%;box-sizing:border-box;`;
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

        _lmToastRegion().appendChild(toast);
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
// [bug-report] marker and stores the full artifacts on disk; ab then
// files a (clean-body) GitHub issue and pulls the artifacts from the hub to use
// as AI-fix context. See plan bright-launching-thompson.md.
async function fileBug(prefill = '') {
    // One modal at a time. The footer "File a bug" button toggles the modal
    // closed on a second click; a `prefill` (e.g. from a log-line 🐞 button)
    // always reopens it fresh so the pre-filled text takes effect.
    const existing = document.getElementById('file-bug-modal');
    if (existing) { existing.remove(); if (!prefill) return; }

    const modal = document.createElement('div');
    modal.id = 'file-bug-modal';
    // Keep the report window itself out of the html2canvas screenshot so the
    // evidence shows the page being reported, not this dialog.
    modal.setAttribute('data-html2canvas-ignore', 'true');
    // z-[70] -- above BOTH a z-50 openModal() dialog and the z-[60] footer, so
    // the report window opens on top of whatever dialog the user is reporting
    // about rather than behind it (lm#487).
    modal.className = 'fixed inset-0 z-[70] flex items-center justify-center bg-black bg-opacity-50 backdrop-blur-sm';
    modal.innerHTML = `
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-2xl overflow-hidden max-h-[92vh] flex flex-col">
            <div class="px-6 py-4 border-b border-slate-200 flex justify-between items-center bg-slate-50">
                <h3 class="text-lg font-bold text-[#263040]">🐞 Bug / Feature Request</h3>
                <div class="flex items-center gap-3">
                    <button id="bug-mode-guided" onclick="bugUseGuided()" class="hidden text-xs font-semibold text-[#01A982] hover:underline">Guided assistant</button>
                    <button id="bug-mode-quick" onclick="bugUseQuickForm()" class="hidden text-xs font-semibold text-slate-500 hover:underline">Use quick form</button>
                    <button onclick="this.closest('#file-bug-modal').remove()" class="text-slate-400 hover:text-slate-600 transition-colors">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                    </button>
                </div>
            </div>
            <div id="bug-guided" class="hidden p-5 space-y-3 overflow-y-auto">
                <div class="flex items-center gap-2 text-xs text-slate-600">
                    <span class="font-bold uppercase text-slate-500">Type</span>
                    <button data-reqtype="bug" onclick="reqAsstSetType('bug')" class="req-asst-type px-3 py-1 rounded-full border">🐞 Bug</button>
                    <button data-reqtype="feature" onclick="reqAsstSetType('feature')" class="req-asst-type px-3 py-1 rounded-full border">💡 Feature</button>
                    <button data-reqtype="" onclick="reqAsstSetType('')" class="req-asst-type px-3 py-1 rounded-full border">Not sure</button>
                    <button onclick="reqAsstReset()" class="ml-auto text-slate-400 hover:text-slate-600">↺ Start over</button>
                </div>
                <div id="req-asst-log" class="h-72 overflow-y-auto bg-slate-50 border border-slate-200 rounded-lg p-3"></div>
                <div id="req-asst-choices" class="flex flex-wrap gap-2"></div>
                <div id="req-asst-checklist" class="text-[11px] leading-relaxed"></div>
                <div class="flex gap-2 items-end">
                    <textarea id="req-asst-input" rows="2" placeholder="Describe what went wrong, or what you'd like added…" class="flex-1 bg-white border border-slate-300 rounded-md px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"></textarea>
                    <button id="req-asst-send" onclick="reqAsstSend()" class="bg-[#01A982] hover:bg-[#019672] text-white px-4 py-2 rounded-md text-sm font-bold">Send</button>
                    <button id="req-asst-stop" onclick="reqAsstStop()" class="hidden bg-slate-200 hover:bg-slate-300 text-slate-700 px-4 py-2 rounded-md text-sm font-bold">Stop</button>
                </div>
                <p class="text-[11px] text-slate-400 leading-relaxed">
                    The assistant asks one question at a time and reads the code read-only to point at the likely area — it never changes anything.
                    When the report is complete, <b>File report</b> sends it (with your console log, page HTML and a screenshot) through the normal
                    pipeline: a <b>bug</b> is filed for AppBuilder to fix; a <b>feature request</b> waits for Global Admin approval.
                </p>
                <div id="req-asst-status" class="text-xs text-slate-500 hidden"></div>
                <div class="flex justify-end gap-3">
                    <button onclick="this.closest('#file-bug-modal').remove()" class="px-4 py-2 text-sm font-medium text-slate-600 hover:text-slate-800">Close</button>
                    <button id="req-asst-file" onclick="reqAsstFile()" disabled class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm disabled:opacity-40 disabled:cursor-not-allowed">File report</button>
                </div>
            </div>
            <div id="bug-quick" class="p-6 space-y-4 overflow-y-auto">
                <div id="bug-guided-note" class="hidden text-[11px] text-slate-400"></div>
                <div class="space-y-2">
                    <label class="text-xs text-slate-500 uppercase font-bold">Describe the bug or request <span class="text-red-500">*</span></label>
                    <textarea id="bug-description" rows="4" placeholder="Describe what went wrong, or what you'd like added — e.g. 'Clicked Save on the firewall rule form and the page went blank.' or 'Add a CSV export button to the device list.'" class="w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500"></textarea>
                </div>
                <div class="flex items-center gap-2">
                    <input type="checkbox" id="bug-is-feature" class="rounded border-slate-300 text-[#01A982] focus:ring-[#01A982]">
                    <label for="bug-is-feature" class="text-xs text-slate-600 select-none cursor-pointer">
                        This is a <b>feature request</b>, not a bug (something I'd like added or changed)
                    </label>
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
                    AppBuilder opens a GitHub issue from your explanation + context. For a <b>bug</b> it will also attempt a fix;
                    a <b>feature request</b> is filed as an enhancement for triage (no auto-fix). The console/HTML/screenshot
                    stay on the hub and are used only as fix context.
                </p>
                <div id="bug-submit-status" class="text-xs text-slate-500 hidden"></div>
                <div class="pt-2 flex justify-end gap-3">
                    <button onclick="this.closest('#file-bug-modal').remove()" class="px-4 py-2 text-sm font-medium text-slate-600 hover:text-slate-800">Cancel</button>
                    <button id="bug-submit-btn" onclick="submitBugReport()" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm">Submit</button>
                </div>
            </div>
        </div>`;
    document.body.appendChild(modal);
    // Pre-fill the textarea (via .value, not template content, so the raw text
    // — newlines and all — lands verbatim and stays user-editable).
    const _ta = document.getElementById('bug-description');
    if (_ta && prefill) _ta.value = prefill;
    const _gi = document.getElementById('req-asst-input');
    if (_gi && prefill) _gi.value = prefill;
    _gi?.addEventListener('keydown', (ev) => {
        if (ev.key === 'Enter' && !ev.shiftKey) { ev.preventDefault(); reqAsstSend(); }
    });
    setTimeout(() => {
        const t = document.getElementById('bug-description');
        t?.focus();
        // Drop the caret at the end so the user types their detail after the
        // pre-filled log context rather than in front of it.
        if (t && prefill) t.setSelectionRange(t.value.length, t.value.length);
    }, 50);
    // Switch to the guided assistant when AppBuilder offers it; the quick form
    // above stays as the fallback (AB offline / older AB / Copilot not ready).
    _reqAsstProbe(!!prefill);
}

// ────────────────────────────────────────────────────────────────────────────
// Guided Bug/Feature Request — the same AppBuilder-run interview as the
// Simulation Build Assistant (ab/request_session.py, relayed by the hub at
// /api/request-assistant/*). AB asks one question at a time until the
// required fields are captured and gates filing server-side; File report
// stores it through the normal /api/bug-report store. All text is escaped.
const _REQ_ASST_KEY = 'lm.requestAssistant.session';

function _reqAsstNew() {
    window._reqAsst = { sid: '', seq: 0, events: [], state: '', spec: null, ready: false,
        missing: [], blocked: [], choices: [], report_id: '', type: (window._reqAsst || {}).type || '',
        timer: null, sending: false };
    return window._reqAsst;
}

function _reqAsstStore(sid) {
    try { if (sid) localStorage.setItem(_REQ_ASST_KEY, sid); else localStorage.removeItem(_REQ_ASST_KEY); } catch (_) { /* private mode */ }
}

async function _reqAsstProbe(fresh) {
    let avail = null;
    try { avail = await apiJson('/api/request-assistant/available'); } catch (_) { avail = null; }
    if (!document.getElementById('file-bug-modal')) return;
    const note = document.getElementById('bug-guided-note');
    if (!avail || !avail.sessions) {
        if (note && avail && avail.available && avail.sessions_reason) {
            note.textContent = 'Guided assistant unavailable: ' + avail.sessions_reason;
            note.classList.remove('hidden');
        }
        return;
    }
    window._reqAsstAvailable = true;
    _reqAsstNew();
    let sid = '';
    try { sid = fresh ? '' : (localStorage.getItem(_REQ_ASST_KEY) || ''); } catch (_) { sid = ''; }
    bugUseGuided();
    if (sid) {
        window._reqAsst.sid = sid;
        try {
            const data = await apiJson(`/api/request-assistant/session/${encodeURIComponent(sid)}?since=0`);
            _reqAsstApply(data);
            if (data.report_id) { _reqAsstStore(''); _reqAsstNew(); }
        } catch (_) { _reqAsstStore(''); _reqAsstNew(); }
        _reqAsstRender();
        _reqAsstSchedule();
    }
}

function bugUseGuided() {
    const g = document.getElementById('bug-guided'), q = document.getElementById('bug-quick');
    if (!g || !q || !window._reqAsstAvailable) return;
    const gi = document.getElementById('req-asst-input'), qt = document.getElementById('bug-description');
    if (gi && qt && !gi.value && qt.value) gi.value = qt.value;
    g.classList.remove('hidden'); q.classList.add('hidden');
    document.getElementById('bug-mode-guided')?.classList.add('hidden');
    document.getElementById('bug-mode-quick')?.classList.remove('hidden');
    if (!window._reqAsst) _reqAsstNew();
    _reqAsstRender();
    setTimeout(() => gi?.focus(), 30);
}

function bugUseQuickForm() {
    const g = document.getElementById('bug-guided'), q = document.getElementById('bug-quick');
    if (!g || !q) return;
    const a = window._reqAsst || {};
    const qt = document.getElementById('bug-description');
    const first = (a.events || []).find(e => e.kind === 'user');
    const typed = document.getElementById('req-asst-input')?.value || '';
    if (qt && !qt.value) qt.value = (first && first.text) || typed;
    const fb = document.getElementById('bug-is-feature');
    if (fb) fb.checked = ((a.spec && a.spec.intent) || a.type) === 'feature';
    g.classList.add('hidden'); q.classList.remove('hidden');
    document.getElementById('bug-mode-quick')?.classList.add('hidden');
    if (window._reqAsstAvailable) document.getElementById('bug-mode-guided')?.classList.remove('hidden');
}

function _reqAsstApply(data) {
    const a = window._reqAsst;
    if (!a || !data) return;
    if (data.session_id && a.sid && data.session_id !== a.sid) return;
    if (data.session_id && !a.sid) { a.sid = data.session_id; _reqAsstStore(a.sid); }
    (data.events || []).forEach(e => { if (e.seq > a.seq) { a.events.push(e); a.seq = e.seq; } });
    ['state', 'spec', 'ready', 'missing', 'blocked', 'choices', 'report_id'].forEach(k => {
        if (data[k] !== undefined) a[k] = data[k];
    });
}

function _reqAsstBubble(role, text) {
    const isUser = role === 'user';
    const bg = isUser ? 'bg-[#01A982] text-white' : 'bg-white border border-slate-200 text-slate-800';
    let body = (!isUser && window.renderHelpMarkdown) ? window.renderHelpMarkdown(text)
        : '<p class="whitespace-pre-wrap">' + escapeHtml(text) + '</p>';
    body = body.replace(/<pre><code/g, '<pre class="bg-slate-800 text-slate-100 p-3 rounded-lg overflow-x-auto text-xs my-2"><code');
    return `<div class="flex ${isUser ? 'justify-end' : 'justify-start'} mb-3">
        <div class="max-w-[80%] rounded-2xl px-4 py-2.5 text-sm leading-relaxed ${bg} shadow-sm"><div class="cs-assistant-msg">${body}</div></div>
    </div>`;
}

function _reqAsstEventHtml(e) {
    const t = String(e.text || '');
    if (e.kind === 'user') return _reqAsstBubble('user', t);
    if (e.kind === 'assistant') return _reqAsstBubble('assistant', t);
    if (e.kind === 'tool') return '<div class="text-[11px] font-mono text-slate-500 ml-2 mb-1 truncate" title="' + escapeHtml(t) + '">› ' + escapeHtml(t) + '</div>';
    if (e.kind === 'status') return '<div class="text-xs italic text-slate-400 ml-2 mb-2">' + escapeHtml(t) + '</div>';
    if (e.kind === 'error') return '<div class="text-xs text-red-700 bg-red-50 border border-red-200 rounded-md px-3 py-2 mb-3">⚠️ ' + escapeHtml(t) + '</div>';
    if (e.kind === 'submit') return '<div class="text-xs text-emerald-800 bg-emerald-50 border border-emerald-200 rounded-md px-3 py-2 mb-3">✅ ' + escapeHtml(t) + '</div>';
    return '';
}

function _reqAsstBusy() {
    const a = window._reqAsst || {};
    return a.sending || a.state === 'preparing' || a.state === 'running';
}

function _reqAsstRender() {
    const a = window._reqAsst;
    const log = document.getElementById('req-asst-log');
    if (!a || !log) return;
    const intro = _reqAsstBubble('assistant', "Tell me what went wrong, or what you'd like added. " +
        "I'll ask a few questions (one at a time) so AppBuilder gets everything it needs.");
    log.innerHTML = intro + a.events.map(_reqAsstEventHtml).join('') +
        (_reqAsstBusy() ? '<div class="text-xs italic text-slate-400 ml-2">Assistant is working…</div>' : '');
    log.scrollTop = log.scrollHeight;

    const intent = (a.spec && a.spec.intent) || a.type || '';
    document.querySelectorAll('#file-bug-modal .req-asst-type').forEach(b => {
        const on = (b.getAttribute('data-reqtype') || '') === intent;
        b.className = 'req-asst-type px-3 py-1 rounded-full border ' + (on
            ? 'bg-[#01A982] text-white border-[#01A982]' : 'bg-white text-slate-600 border-slate-300 hover:border-[#01A982]');
        b.disabled = !!a.sid;
    });

    const busy = _reqAsstBusy();
    const done = a.state === 'submitted';
    const ch = document.getElementById('req-asst-choices');
    if (ch) {
        ch.innerHTML = (!busy && !done ? (a.choices || []) : []).map((c, i) =>
            `<button onclick="reqAsstChoose(${i})" class="px-3 py-1 rounded-full border border-[#01A982] text-[#01A982] text-xs hover:bg-[#01A982]/10">${escapeHtml(String(c))}</button>`).join('');
    }
    const cl = document.getElementById('req-asst-checklist');
    if (cl) {
        let h = '';
        if (a.sid && (a.missing || []).length) {
            h += '<div class="text-amber-700">Still needed: ' + a.missing.map(m => escapeHtml(String(m))).join(', ') + '</div>';
        } else if (a.sid && a.spec && a.ready) {
            h += '<div class="text-emerald-700">✅ All required details captured — review the summary, then File report.</div>';
        }
        (a.blocked || []).forEach(p => { h += '<div class="text-red-700">⛔ ' + escapeHtml(String(p)) + '</div>'; });
        cl.innerHTML = h;
    }
    const send = document.getElementById('req-asst-send'), stop = document.getElementById('req-asst-stop');
    const input = document.getElementById('req-asst-input');
    if (send) { send.disabled = busy || done; send.classList.toggle('opacity-50', busy || done); send.classList.toggle('hidden', a.state === 'running'); }
    if (stop) stop.classList.toggle('hidden', a.state !== 'running');
    if (input) input.disabled = done;
    const file = document.getElementById('req-asst-file');
    if (file) file.disabled = !(a.sid && a.ready && !busy && !a.report_id);
}

function _reqAsstSchedule() {
    const a = window._reqAsst;
    if (!a || a.timer || !a.sid || !_reqAsstBusy()) return;
    a.timer = setTimeout(async () => {
        a.timer = null;
        if (!document.getElementById('file-bug-modal') || window._reqAsst !== a) return;
        try {
            _reqAsstApply(await apiJson(`/api/request-assistant/session/${encodeURIComponent(a.sid)}?since=${a.seq}`));
        } catch (err) {
            if (/^404/.test(String(err && err.message))) { _reqAsstStore(''); _reqAsstNew(); }
        }
        _reqAsstRender();
        _reqAsstSchedule();
    }, 1500);
}

function _reqAsstConsoleErrors() {
    return (window.__lmBugBuffer || [])
        .filter(e => /error|warn/i.test(String(e.level || '')))
        .slice(-40)
        .map(e => `[${e.ts}] ${String(e.level).toUpperCase()}: ${e.msg}`)
        .join('\n');
}

function reqAsstSetType(t) {
    const a = window._reqAsst || _reqAsstNew();
    if (a.sid) return;
    a.type = t;
    _reqAsstRender();
}

function reqAsstChoose(i) {
    const c = ((window._reqAsst || {}).choices || [])[i];
    if (c !== undefined) reqAsstSend(String(c));
}

async function reqAsstSend(text) {
    const a = window._reqAsst || _reqAsstNew();
    const input = document.getElementById('req-asst-input');
    const msg = String(text !== undefined ? text : (input?.value || '')).trim();
    if (!msg || _reqAsstBusy() || a.state === 'submitted') return;
    const status = document.getElementById('req-asst-status');
    a.sending = true;
    a.choices = [];
    _reqAsstRender();
    try {
        let data;
        if (!a.sid) {
            data = await apiJson('/api/request-assistant/session', { method: 'POST', body: JSON.stringify({
                message: msg, type: a.type || '', context: _bugContextMeta(), console_errors: _reqAsstConsoleErrors() }) });
        } else {
            data = await apiJson(`/api/request-assistant/session/${encodeURIComponent(a.sid)}/reply`,
                { method: 'POST', body: JSON.stringify({ message: msg }) });
        }
        if (input && text === undefined) input.value = '';
        if (status) status.classList.add('hidden');
        _reqAsstApply(data);
        if (!a.state || a.state === 'awaiting_user') a.state = 'running';
    } catch (err) {
        if (status) { status.textContent = 'Assistant error: ' + err.message; status.classList.remove('hidden'); }
        if (/^404/.test(String(err && err.message))) { _reqAsstStore(''); _reqAsstNew(); }
    } finally {
        a.sending = false;
    }
    _reqAsstRender();
    _reqAsstSchedule();
}

async function reqAsstStop() {
    const a = window._reqAsst;
    if (!a || !a.sid) return;
    try { _reqAsstApply(await apiJson(`/api/request-assistant/session/${encodeURIComponent(a.sid)}/cancel`, { method: 'POST' })); } catch (_) { /* best effort */ }
    _reqAsstRender();
    _reqAsstSchedule();
}

async function reqAsstReset() {
    const a = window._reqAsst;
    if (a && a.sid && a.state === 'running') {
        try { await apiJson(`/api/request-assistant/session/${encodeURIComponent(a.sid)}/cancel`, { method: 'POST' }); } catch (_) { /* best effort */ }
    }
    if (a && a.timer) clearTimeout(a.timer);
    _reqAsstStore('');
    _reqAsstNew();
    const status = document.getElementById('req-asst-status');
    if (status) status.classList.add('hidden');
    _reqAsstRender();
}

async function reqAsstFile() {
    const a = window._reqAsst;
    if (!a || !a.sid || !a.ready) return;
    const btn = document.getElementById('req-asst-file');
    const status = document.getElementById('req-asst-status');
    const say = (m) => { if (status) { status.textContent = m; status.classList.remove('hidden'); } };
    if (btn) { btn.disabled = true; btn.textContent = 'Filing…'; }
    try {
        say('Capturing console, HTML, and screenshot…');
        const { consoleLogs, html, screenshot } = await _captureBugContext();
        say('Filing report…');
        const data = await apiJson(`/api/request-assistant/session/${encodeURIComponent(a.sid)}/submit`, {
            method: 'POST', body: JSON.stringify({ console_logs: consoleLogs, html, screenshot, context: _bugContextMeta() }) });
        const label = data.type === 'feature' ? 'Feature request' : 'Bug report';
        const next = data.type === 'feature' ? 'pending Global Admin approval' : 'ab will file an issue';
        showToast(`${label} submitted (id ${data.report_id || ''}) — ${next}`, 'success');
        _reqAsstStore('');
        _reqAsstNew();
        document.getElementById('file-bug-modal')?.remove();
    } catch (err) {
        console.error('Request assistant: file failed', err);
        say('Failed to file: ' + err.message);
        showToast('Failed to file: ' + err.message, 'error');
        if (btn) { btn.disabled = false; btn.textContent = 'Retry'; }
    }
}

// Shared capture for manual + auto bug filing: console buffer + truncated DOM
// + a best-effort html2canvas screenshot. Never blocks submission on failure.
async function _captureBugContext() {
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
    return { consoleLogs, html, screenshot };
}

function _bugContextMeta() {
    return {
        currentView,
        currentSubView,
        currentTenant,
        url: location.href,
        userAgent: navigator.userAgent,
        timestamp: Date.now(),
        hubVersion: window.__lmHubVersion || 'unknown',
        webuiVersion: window.__lmWebuiVersion || 'unknown',
        username: currentUser?.username || null,
    };
}

// Core submit shared by the manual File-a-Bug modal and the auto-file path
// (the runtime-error banner). ``onStatus`` receives human-readable progress.
// ``type`` is "bug" (default) or "feature" — from the modal's feature checkbox.
// ab files a feature request as an ``enhancement`` issue (no auto-fix).
async function _submitBugReport(explanation, severity, onStatus, type = 'bug') {
    if (typeof onStatus === 'function') onStatus('Capturing console, HTML, and screenshot…');
    const { consoleLogs, html, screenshot } = await _captureBugContext();
    const payload = { explanation, severity, type, console_logs: consoleLogs, html, screenshot, context: _bugContextMeta() };
    // DEV-BREAK: set window.__lmDevBreakBugReport = true to force a submit error (test filing workflow)
    if (window.__lmDevBreakBugReport) return await Promise.reject(new Error('DEV BREAK: apiJson intentionally failed'));
    if (typeof onStatus === 'function') onStatus('Submitting to hub…');
    return await apiJson('/api/bug-report', { method: 'POST', body: JSON.stringify(payload) });
}

async function submitBugReport() {
    const explanation = (document.getElementById('bug-description')?.value || '').trim();
    if (!explanation) {
        showToast('Please describe the bug or request before submitting', 'error');
        return;
    }
    const severity = document.getElementById('bug-severity')?.value || 'medium';
    const isFeature = !!document.getElementById('bug-is-feature')?.checked;
    const rtype = isFeature ? 'feature' : 'bug';
    const btn = document.getElementById('bug-submit-btn');
    const statusEl = document.getElementById('bug-submit-status');
    const setBusy = (msg) => {
        if (btn) { btn.disabled = true; btn.classList.add('opacity-60', 'cursor-wait'); btn.textContent = 'Submitting…'; }
        if (statusEl) { statusEl.textContent = msg; statusEl.classList.remove('hidden'); }
    };
    try {
        const data = await _submitBugReport(explanation, severity, setBusy, rtype);
        const label = isFeature ? 'Feature request' : 'Bug report';
        showToast(`${label} submitted (id ${data.id || ''}) — ab will file an issue`, 'success');
        document.getElementById('file-bug-modal')?.remove();
    } catch (err) {
        console.error('File-a-Bug: submit failed', err);
        if (statusEl) { statusEl.textContent = 'Failed to submit: ' + err.message; statusEl.classList.remove('hidden'); }
        showToast('Failed to submit: ' + err.message, 'error');
        if (btn) { btn.disabled = false; btn.classList.remove('opacity-60', 'cursor-wait'); btn.textContent = 'Retry'; }
    }
}

// Auto-file a bug when the runtime-error banner fires (called from the
// index.html error boundary). Dedup'd per unique message per session so a
// spammy handler doesn't open a GitHub issue on every throw. ``onStatus``
// updates the banner's "Filing Bug with AppBuilder" status line.
async function fileBugAuto(message, where, onStatus) {
    const filedBugs = window.__lmAutoFiledBugs
        || (window.__lmAutoFiledBugs = new Set());
    const sig = String(message || '').slice(0, 200);
    if (filedBugs.has(sig)) {
        if (typeof onStatus === 'function') onStatus('Already filed for this error');
        return;
    }
    filedBugs.add(sig);
    if (typeof onStatus === 'function') onStatus('Filing Bug with AppBuilder…');
    const whereStr = where ? ` (${where})` : '';
    const viewCtx = [currentView, currentSubView].filter(Boolean).join(' / ');
    const tenantCtx = currentTenant ? ` · tenant=${currentTenant}` : '';
    const explanation = `[Auto-filed from a runtime browser error — the user did not type this.]\n\n`
        + `Error: ${message}${whereStr}\n`
        + `View: ${viewCtx || '(unknown)'}${tenantCtx}\n`
        + `URL: ${location.href}\n`
        + `User agent: ${navigator.userAgent}\n`;
    const wrap = typeof onStatus === 'function' ? (s) => onStatus('Filing Bug with AppBuilder — ' + s) : null;
    try {
        const data = await _submitBugReport(explanation, 'high', wrap, 'bug');
        if (typeof onStatus === 'function') onStatus(`Bug filed (id ${data.id || ''}) — ab will triage`);
    } catch (err) {
        console.error('Auto bug-file failed', err);
        if (typeof onStatus === 'function') onStatus('Bug filing failed: ' + (err && err.message || ''));
    }
}
window.fileBugAuto = fileBugAuto;

// User-initiated bug filing from a specific log event row (the per-row 🐞 "Bug"
// button in the Logs view). Unlike fileBugAuto — the runtime-error autopilot
// whose explanation is prefixed "the user did not type this" — THIS is
// explicitly the user's deliberate choice, so the explanation is framed
// honestly as user-initiated. Opens the editable File-a-Bug modal pre-filled
// from the log line so the user can add detail and pick severity before
// submitting (the modal path is the nicer UX than a silent one-click file).
// `event.stopPropagation()` stops the click from ALSO toggling a grouped-log
// row's expand/collapse (grouped headers carry an onclick=toggleLogGroup).
function fileBugFromLog(event, btn) {
    if (event && typeof event.stopPropagation === 'function') event.stopPropagation();
    // getAttribute decodes the escapeHtml'd entities back to the ORIGINAL raw
    // line/level/source, so the bug report carries the real log text.
    const line = (btn && btn.getAttribute('data-logline')) || '';
    const level = (btn && btn.getAttribute('data-level')) || '';
    const source = (btn && btn.getAttribute('data-source')) || '';
    const viewCtx = [currentView, currentSubView].filter(Boolean).join(' / ') || '(unknown)';
    const tenantCtx = currentTenant || '(none)';
    const explanation =
        `Filing a bug from a specific log event (user-initiated from the Logs view).\n\n`
        + `Log line: ${line}\n`
        + (level ? `Level: ${level}\n` : '')
        + (source ? `Source: ${source.trim()}\n` : '')
        + `View: ${viewCtx}\n`
        + `Tenant: ${tenantCtx}\n`
        + `URL: ${location.href}\n`
        + `User agent: ${navigator.userAgent}\n\n`
        + `What went wrong / what I expected (please add detail):\n`;
    fileBug(explanation);
}
window.fileBugFromLog = fileBugFromLog;

function userAllowedTenants() {
    return currentUser?.tenants || [];
}

function canAccessTenant(tenantId) {
    if (isAdmin()) return true;
    // Deny-by-default — exact parity with the backend access.check_tenant_access:
    // a non-admin may access ONLY tenants explicitly in their user.tenants list.
    // An empty list means NO tenant assignment (NOT "sees all"). The previous
    // `allowed.length === 0` branch waved a tenantless user through to EVERY
    // tenant — including the built-in 'default' ("Admin") scope — which the
    // backend then denied, stranding them on a data-less view (the "no tenant
    // assigned" bug). Now the UI agrees: no assignment → no accessible tenant.
    return userAllowedTenants().includes(tenantId);
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
        const r = await fetch(`/auth/prefixes${qs}`, { credentials: 'same-origin', _keepOnNavigate: true });
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
    _cacheStatusPoller = pollManager.register(async () => {
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
    pollManager.unregister(_cacheStatusPoller);
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
    settings: ['General', 'User Access', 'Cloud', 'Tenant Config', 'Sync', 'Hub Status', 'API Tokens', 'Self-Backup', 'Collab', 'Notifications', 'Icons', 'Diagnostics'],
    logs:     ['logs-hub', 'logs-pxmx', 'logs-opn', 'logs-netbox', 'logs-cppm', 'logs-cs', 'logs-console', 'logs-agents', 'logs-recovery', 'logs-errors', 'logs-bugs', 'logs-features'],
    setup: ['Spokes & Agents', 'Module Management', 'Directory (LDAP)', 'Simulations', 'Remote Console', 'Test Data Feed'],
    opnsense: ['Firewall Rules', 'NAT Policies', 'DNS Records', 'Aliases', 'DHCP Leases', 'Interfaces'],
    pxmx: ['Overview', 'Virtual Machines', 'Diagnostics', 'Settings'],
    ldap: ['Users', 'Groups'],
    cppm: ['NAC Status', 'Access Tracker', 'My Devices', 'Unknown Devices', 'My Users'],
    cs: ['Dashboard', 'Clients', 'Central', 'Central On-Prem', 'Mist', 'VM Server', 'Config', 'Setup', 'Spoke Management', 'Assistant'],
    netbox: ['Overview', 'Devices', 'Racks', 'Prefixes', 'IP Addresses'],
    dns: ['Overview', 'Records', 'Forwarders', 'Overrides', 'External DNS', 'Diagnostics'],
    dhcp: ['Overview', 'Subnets', 'Leases', 'Reservations', 'Diagnostics'],
    nw: ['Overview', 'Gateways', 'Switches', 'Firewalls', 'Other', 'Topology', 'Scan'],
    truenas: ['Appliances', 'Pools', 'Datasets', 'Shares', 'Disks', 'Alerts', 'Capacity'],
};

// Two-tier horizontal nav: child tabs that appear in #top-nav-secondary under
// a primary. Only cs (Simulations) uses this today — its primaries mirror the
// solutions-hpe webui-hub tenant sub-nav, and the child sets mirror webui-hub's
// own subtab lists (VM Server 11, Setup 7, Central 3, Simulations 3, Clients 3,
// Config 2). Primaries not listed here (Spoke Management) have no
// children → render directly, no secondary strip. Config sub-tabs: "Sim Quotas"
// (alert→sim linkage + per-site client quotas the engine keeps filled), "PXMX
// Sites" (assign pxmx servers to sites → per-site runner pools), "Quota State"
// (live engine ledger), and "Config Editor" (the former flat Config view — Source
// of Truth + simulation.conf + user-overrides + hub config).
const VIEW_CHILDREN = {
    cs: {
        'Dashboard': ['Checks', 'Hardware', 'Client Count'],
        'Clients':     ['All', 'T1', 'T2', 'T3', 'Offline'],
        'Central':         ['Sites', 'Alerts', 'Insights', 'Clients', 'Hardware', 'Diagnostic'],
        'Central On-Prem': ['Sites', 'Alerts', 'Insights', 'Clients', 'Hardware', 'Diagnostic'],
        'Mist':            ['Sites', 'Alerts', 'Insights', 'Clients', 'Hardware', 'Diagnostic'],
        'VM Server':   ['Overview', 'VMs', 'Terminal', 'USB', 'PCI', 'IoT', 'VirtualHere', 'Command Queue', 'Details'],
        'Config':      ['Engine', 'Engine State', 'Engine Diagnostic', 'Sites', 'Config Editor'],
        'Setup':       ['General', 'Central API', 'Central On-Prem API', 'Mist API', 'Proxmox', 'GitHub', 'Security', 'Notifications', 'Diagnostics'],
    },
    settings: {
        // Cloud gets a second-tier strip — one tab per cloud provider (Azure,
        // OCI); each provider's own integrations are a THIRD tier (see
        // VIEW_GRANDCHILDREN below) so e.g. Azure's SSO/NSG/Cloud NAC/Key Vault/
        // NetBox SSO tiles nest under 'Azure', not flattened alongside OCI's.
        'Cloud': ['Azure', 'OCI'],
    },
};

// Third-tier grandchild tabs (#top-nav-tertiary), nested under a VIEW_CHILDREN
// child. Only Settings → Cloud uses this today: each provider's own set of
// integrations (Azure shares its SSO app registration + cert across every
// item below; OCI uses its own API signing key).
const VIEW_GRANDCHILDREN = {
    settings: {
        Cloud: {
            'Azure': ['SSO', 'NSG', 'Cloud NAC', 'Vault', 'NetBox SSO'],
            'OCI': ['NSG', 'Vault'],
        },
    },
};

// First grandchild of a child, or '' if the child has no grandchildren.
function _csDefaultGrandchild(viewId, primary, child) {
    const gkids = ((VIEW_GRANDCHILDREN[viewId] || {})[primary] || {})[child];
    return (gkids && gkids.length) ? gkids[0] : '';
}

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
    'logs-features': 'Feature Request',
    'logs-opn': 'Firewall',
    'logs-pxmx': 'Hypervisor',
    'logs-cppm': 'NAC',
    'logs-netbox': 'IPAM',
    'logs-nw': 'Network',
    'logs-cs': 'Simulations',
    'logs-console': 'Console',
    'logs-le': 'Certificates',
    'logs-ldap': 'Directory',
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
    'logs-nw':     'nw',
    'logs-cppm':   'cppm',
    'logs-cs':     'cs',
    'logs-le':     'le',
    'logs-truenas': 'truenas',
    'logs-ldap':   'ldap',
};
function logsSubmenu() {
    const products = window.activeProducts || new Set();
    const hasAgents = !!window.hasAgents;
    // Preserve the canonical order: hub first, then installed module tabs in
    // their fixed sequence, agents, then the hub-native filtered views last.
    const order = ['logs-hub', 'logs-pxmx', 'logs-opn', 'logs-netbox', 'logs-nw', 'logs-cppm', 'logs-cs', 'logs-console', 'logs-le', 'logs-truenas', 'logs-ldap', 'logs-agents', 'logs-recovery', 'logs-errors'];
    return order.filter(m => {
        if (m === 'logs-hub' || m === 'logs-recovery' || m === 'logs-errors' || m === 'logs-console') return true;
        if (m === 'logs-agents') return hasAgents;
        const product = LOG_MODULE_PRODUCT[m];
        return !product || products.has(product);
    });
}

async function loadFirewalls() {
    try {
        const data = await apiJson('/setup/firewalls');
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
            // Re-point the Managed Devices tenant filter at the tenant we just
            // switched to. That filter lives on window (_mdFilter) so the tab
            // handlers survive re-renders, which also means it survived a TENANT
            // switch -- and for a Global Admin the device fetch is unscoped
            // (_devEndpoint returns the bare /setup/* path, no ?tenant=), so
            // every tenant's devices are always present. The self-heal in
            // loadAllDevices only clears a filter whose tenant owns NO device,
            // so it could never fire here: the old tenant still owned devices
            // and the list stayed pinned to it. The page really did refetch --
            // it was re-filtered back to the previous tenant, which is why this
            // read as "My Devices does not refresh" (lm#486). loadAllDevices()
            // falls back to 'all' if the new tenant owns nothing.
            if (window._mdFilter) window._mdFilter.tenant = tenant;
            // Preserve the active sub-view across a tenant switch. setView()
            // re-renders the whole view and resets currentSubView to the first
            // sub-menu (Overview/Devices), so a user on Prefixes who switches
            // tenant would be bounced back to the default tab. Instead, just
            // reload the current sub-view's data for the new tenant — the view
            // layout (nav/header) is unchanged, only the tenant filter moved.
            // Fall back to setView() only if the recorded sub-view isn't valid
            // for the current view (e.g. view changed mid-flight).
            const subs = VIEW_SUBMENUS[currentView] || [];
            if (subs.includes(currentSubView) && VIEW_LOADERS[currentView]) {
                setSubView(currentSubView);
            } else {
                // No loader for this view: setSubView would no-op and leave the
                // OLD tenant's data on screen, so do a full re-render instead.
                setView(currentView);
            }
        }
    } catch (err) {
        console.error('Failed to set tenant', err);
    }
}


async function scanGitHubRepos() {
    const btn = event?.target;
    const origText = btn?.textContent;
    if (btn) { btn.disabled = true; btn.textContent = 'Scanning…'; }
    try {
        const data = await apiJson('/setup/github-repos');
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

// Compact count formatting so a growing tally (e.g. 1,100 → "1.1K") stays narrow
// in fixed-width stat chips. Exact numbers below 1000 render in full; 1000+ use
// compact notation (1.1K / 12.3K / 1.2M). Callers keep the exact value in a
// title/tooltip so the precise count is still available on hover.
function fmtCompactNum(val) {
    const n = Number(val || 0);
    if (!isFinite(n)) return '0';
    if (Math.abs(n) < 1000) return n.toLocaleString();
    try {
        return new Intl.NumberFormat(undefined, { notation: 'compact', maximumFractionDigits: 1 }).format(n);
    } catch (e) {  // very old engines without compact notation
        const units = [['B', 1e9], ['M', 1e6], ['K', 1e3]];
        for (const [u, d] of units) if (Math.abs(n) >= d) return (n / d).toFixed(1).replace(/\.0$/, '') + u;
        return n.toLocaleString();
    }
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
        const data = await apiJson('/setup/tenants');
        window._sharedTenantId = data.shared_tenant_id || null;  // for the shared badge / gate
        const tenants = data.tenants || [];
        // Keep the shared tenant cache (group/user tenant-scope pickers) in
        // step with the list after a tenant add/sync/delete.
        _cacheAllTenants(tenants);

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
            // Delete is a Global-Admin action (like create/sync/re-scope) and
            // never offered for the built-in 'default' tenant.
            const canDelete = isAdmin() && String(t.id).toLowerCase() !== 'default';
            const nameArg = String(t.name || t.id).replace(/'/g, "\\'");
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
                    ${canDelete ? `<button onclick="deleteTenant('${t.id}','${nameArg}')" title="Delete tenant" class="p-1 rounded text-slate-300 hover:text-red-500 hover:bg-red-50 transition-colors"><svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg></button>` : ''}
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
        showToast('Error loading tenant: ' + err.message, 'error');
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
            showToast('Tenant configuration saved successfully!', 'success');
            await loadTenantConfig();
        } else {
            const d = await response.json().catch(() => ({}));
            showToast('Failed to save tenant configuration: ' + (d.detail || response.statusText), 'error');
        }
    } catch (err) {
        showToast('Error saving tenant: ' + err.message, 'error');
    }
}

async function addTenant() {
    const tenantId = document.getElementById('new-tenant-id').value.trim();
    if (!tenantId) {
        showToast('Please enter a Tenant ID', 'error');
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
            showToast('Failed to create tenant.', 'error');
        }
    } catch (err) {
        showToast('Error creating tenant: ' + err.message, 'error');
    }
}

// Global-Admin-only. Deletes a tenant's registry shell + user assignments via
// DELETE /setup/tenants/{id}. The server refuses the 'default' tenant and any
// tenant that still owns bound spokes (409) — per-module data is NOT purged
// (use Migrate Data first if it must be moved). Surfaces the server's detail so
// the operator sees exactly which spokes block the delete.
async function deleteTenant(tenantId, tenantName) {
    const label = tenantName || tenantId;
    if (!await showConfirmToast(`Delete tenant “${label}”? This removes the tenant and detaches it from all users. Bound spokes must be re-bound or decommissioned first, and this does NOT delete the tenant's NetBox/Proxmox/LDAP data — use “Migrate Data” beforehand if you need it moved or purged.`)) return;
    try {
        const response = await setupFetch(`/setup/tenants/${encodeURIComponent(tenantId)}`, { method: 'DELETE' });
        const d = await response.json().catch(() => ({}));
        if (response.ok) {
            showToast(d.message || `Tenant ${label} deleted.`, 'success');
            // If we were viewing the deleted tenant, drop back to default.
            if (currentTenant === tenantId && typeof setTenant === 'function') {
                await setTenant('default');
            }
            await loadTenantConfig();
        } else {
            showToast('Failed to delete tenant: ' + (d.detail || response.statusText), 'error');
        }
    } catch (err) {
        showToast('Error deleting tenant: ' + err.message, 'error');
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
            showToast(msg, 'success');
        } else {
            showToast('Sync failed: ' + (data.detail || resp.statusText), 'error');
        }
    } catch (err) {
        showToast('Sync error: ' + err.message, 'error');
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

// ★ next to each tenant in the picker: the tenant LM opens on at sign-in.
// Saved on the user's record by the hub, so it follows them to any browser.
function _tenantDefaultStar(tenantId) {
    const on = currentUser?.default_tenant === tenantId;
    const tip = on ? 'Default tenant — click to clear' : 'Open on this tenant when I sign in';
    return `<button data-default-tid="${escapeHtml(tenantId)}" onclick="setDefaultTenant('${escapeHtml(tenantId)}', event)" title="${tip}" aria-label="${tip}" class="px-2 py-1.5 text-[12px] leading-none ${on ? 'text-amber-300' : 'text-slate-500 hover:text-white'}">${on ? '★' : '☆'}</button>`;
}

async function setDefaultTenant(tenantId, evt) {
    if (evt) evt.stopPropagation();  // starring must not switch tenant or close the menu
    const clear = currentUser?.default_tenant === tenantId;
    try {
        const r = await fetch('/auth/default-tenant', {
            method: 'PUT',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ tenant_id: clear ? null : tenantId }),
        });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(d.detail || r.statusText);
        currentUser.default_tenant = d.default_tenant;
        document.querySelectorAll('#tenant-picker-menu button[data-default-tid]').forEach(b => {
            b.outerHTML = _tenantDefaultStar(b.dataset.defaultTid);
        });
        const name = (window._lmTenantPicker || []).find(t => t.id === tenantId)?.name || tenantId;
        showToast(clear ? 'Default tenant cleared' : `${name} is now your default tenant`, 'success');
    } catch (e) {
        showToast(`Could not save default tenant: ${e.message}`, 'error');
    }
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
            showToast('No firewalls configured to refresh.', 'success');
            return;
        }
        // One batched call refreshes every firewall server-side (concurrently)
        // instead of one GET per firewall from the browser.
        let ok = 0, fail = 0;
        try {
            const r = await fetch('/api/firewall/refresh', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ firewall_ids: firewalls.map(fw => fw.id) }),
            });
            const d = await r.json().catch(() => ({}));
            if (r.ok && Array.isArray(d.results)) {
                ok = d.results.filter(x => x && x.ok).length;
                fail = d.results.filter(x => x && !x.ok).length;
            } else { fail = firewalls.length; }
        } catch (e) { fail = firewalls.length; }
        showToast(`Refreshed cache for ${ok} firewall(s)${fail ? ` (${fail} failed)` : ''}.`, fail ? 'error' : 'success');
        console.log(`Firewall cache refresh: ${ok} ok, ${fail} failed of ${firewalls.length}`);

        if (currentView === 'opnsense' && currentSubView !== 'Configuration') {
            loadOpnsenseManagement();
        }
    } catch (err) {
        showToast('Error refreshing firewall cache: ' + err.message, 'error');
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
// Friendly spoke/agent name. INVARIANT: the backend defaults display_name to
// the node's own id (spoke_id/agent_id) when it's unnamed (setup.py
// _aggregate_spokes, tenant_devices._bindable_spokes, hub_cert_distribution
// mtls_readiness), so display_name is NEVER empty — a plain `display_name || id`
// renders the GUID. Prefer a REAL display_name (≠ id), then the reported
// hostname, then the id. Route every by-name spoke/agent render through this so
// the UUID never leaks to the UI. Keep the raw id in a title= hover.
function _spokeName(o) {
    if (!o) return '';
    const id = o.spoke_id || o.id || o.agent_id || '';
    const dn = o.display_name;
    const base = (dn && dn !== id) ? dn : (o.hostname || id);
    return _nodeLabel(base, _tenantOf(o));
}

// Tenant of a spoke/agent object for display labelling. Spoke-kind rows carry
// it on tenant_id; Proxmox node agents carry it in client_simulation.tenant_id.
function _tenantOf(o) {
    if (!o) return '';
    return String(o.tenant_id || (o.client_simulation && o.client_simulation.tenant_id) || '').trim();
}

// Tenant-qualified, UPPERCASE display label for a spoke/agent — e.g. base
// "pxmx-svr-cs-06" bound to tenant "lrb" renders "LRB-PXMX-SVR-CS-06". Keeps
// generic node names from colliding across tenants in the UI.
// DISPLAY ONLY: the stored spoke_id/agent_id (identity — keys, approval,
// routing, and every action) is NEVER changed; callers keep passing the raw id
// as the <option> value / sid / idTitle. Idempotent: a base that already starts
// with the tenant prefix isn't doubled, so it's safe to apply more than once
// along a render path (e.g. a name already run through _spokeName).
function _nodeLabel(base, tenant) {
    let label = String(base == null ? '' : base).trim();
    const t = String(tenant == null ? '' : tenant).trim();
    if (t && label) {
        const T = t.toUpperCase();
        const U = label.toUpperCase();
        if (U !== T && !U.startsWith(T + '-')) label = `${t}-${label}`;
    }
    return label.toUpperCase();
}

function _renderSpokeAgentRow(label, mod, status, spokeVariant, tenant, idTitle, revokeInfo) {
    const _revoked = !!(revokeInfo && revokeInfo.revoked);
    const dot = _revoked
        ? 'bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.7)]'
        : (status === 'online'
        ? 'bg-green-500 shadow-[0_0_8px_rgba(34,197,94,0.6)]'
        : (status === 'pending' ? 'bg-amber-400' : 'bg-slate-400'));
    const badge = status === 'online'
        ? '<span class="text-[10px] uppercase tracking-widest text-green-600 font-bold">Online</span>'
        : (status === 'pending'
            ? '<span class="text-[10px] uppercase tracking-widest text-amber-500 font-bold">Pending</span>'
            : '<span class="text-[10px] uppercase tracking-widest text-slate-400 font-bold">Offline</span>');
    // Revoked badge — surfaces WHY a node lost access (admin action OR an
    // automatic tenant-side threat response) right in the spokes/agents module
    // and the tenant view. The reason + who/when is in the hover title. A
    // threat_auto revoke is styled distinctly (it means the node tripped a
    // recon/scan signature and was auto-contained; admin re-approval required).
    const revokedBadge = _revoked
        ? (() => {
            const _by = revokeInfo.revoked_by || '';
            const _auto = _by === 'threat_auto';
            const _when = revokeInfo.revoked_ts
                ? new Date(revokeInfo.revoked_ts * 1000).toLocaleString() : '';
            const _title = `Revoked${_auto ? ' automatically (tenant-side threat response)' : ' by admin'}`
                + (revokeInfo.revoke_reason ? ` — ${revokeInfo.revoke_reason}` : '')
                + (_when ? ` (${_when})` : '')
                + '. Re-approval required to return.';
            return `<span class="text-[10px] px-2 py-0.5 rounded-full font-bold uppercase ${_auto ? 'bg-red-600 text-white animate-pulse' : 'bg-red-100 text-red-700'}" title="${escapeHtml(_title)}">${_auto ? '⛔ Auto-Revoked' : '⛔ Revoked'}</span>`;
        })()
        : '';
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
    // Metrics/backpressure are keyed by the raw hub spoke/agent id, NOT the
    // (now tenant-prefixed, uppercased) display label — look them up by idTitle
    // (the raw id every caller passes) so a friendly/qualified label never
    // silently drops the msg/s, backlog, and throttle chips.
    const _key = idTitle || label;
    const _mps = _m.spoke_mps ? _m.spoke_mps[_key] : undefined;
    const _bk = (_m.backlog_stats && _m.backlog_stats.by_spoke) ? _m.backlog_stats.by_spoke[_key] : undefined;
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
    const _lvl = (_bp.spoke_levels && _bp.spoke_levels[_key]) || 0;
    const throttleChip = _lvl === 1
        ? `<span class="text-[10px] px-2 py-0.5 rounded-full font-bold uppercase bg-red-100 text-red-700 animate-pulse" title="Offending — this ${spokeVariant ? 'spoke' : 'agent'} is over its message rate; the hub asked it to slow down &amp; coalesce updates locally">⚠ Offending</span>`
        : (_lvl >= 2
            ? `<span class="text-[10px] px-2 py-0.5 rounded-full font-bold uppercase bg-orange-100 text-orange-700" title="Throttled — fleet-wide slow-down active; this ${spokeVariant ? 'spoke' : 'agent'} is coalescing updates locally">⏳ Throttled</span>`
            : '');
    return `
        <div class="${container}">
            <div class="flex items-center gap-3">
                <div class="w-2 h-2 rounded-full ${dot}"></div>
                <span class="${nameCls}" title="${escapeHtml(String(idTitle || label))}">${escapeHtml(String(label))}</span>
                ${(mod && mod !== '—') ? `<span class="text-[10px] px-2 py-0.5 rounded-full font-bold uppercase bg-slate-200 text-slate-600">${mod}</span>` : ''}
                ${tenantChip}
            </div>
            <div class="flex items-center gap-2">
                ${revokedBadge}${throttleChip}${mpsChip}${backlogChip}${badge}
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
let _statusDownToast = null;   // sticky "update/restart in progress" toast handle
let _statusDownTicks = 0;      // consecutive unreachable poll ticks (×10s)
let _statusDownFromVersion = null; // hub version observed just before it went down
let _pageLoadHubVersion = null; // hub version this tab's JS bundle was loaded against
let _versionDriftReloading = false; // a drift reload is already scheduled

// Stale-bundle guard. The reload on the reconnect path above only fires if the
// poller actually SAW the hub go down (_statusDownToast). A self-update that
// restarts between two 10s polls -- or a WebUI-only asset change with no
// restart at all -- never sets that toast, so the tab keeps running the JS it
// loaded hours ago while talking to a newer API. That is unrecoverable on its
// own: assets are served `immutable, max-age=1yr` (see serve_ui) and this is a
// SPA, so index.html -- the only no-store document, and the only thing that
// hands out a fresh ?v= token -- is never re-fetched. Symptom is a control that
// silently does nothing because its handler only exists in the new bundle.
// So: compare every poll against the version this page loaded with, and reload
// on any change. Cheap when assets did NOT change (same ?v= = 304s).
function _checkWebuiVersionDrift(version) {
    if (!version || _versionDriftReloading) return;
    if (!_pageLoadHubVersion) { _pageLoadHubVersion = version; return; }
    if (version === _pageLoadHubVersion) return;
    // Never yank a modal out from under someone mid-edit -- polling continues,
    // so this reloads on a later tick once the dialog is closed.
    if (document.querySelector('.fixed.inset-0')) return;
    _versionDriftReloading = true;
    if (typeof showToast === 'function') {
        showToast(`Hub updated (${_pageLoadHubVersion} → ${version}) — reloading to load the new version…`, 'success');
    }
    setTimeout(() => window.location.reload(), 1500);
}
async function updateStatus() {
    // Honor hub overload backpressure: if the hub told us to back off, skip
    // this tick instead of hammering a saturated loop.
    if (Date.now() < _statusBackoffUntil) return;
    try {
        // Each fetch is made non-fatal (.catch → null): a CONNECTION failure
        // ("Load failed" / "could not connect") on the expensive admin endpoints
        // (/setup/pending_spokes + /setup/diagnostics iterate every spoke and can
        // drop under load) must NOT reject Promise.all and abort the whole tick —
        // that skips _rebuildMainNav, freezing the left nav on stale data (e.g. a
        // module that connected AFTER the last good poll never gets its nav item).
        // A null response is then treated exactly like a !ok one below: fall back
        // to the last-known-good spoke list so the nav stays intact.
        const requests = [fetch('/status').catch(() => null)];
        if (isAdmin()) {
            requests.push(setupFetch('/setup/pending_spokes').catch(() => null),
                          setupFetch('/setup/diagnostics').catch(() => null));
        } else if (isTenantAdmin()) {
            // A tenant-admin cannot reach the Global-Admin-only /setup/* surface
            // (it 403s), so they get the spoke list that builds the left nav from
            // the tenant-scoped /tenant/spokes mirror instead — their OWN + shared
            // approved spokes. Without this the nav has NO spoke list at all and
            // every module menu vanishes for a tenant-admin. No /setup/diagnostics
            // sibling (hub-health is admin-only), so push a null placeholder to
            // keep the [status, approvals, diag] destructuring positions aligned.
            requests.push(setupFetch('/tenant/spokes').catch(() => null),
                          Promise.resolve(null));
        }
        const [statusRes, approvalsRes, diagRes] = await Promise.all(requests);

        // /status itself unreachable this tick → the hub is (re)starting or
        // briefly unreachable. Surface the SAME reassuring "please wait" message
        // the button-driven update shows, instead of a silent blank screen — the
        // user asked for parity with those in-flight messages. Sticky toast that
        // self-dismisses on reconnect below. Suppressed while a button-driven
        // update is already narrating its own "Restarting…" progress.
        if (!statusRes) {
            _statusDownTicks++;
            if (!window.__lmUpdateInProgress && !_statusDownToast && typeof showStickyToast === 'function') {
                // Remember the version we were on so we can tell, on reconnect,
                // whether this outage was an actual update (version advanced).
                _statusDownFromVersion = window.__lmHubVersion || null;
                _statusDownToast = showStickyToast(
                    'Hub unavailable — an update or restart is in progress. Please wait…', 'info');
            } else if (_statusDownToast) {
                _statusDownToast.update(
                    `Hub unavailable — an update or restart is in progress. Please wait… (${_statusDownTicks * 10}s)`);
            }
            return;
        }

        // /status answered again with 200 (ready). If we were showing the
        // "please wait" toast, the hub just came back: clear it, and if its
        // version advanced during the outage this WAS an update — reload so the
        // browser picks up the new WebUI assets (the stale-asset blank-screen
        // the user hit otherwise). A 503 here (protect mode, still starting) is
        // NOT a full recovery — leave the toast up and let the 503 branch below
        // back off; we dismiss only once it truly answers 200.
        if (_statusDownToast && statusRes.ok) {
            _statusDownToast.dismiss();
            _statusDownToast = null;
            _statusDownTicks = 0;
            try {
                const sd = await statusRes.clone().json();
                const newVer = sd && sd.metrics ? sd.metrics.version : null;
                if (newVer && _statusDownFromVersion && newVer !== _statusDownFromVersion) {
                    showToast(`Hub updated (${_statusDownFromVersion} → ${newVer}) — reloading to load the new version…`, 'success');
                    setTimeout(() => window.location.reload(), 1500);
                    return;
                }
                showToast('Hub reconnected.', 'success');
            } catch (e) { /* non-fatal — recovery toast is best-effort */ }
        }

        // 503 + Retry-After = hub in protect mode → back off polling.
        if (statusRes.status === 503) {
            const ra = parseInt(statusRes.headers.get('Retry-After') || '30', 10) || 30;
            _statusBackoffUntil = Date.now() + ra * 1000;
            if (typeof showToast === 'function') showToast(`Hub busy (protecting) — backing off ${ra}s`, 'info');
            return;
        }
        _statusBackoffUntil = 0;
        if (!statusRes.ok) throw new Error('API Error');
        const approvalsOk = (isAdmin() || isTenantAdmin()) && approvalsRes?.ok;
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
        window.__lmNavArgs = [allSpokes, connections];
        _rebuildMainNav(allSpokes, connections);
        _refreshCertMonFlag();
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
        const esc = escapeHtml;  // shared escaper (escapes &<>"')
        const kv = (obj) => Object.keys(obj || {}).length
            ? Object.entries(obj).sort((a,b)=>b[1]-a[1])
                .map(([k,v]) => `<span class="inline-block bg-slate-100 rounded px-2 py-0.5 mr-1 mb-1">${esc(k)}: <b>${v}</b></span>`).join('')
            : '<span class="text-slate-400 italic">none</span>';
        // Same chips, but for maps keyed by SPOKE ID — show the operator the
        // spoke/agent name instead of a raw UUID, keeping the id on hover so it
        // is still available for correlating against logs.
        const kvSpokes = (obj) => Object.keys(obj || {}).length
            ? Object.entries(obj).sort((a,b)=>b[1]-a[1])
                .map(([k,v]) => `<span class="inline-block bg-slate-100 rounded px-2 py-0.5 mr-1 mb-1" title="${esc(k)}">${esc(spokeDisplayName(k))}: <b>${v}</b></span>`).join('')
            : '<span class="text-slate-400 italic">none</span>';
        detEl.innerHTML = `
            <div><span class="text-slate-400 uppercase text-[10px] font-bold tracking-widest">Backlog</span>
                 &nbsp;total <b>${bs.total ?? 0}</b> · unacked <b>${bs.pending_ack ?? 0}</b> · queued <b>${bs.queued ?? 0}</b>
                 ${bs.oldest_age_s ? `· oldest <b>${bs.oldest_age_s}s</b>` : ''}</div>
            <div><span class="text-slate-400 uppercase text-[10px] font-bold tracking-widest">By type</span><br>${kv(bs.by_type)}</div>
            <div><span class="text-slate-400 uppercase text-[10px] font-bold tracking-widest">By spoke</span><br>${kvSpokes(bs.by_spoke)}</div>
            <div class="pt-1 border-t border-slate-100"><span class="text-slate-400 uppercase text-[10px] font-bold tracking-widest">Rate limit</span>
                 &nbsp;burst <b>${rl.capacity ?? '—'}</b> · <b>${rl.fill_rate ?? '—'}</b>/s
                 &nbsp;·&nbsp;drops total <b>${m.rate_limit_drops_total ?? 0}</b></div>
            <div><span class="text-slate-400 uppercase text-[10px] font-bold tracking-widest">Drops by spoke</span><br>${kvSpokes(drops)}</div>
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
                    ${thr.length ? `<br><span class="text-slate-400">throttled:</span> ${kvSpokes(bp.spoke_levels || {})}` : ''}</div>`;
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
        //   RED (failed/stuck)     = the update is NOT going to complete on its
        //                           own: a rollback failed, a version is on the
        //                           bad-versions list (the updater skips it, so
        //                           Update is a permanent no-op), or drift has
        //                           persisted past LM_UPDATE_STUCK_S.
        // Amber previously covered this case too, so a hub wedged on an old
        // version looked identical to one waiting on a routine restart — you
        // could press Update repeatedly and never learn it could not work.
        const wd = m.watchdog || {};
        const behind = !!wd.behind;
        const updateAvail = !!wd.update_available;
        const updFailed = !!wd.update_failed;
        const updStuck = !!wd.update_stuck;
        const bad = (updFailed || updStuck);
        const dotTone = bad ? 'bg-red-500'
            : (behind || updateAvail) ? 'bg-amber-400' : 'bg-green-500';
        // wd.running_version mirrors m.version (both the running process's boot
        // version); target_version is the on-disk VERSION. Surface the explicit
        // running/target pair in the tooltip so the drift is obvious.
        const running = wd.running_version || m.version;
        const target = wd.target_version || '';
        // A red dot must say WHAT to do — an alarming dot with a vague tooltip is
        // worse than no dot. The hub sends update_fault_reason already phrased
        // for a human; fall back to a generic line only if it's missing.
        const stuckMin = wd.stuck_for_s != null ? Math.round(wd.stuck_for_s / 60) : null;
        const title = bad
            ? `UPDATE NOT PROGRESSING — running ${running}${target && target !== running ? `, disk has ${target}` : ''}`
              + (wd.update_fault_reason ? `. ${wd.update_fault_reason}` : '')
              + ((wd.bad_versions || []).length ? ` Bad versions: ${(wd.bad_versions || []).join(', ')}.` : '')
              + (stuckMin != null ? ` Pending ${stuckMin} min.` : '')
              + ' Check Setup → Diagnostics and the hub log; this will not clear on its own.'
            : behind
                ? `Behind — disk has ${target} but running ${running}; restart pending (watchdog will in-window)`
                : updateAvail
                    ? `Update available — a newer version is on the remote (running ${running}); click Update to pull`
                    : `Up to date (running ${running})`;
        // Match the green glow the hub/module online dots carry
        // (shadow-[0_0_6px_rgba(34,197,94,0.5)]) so the version dot reads as the
        // same shade of green, not a flatter one. Only green gets the halo; the
        // amber behind/update-available tone stays flat (matches the amber dots).
        // Red gets a halo too — a fault should be as visually loud as healthy is
        // reassuring; only the amber "pending" tone stays flat.
        const dotGlow = bad ? ' shadow-[0_0_6px_rgba(239,68,68,0.6)]'
            : (behind || updateAvail) ? '' : ' shadow-[0_0_6px_rgba(34,197,94,0.5)]';
        versionEl.innerHTML = `<span class="inline-block w-2 h-2 rounded-full ${dotTone}${dotGlow} transition-all align-middle mr-1.5" title="${escapeHtml(title)}"></span>Version | ${escapeHtml(m.version)}`;
        window.__lmHubVersion = m.version;  // for File-a-Bug context (running version)
        window.__lmTargetVersion = target || null;  // on-disk VERSION, for the Update toast
        _checkWebuiVersionDrift(m.version);
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
        const data = await apiJson('/setup/rate-limit-drops/reset', { method: 'POST' });
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
        const data = await apiJson('/setup/hub-backlog/purge', { method: 'POST' });
        if (typeof showToast === 'function') showToast(`Dropped ${data.dropped} backlog message(s).`, 'success');
        updateStatus();  // refresh the tiles/detail
    } catch (e) {
        if (typeof showToast === 'function') showToast(`Drop backlog failed: ${e.message}`, 'error');
        else showToast(`Drop backlog failed: ${e.message}`, 'error');
    } finally {
        if (btn) { btn.disabled = false; btn.textContent = 'Drop Backlog'; }
    }
}

// Restart the hub service (admin, System → Hub Status). No confirmation —
// this is a deliberate admin action reachable only from an already-gated
// admin page; the hub (and this WebUI session) briefly drops while
// lm.service cycles.
async function restartHubService() {
    const btn = document.getElementById('restart-hub-btn');
    if (btn) { btn.disabled = true; btn.textContent = 'Restarting…'; }
    try {
        const data = await apiJson('/setup/hub/restart', { method: 'POST' });
        showToast(`${data.message || 'Hub restarting'} — reloading in ~8s…`, 'success');
        setTimeout(() => location.reload(), 8000);
    } catch (e) {
        showToast(`Restart failed: ${e.message}`, 'error');
        if (btn) { btn.disabled = false; btn.textContent = '♻️ Restart hub service'; }
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
        const data = await apiJson('/setup/config');
        const g = (data.global_config && data.global_config.update_gate) || {};
        window.__lmUpdateGateCfg = g;
        const setv = (id, v) => { const el = document.getElementById(id); if (el && document.activeElement !== el) el.value = v; };
        setv('ug-mode', g.mode || _UG_DEFAULTS.mode);
        setv('ug-window-hour', g.window_hour !== undefined ? g.window_hour : _UG_DEFAULTS.window_hour);
        setv('ug-window-duration', g.window_duration_h !== undefined ? g.window_duration_h : _UG_DEFAULTS.window_duration_h);
        setv('ug-timezone', g.timezone || '');
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
    let browserTz = '';
    try { browserTz = Intl.DateTimeFormat().resolvedOptions().timeZone || ''; } catch (e) { /* ignore */ }
    setv('ug-timezone', browserTz);
    if (typeof showToast === 'function') showToast(`Defaults filled (02:00 ${browserTz || 'hub clock'} window) — click Save to apply.`, 'info');
}

async function saveUpdateGateConfig() {
    const btn = document.getElementById('ug-save-btn');
    const merged = Object.assign({}, window.__lmUpdateGateCfg || {}, {
        mode: document.getElementById('ug-mode').value,
        window_hour: Number(document.getElementById('ug-window-hour').value),
        window_duration_h: Number(document.getElementById('ug-window-duration').value),
        timezone: (document.getElementById('ug-timezone').value || '').trim(),
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
        const data = await apiJson('/setup/config');
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
        if (typeof showToast === 'function') showToast(m, 'error'); else showToast(m, 'success');
        return;
    }
    if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
    try {
        const data = await apiJson('/setup/config', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ config: { backpressure: merged } }),
        });
        window.__lmBackpressureCfg = merged;
        if (typeof showToast === 'function')
            showToast('Backpressure tuning saved — applies live on the next tick.', 'success');
    } catch (e) {
        if (typeof showToast === 'function') showToast(`Save failed: ${e.message}`, 'error');
        else showToast(`Save failed: ${e.message}`, 'error');
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
        if (typeof showToast === 'function') showToast(msg, 'error'); else showToast(msg, 'success');
        return;
    }
    if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
    try {
        const data = await apiJson('/setup/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ config: { rate_limit: { capacity, fill_rate } } }),
        });
        if (typeof showToast === 'function')
            showToast(`Rate limit saved (burst ${capacity}, ${fill_rate}/s). Applies as spokes reconnect.`, 'success');
    } catch (e) {
        if (typeof showToast === 'function') showToast(`Save rate limit failed: ${e.message}`, 'error');
        else showToast(`Save rate limit failed: ${e.message}`, 'error');
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
            error: !!s.last_error,
            // Friendly label for the tray tooltip — the spoke_id is a GUID after
            // the guid-primary migration; show the name, keep the id on hover.
            name: _spokeName(s),
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

        if (className === 'Console') {
            // Icon #11 (Console) from LM_NAV_ICONS — the terminal/prompt glyph
            // requested for the Console module.
            icon = '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" d="M6.75 7.5l3 2.25-3 2.25m4.5 0h3m-9 8.25h13.5A2.25 2.25 0 0021 18V6a2.25 2.25 0 00-2.25-2.25H5.25A2.25 2.25 0 003 6v12a2.25 2.25 0 002.25 2.25z"></path></svg>';
        } else if (className === 'Firewalls') {
            icon = '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>';
        } else if (className === 'Hypervisors') {
            icon = '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12H3m18 0h-2M12 5V3m0 18v-2m5.657-14.343l-1.414 1.414M6.757 17.243l-1.414 1.414m12.728 0l-1.414-1.414M6.757 6.757L5.343 5.343M12 8a4 4 0 100 8 4 4 0 000-8z"></path></svg>';
        } else if (className === 'NAC') {
            icon = '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg>';
        } else if (className === 'IPAM') {
            icon = '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zm10 0a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zm10 0a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M8 8v2m0 4v-2m8-2v2m0 4v-2M8 12h8"></path></svg>';
        } else if (className === 'Simulations') {
            icon = '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z"></path></svg>';
        } else if (className === 'DNS') {
            icon = '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3.6 9h16.8M3.6 15h16.8M11.5 3a17 17 0 000 18M12.5 3a17 17 0 010 18"></path></svg>';
        } else if (className === 'DHCP') {
            // Inbox + down-arrow — a device RECEIVES an IP address lease handed
            // out by the DHCP server; distinct from DNS (globe) and Network (nodes).
            icon = '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" d="M9 3.75H6.912a2.25 2.25 0 00-2.15 1.588L2.35 13.177a2.25 2.25 0 00-.1.661V18a2.25 2.25 0 002.25 2.25h15A2.25 2.25 0 0021.75 18v-4.162c0-.224-.034-.447-.1-.661L19.24 5.338a2.25 2.25 0 00-2.15-1.588H15M2.25 13.5h3.86a2.25 2.25 0 012.012 1.244l.256.512a2.25 2.25 0 002.013 1.244h3.218a2.25 2.25 0 002.013-1.244l.256-.512a2.25 2.25 0 012.013-1.244h3.859M12 3v8.25m0 0l-3-3m3 3l3-3"></path></svg>';
        } else if (className === 'Network') {
            // Connected nodes (topology) — network switches/gateways; visually
            // distinct from the DNS globe (they previously shared a globe icon).
            icon = '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="6" cy="6" r="2.25" stroke-width="2"></circle><circle cx="18" cy="6" r="2.25" stroke-width="2"></circle><circle cx="12" cy="18" r="2.25" stroke-width="2"></circle><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.25 6h7.5M7.2 7.9l3.6 8.2M16.8 7.9l-3.6 8.2"></path></svg>';
        } else if (className === 'Certificates') {
            icon = '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m-6-8h6M5 21h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v14a2 2 0 002 2z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M14.5 19.5l1.5 1.5 2.5-2.5"></path></svg>';
        } else if (className === 'Storage') {
            icon = '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.6" d="M5.25 14.25h13.5m-13.5 0a3 3 0 01-3-3m3 3a3 3 0 100 6h13.5a3 3 0 100-6m-16.5-3a3 3 0 013-3h13.5a3 3 0 013 3m-19.5 0a4.5 4.5 0 01.9-2.7L5.737 5.1a3.375 3.375 0 012.7-1.35h7.126c1.062 0 2.062.5 2.7 1.35l2.587 3.45a4.5 4.5 0 01.9 2.7m0 0a3 3 0 01-3 3m0 3h.008v.008h-.008v-.008zm0-6h.008v.008h-.008V8.25zm-3 6h.008v.008h-.008v-.008zm0-6h.008v.008h-.008V8.25z"></path></svg>';
        } else if (firstProduct && window.VIEWS && window.VIEWS[firstProduct]) {
            icon = window.VIEWS[firstProduct].icon || '';
        }

        return `
            <div onclick="setView('${className}')" id="nav-${className}" class="nav-item ${isActive} p-3 rounded-r-lg flex items-center gap-3 text-xs font-medium">
                <div>${icon}</div>
                <span>${className}</span>
            </div>
        `;
    }).join('');

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
    const _bugReportNavHtml = () => `
        <div onclick="setView('bugs')" id="nav-bugs" class="nav-item p-3 rounded-r-lg flex items-center gap-3 text-xs font-medium">
            <div><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M4.5 8.5l2-1.5m13 1.5l-2-1.5M4.5 15.5l2 1.5m13-1.5l-2 1.5M12 4a4 4 0 014 4v4a4 4 0 01-8 0V8a4 4 0 014-4z"></path></svg></div>
            <span>Bug Report</span>
        </div>`;
    // Feature Request — admin-only sibling of Bug Report. Same store, filtered
    // to type=feature (loadBugReports('feature')); filed by ab as an
    // ``enhancement`` issue (no auto-fix). See memory file-a-bug-feature.
    const _featureRequestNavHtml = () => `
        <div onclick="setView('features')" id="nav-features" class="nav-item p-3 rounded-r-lg flex items-center gap-3 text-xs font-medium">
            <div><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09zM18.259 8.715L18 9.75l-.259-1.035a3.375 3.375 0 00-2.455-2.456L14.25 6l1.036-.259a3.375 3.375 0 002.455-2.456L18 2.25l.259 1.035a3.375 3.375 0 002.456 2.456L21.75 6l-1.035.259a3.375 3.375 0 00-2.456 2.456z"></path></svg></div>
            <span>Feature Request</span>
        </div>`;
    const _templateRepoNavHtml = () => `
        <div onclick="setView('templates')" id="nav-templates" class="nav-item p-3 rounded-r-lg flex items-center gap-3 text-xs font-medium">
            <div><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4"></path></svg></div>
            <span>Template Repo</span>
        </div>`;
    const _myDevicesNavHtml = () => `
        <div onclick="setView('mydevices')" id="nav-mydevices" class="nav-item p-3 rounded-r-lg flex items-center gap-3 text-xs font-medium">
            <div><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01"></path></svg></div>
            <span>My Devices</span>
        </div>`;
    // Reports is a hub-side feature (no product spoke), so it never enters the
    // spoke-driven activeClasses list — it's a STATIC nav item gated by the
    // 'reports' right (canSeeModule), NOT admin-only.
    const _reportsNavHtml = () => `
        <div onclick="setView('reports')" id="nav-reports" class="nav-item p-3 rounded-r-lg flex items-center gap-3 text-xs font-medium">
            <div><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" d="M8 17V11m4 6V7m4 10v-4M5 21h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v14a2 2 0 002 2z"></path></svg></div>
            <span>Reports</span>
        </div>`;
    // Directory (LDAP/Entra) — a standalone tenant-scoped view (setView('ldap')),
    // NOT a MODULE_CLASSES class. Shown once a directory spoke is loaded
    // (activeProducts has 'ldap' via MODULE_TYPE_PRODUCT) AND the caller has the
    // 'ldap' right (canSeeModule) — so a tenant-admin managing their own OU sees
    // it too, not just global admins. People/id icon.
    const _directoryNavHtml = () => `
        <div onclick="setView('ldap')" id="nav-ldap" class="nav-item p-3 rounded-r-lg flex items-center gap-3 text-xs font-medium">
            <div><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z"></path></svg></div>
            <span>Directory</span>
        </div>`;
    // Security (threat monitor) — admin-only hub-side view; static like Reports.
    const _securityNavHtml = () => `
        <div onclick="setView('security')" id="nav-security" class="nav-item p-3 rounded-r-lg flex items-center gap-3 text-xs font-medium">
            <div><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg></div>
            <span>Security</span>
        </div>`;
    // OS Updates — fleet OS patching (hub_os_updates.py); Global Admin only,
    // like its /api/os-updates routes. Download-tray icon.
    const _osUpdatesNavHtml = () => `
        <div onclick="setView('osupdates')" id="nav-osupdates" class="nav-item p-3 rounded-r-lg flex items-center gap-3 text-xs font-medium">
            <div><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3"></path></svg></div>
            <span>OS Updates</span>
        </div>`;
    // Cert Expiry Monitor — Global Admin only, and only once switched on in
    // System → General (window.__lmCertMonEnabled, from /api/certmon/status).
    const _certMonNavHtml = () => `
        <div onclick="setView('certmon')" id="nav-certmon" class="nav-item p-3 rounded-r-lg flex items-center gap-3 text-xs font-medium">
            <div><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" d="M9 12.75L11.25 15 15 9.75M21 12c0 1.268-.63 2.39-1.593 3.068a3.745 3.745 0 01-1.043 3.296 3.745 3.745 0 01-3.296 1.043A3.745 3.745 0 0112 21c-1.268 0-2.39-.63-3.068-1.593a3.746 3.746 0 01-3.296-1.043 3.745 3.745 0 01-1.043-3.296A3.745 3.745 0 013 12c0-1.268.63-2.39 1.593-3.068a3.745 3.745 0 011.043-3.296 3.746 3.746 0 013.296-1.043A3.746 3.746 0 0112 3c1.268 0 2.39.63 3.068 1.593a3.746 3.746 0 013.296 1.043 3.746 3.746 0 011.043 3.296A3.745 3.745 0 0121 12z"></path></svg></div>
            <span>Cert Monitor</span>
        </div>`;
    // Credential Vault — hub-side per-tenant secret locker (routes/cred_vault.py,
    // /tenant/cred-vault/*). Reachable by a tenant-admin (own-tenant buckets) OR
    // a Global Admin (any tenant + the __admin__ infrastructure slot); the
    // server enforces reach + pass-phrase on every read/write. Padlock icon.
    const _credVaultNavHtml = () => `
        <div onclick="setView('credvault')" id="nav-credvault" class="nav-item p-3 rounded-r-lg flex items-center gap-3 text-xs font-medium">
            <div><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8" d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z"></path></svg></div>
            <span>Credential Vault</span>
        </div>`;

    mainNav.innerHTML = `
        ${dynamicHtml}
        ${((window.activeProducts && window.activeProducts.has('ldap')) && canSeeModule('Directory')) ? _directoryNavHtml() : ''}
        ${canSeeModule('Reports') ? _reportsNavHtml() : ''}
        <div class="pt-4 mt-4 border-t border-slate-200"></div>
        ${isAdmin() ? adminSetup : ''}
        ${isAdmin() ? adminSettings : ''}
        ${isAdmin() ? adminLogs : ''}
        ${isAdmin() ? _securityNavHtml() : ''}
        ${(isAdmin() || isTenantAdmin()) ? _osUpdatesNavHtml() : ''}
        ${(isAdmin() && window.__lmCertMonEnabled) ? _certMonNavHtml() : ''}
        ${(isAdmin() || isTenantAdmin()) ? _credVaultNavHtml() : ''}
        ${isAdmin() ? _templateRepoNavHtml() : ''}
        ${(isAdmin() || isTenantAdmin()) ? _bugReportNavHtml() : ''}
        ${(isAdmin() || isTenantAdmin()) ? _featureRequestNavHtml() : ''}
        ${(!isAdmin() && isTenantAdmin()) ? _myDevicesNavHtml() : ''}
    `;

    // Normalize the nav font size across every item. The admin items (Setup/
    // System/Logs) come from the STATIC index.html (captured via _getNavHtml),
    // which isn't cache-busted — a stale copy can still carry text-sm while the
    // JS-injected items are text-xs, making one item (e.g. Logs) look larger.
    // Force text-xs on all so they always match regardless of the cached HTML.
    mainNav.querySelectorAll('.nav-item').forEach(el => {
        el.classList.remove('text-sm');
        el.classList.add('text-xs');
    });

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
// ab) move to Agents. Proxmox node agents are fetched separately via
// GET /api/pxmx/agents and appended. Each row is rendered by the shared
// _renderSpokeAgentRow() helper above. The pxmx agents fetch is best-effort —
// on failure the generic agents still render (see catch below).
async function _renderDashboardLists(allSpokes, approvedSpokes, connections) {
    // Split known modules by module_type: infrastructure spokes (including
    // the pxmx "hypervisor" spoke) stay in the Spokes list; only generic
    // Hub-direct agents (module_type "agent", e.g. ab) move to the
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
                // Friendly name. GOTCHA: the backend (/setup/pending_spokes,
                // setup.py) defaults display_name to the spoke_id (UUID) when a
                // spoke is unnamed — so display_name is NEVER empty and a plain
                // `display_name || hostname` always showed the UUID. Treat
                // display_name===id as "unset" and fall through to the reported
                // hostname before the UUID. GUID stays on hover via idTitle.
                const name = (spoke.display_name && spoke.display_name !== id)
                    ? spoke.display_name
                    : (spoke.hostname || id);
                const mod = moduleLabel(spoke.module_type);
                const status = !spoke.approved ? 'pending'
                    : (connections.includes(id) ? 'online' : 'offline');
                return _renderSpokeAgentRow(_nodeLabel(name, spoke.tenant_id), mod, status, true, spoke.tenant_id, id,
                    { revoked: spoke.revoked, revoke_reason: spoke.revoke_reason, revoked_by: spoke.revoked_by, revoked_ts: spoke.revoked_ts });
            }).join('');
        }
    }

    const agentList = document.getElementById('agent-list');
    const agentCount = document.getElementById('agent-count');
    if (!agentList) return;
    // Generic Hub-direct agents (module_type "agent") from /setup/pending_spokes.
    const hubAgentRows = [
        ...approvedHubAgents.map(a => ({ id: a.spoke_id, label: _nodeLabel((a.display_name && a.display_name !== a.spoke_id) ? a.display_name : (a.hostname || a.spoke_id), a.tenant_id), status: connections.includes(a.spoke_id) ? 'online' : 'offline', mod: moduleLabel(a.module_type), rv: { revoked: a.revoked, revoke_reason: a.revoke_reason, revoked_by: a.revoked_by, revoked_ts: a.revoked_ts } })),
        ...pendingHubAgents.map(a => ({ id: a.spoke_id, label: _nodeLabel((a.display_name && a.display_name !== a.spoke_id) ? a.display_name : (a.hostname || a.spoke_id), a.tenant_id), status: 'pending', mod: moduleLabel(a.module_type), rv: { revoked: a.revoked, revoke_reason: a.revoke_reason, revoked_by: a.revoked_by, revoked_ts: a.revoked_ts } })),
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
            const agentRes = await fetch('/api/pxmx/agents?tenant=' + encodeURIComponent(currentTenant), { credentials: 'same-origin' });
            if (agentRes.ok) {
                const agentData = await agentRes.json();
                pxmxRows = [
                    ...(agentData.agents || []).map(a => ({ id: a.agent_id, label: _nodeLabel(a.display_name || a.hostname || a.agent_id, _tenantOf(a)), status: 'online', mod: 'Proxmox' })),
                    ...(agentData.pending_agents || []).map(a => ({ id: a.agent_id, label: _spokeName(a), status: 'pending', mod: 'Proxmox' })),
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
        agentList.innerHTML = all.map(a => _renderSpokeAgentRow(a.label, a.mod, a.status, false, undefined, a.id, a.rv)).join('');
    }
}

function renderSpokeIndicators() {
    const hubDot = document.getElementById('hub-status-dot');
    const moduleDot = document.getElementById('module-status-dot');
    // The dot is the entry point to the diagnostics view — it merges four
    // producers, so "what is red?" is only answerable there. Bound once.
    const _mdWrap = document.getElementById('module-status-container');
    if (_mdWrap) _mdWrap.classList.toggle('cursor-pointer', isAdmin());
    if (_mdWrap && isAdmin() && !_mdWrap._diagBound) {
        _mdWrap._diagBound = true;
        _mdWrap.title = 'Open Module Diagnostics — every producer behind this dot';
        _mdWrap.addEventListener('click', () => {
            try {
                setView('settings');
                setSubView('Diagnostics');
            } catch (e) { console.error('module-status → Diagnostics failed', e); }
        });
    }
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

        tooltipHtml += `<div class="flex items-center justify-between gap-4 py-0.5"><span class="opacity-80" title="${escapeHtml(id)}">${escapeHtml(health.name || id)}</span><div class="flex items-center gap-1.5"><div class="w-1.5 h-1.5 rounded-full ${dotColor}"></div><span class="text-[9px]">${statusText}</span></div></div>`;
    });

    let overallColor = 'bg-yellow-500';
    if (allGreen) overallColor = 'bg-green-500';
    else if (allRed) overallColor = 'bg-red-500';

    moduleDot.className = `w-2 h-2 rounded-full ${overallColor} transition-all`;

    // Append a forgiving out-of-contact alert summary (SpokeAlertMixin) to the
    // tooltip. Distinct from the realtime dots above — these fire only after a
    // spoke has been out of contact >=5m (warning) / >=30m (error). A sustained
    // spoke/agent outage also turns the module dot red so an operator scanning
    // the header notices it.
    const alerts = Array.isArray(window.activeAlerts) ? window.activeAlerts : [];
    let alertHtml = '';
    if (alerts.length) {
        // MODULE STATUS reports SPOKE AND AGENT health — nothing else may colour
        // it. Fleet-availability and out-of-dongles ride the same /status channel
        // but describe lab capacity (a degraded client fleet, a host with no
        // working dongles left); neither is a module that can be up or down, so a
        // dongle shortage turning this dot red made every spoke look unhealthy.
        // They stay listed below for visibility, under their own headings.
        // Agent out-of-contact counts too. A relayed pxmx/cs agent IS a module
        // that can be up or down — and it is the one the spoke sweep cannot
        // see, so excluding it is exactly how four dead agents kept the dot
        // green while their (healthy) parent spokes reported in.
        const _MODULE_SOURCES = new Set(['spoke_out_of_contact', 'agent_out_of_contact']);
        const isSpokeAlert = a => _MODULE_SOURCES.has(a.source || 'spoke_out_of_contact');
        const hasErr = alerts.some(a => isSpokeAlert(a) && String(a.tier) === 'error');
        if (hasErr) overallColor = 'bg-red-500';
        moduleDot.className = `w-2 h-2 rounded-full ${overallColor} transition-all`;
        const esc = escapeHtml;  // shared escaper (escapes &<>"')
        const row = a => { const _h = (window.spokeHealth || {})[a.spoke_id]; const _nm = (a.display_name || a.name || (_h && _h.name) || a.spoke_id); return `<div class="flex items-center justify-between gap-4 py-0.5"><span class="opacity-80" title="${esc(a.spoke_id)}">${esc(_nm)}</span><div class="flex items-center gap-1.5"><div class="w-1.5 h-1.5 rounded-full ${a.tier === 'error' ? 'bg-red-400' : 'bg-amber-400'}"></div><span class="text-[9px]">${a.tier}</span></div></div>`; };
        // Group by PRODUCER. Only spoke_out_of_contact entries are spokes/agents
        // that stopped talking to the hub; fleet-availability and out-of-dongles
        // are lab-capacity signals keyed on synthetic ids (fleet:<tenant> /
        // dongles:<host>). Listing them all under one "Out-of-contact alerts"
        // heading read as "these hosts went silent", which they had not. An
        // untagged entry (older hub) falls back to out-of-contact = old behaviour.
        const GROUPS = [
            ['spoke_out_of_contact', 'Out-of-contact alerts'],
            ['agent_out_of_contact',  'Agents out of contact'],
            ['fleet_availability',   'Fleet availability'],
        ];
        alertHtml = GROUPS.map(([src, label]) => {
            const inGroup = alerts.filter(a => (a.source || 'spoke_out_of_contact') === src);
            if (!inGroup.length) return '';
            return `<div class="mt-2 pt-2 border-t border-white/15">
            <div class="text-[9px] uppercase opacity-60 mb-1">${esc(label)}</div>
            ${inGroup.map(row).join('')}
        </div>`;
        }).join('');
    }
    tooltipEl.innerHTML = tooltipHtml + alertHtml;
}

async function setView(viewId) {
    if ((viewId === 'setup' || viewId === 'settings' || viewId === 'logs') && !isAdmin()) {
        return;  // silently block — nav items are hidden, this guards deep-links
    }
    // Bug Report / Feature Request — Global Admin (full) OR tenant-admin (their
    // own tenant, read-only). Guards deep-links for everyone else.
    if ((viewId === 'bugs' || viewId === 'features') && !(isAdmin() || isTenantAdmin())) {
        return;
    }
    // My Devices is the tenant-admin device surface — reachable only by a
    // tenant-admin (or a Global Admin); guards deep-links for everyone else.
    if (viewId === 'mydevices' && !(isTenantAdmin() || isAdmin())) {
        return;
    }
    // Credential Vault — reachable by a tenant-admin (own-tenant buckets) or a
    // Global Admin; the server enforces per-bucket reach + pass-phrase on top.
    if (viewId === 'credvault' && !(isTenantAdmin() || isAdmin())) {
        return;
    }
    if (viewId === 'osupdates' && !(isAdmin() || isTenantAdmin())) {
        return;
    }
    // Cert Expiry Monitor — Global Admin only, and only while enabled.
    if (viewId === 'certmon' && !(isAdmin() && window.__lmCertMonEnabled)) {
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
            showToast('No active products available for this category.', 'success');
            return;
        }

        // Some multi-product classes render ONE unified view with the other
        // products surfaced as subtabs (DNS = Unbound Overview/Records/
        // Forwarders + an External DNS subtab). Such a class pins to its primary
        // view regardless of which product(s) are active — external providers
        // (henet, …) have no standalone view, and the class name is never a real view.
        const primaryView = CLASS_PRIMARY_VIEW[viewId];
        if (primaryView) {
            currentView = primaryView;
            currentProduct = products[0];
        } else if (products.length === 1) {
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
    currentSubGrandchild = _csDefaultGrandchild(currentView, currentSubView, currentSubChild);
    _lmNavSeq++;
    document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
    const navItem = document.getElementById(`nav-${isClass ? viewId : currentView}`);
    if (navItem) navItem.classList.add('active');

    // Auto-minimize the serial console dock when navigating to another view.
    // The dock is a fixed overlay that covers the page, so clicking a left-menu
    // item would otherwise leave the console sitting on top of the destination.
    // Collapsing keeps every session connected (footer pill restores it), so
    // this is non-destructive — same as pressing Minimize.
    if (prevView !== currentView && !window._serialDockCollapsed &&
        document.getElementById('serial-console-modal') &&
        typeof serialSetDockCollapsed === 'function') {
        serialSetDockCollapsed(true);
    }
    // Same treatment for the VM (noVNC) console dock — also a fixed overlay.
    if (prevView !== currentView && !window._pxmxDockCollapsed &&
        document.getElementById('pxmx-vnc-modal') &&
        typeof pxmxSetDockCollapsed === 'function') {
        pxmxSetDockCollapsed(true);
    }

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
// entry ever matches per call; a view with no entry here intentionally no-ops
// (and is re-rendered via setView instead). cs is wrapped because its loader
// (loadCSData, defined in sim-views.js) takes (subMenu, currentSubChild);
// the child is resolved above via _csDefaultChild. opnsense is wrapped because
// loadOpnsenseManagement() takes no argument (it reads the currentSubView global).
const VIEW_LOADERS = {
    // dashboard has real per-tenant content (summary tiles + infra status), so it
    // needs a loader too. A tenant switch re-renders through setSubView (not
    // setView, which would reset the active tab), and with no entry here the
    // Overview silently kept showing the PREVIOUS tenant's data until a manual
    // reload. Mirrors initView('dashboard') without re-rendering the layout.
    dashboard: () => {
        updateStatus();
        if (isAdmin()) loadAllTenantsOverview(); else loadDashboardSummary();
        loadInfraStatus();
    },
    opnsense: () => loadOpnsenseManagement(),
    cppm:     (subMenu) => loadCPPMData(subMenu),
    pxmx:     (subMenu) => loadPxmxData(subMenu),
    ldap:     (subMenu) => loadLDAPData(subMenu),
    netbox:   (subMenu) => loadNetboxData(subMenu),
    dns:      (subMenu) => loadDNSData(subMenu),
    dhcp:     (subMenu) => loadDHCPData(subMenu),
    nw:       (subMenu) => loadNwData(subMenu),
    le:       (subMenu) => loadLEData(subMenu),
    console:  (subMenu) => loadConsoleData(subMenu),
    truenas:  (subMenu) => loadTruenasData(subMenu),
    cs:       (subMenu) => loadCSData(subMenu, currentSubChild),
    setup:    (subMenu) => _renderSetupSection(subMenu),
    settings: (subMenu) => _renderSettingsSection(subMenu),
    logs:     (subMenu) => _renderLogsSection(subMenu),
};

async function setSubView(subMenu) {
    if (subMenu === 'Diagnostics' && !isAdmin()) return;
    _lmNavSeq++;
    currentSubView = subMenu;
    // Leaving the Certificates tab: stop the in-flight distribution poller/
    // ticker so it doesn't keep fetching /api/le/inflight in the background.
    // (loadLEData restarts them when the tab is re-entered.)
    if (currentView !== 'le') clearLeInflightPollers();
    // Reset the child (and grandchild, three-tier nav) for the newly-selected
    // primary. For non-cs/non-Cloud modules _csDefaultChild returns '' and the
    // secondary strip is hidden by renderSecondaryNav (same for the tertiary
    // strip when the child has no grandchildren).
    currentSubChild = _csDefaultChild(currentView, subMenu);
    currentSubGrandchild = _csDefaultGrandchild(currentView, subMenu, currentSubChild);

    // Update active state in top-nav
    document.querySelectorAll('#top-nav .sub-nav-item').forEach(el => {
        el.classList.toggle('active', el.dataset.submenu === subMenu);
    });

    // Show/hide + populate the secondary child strip for this primary.
    renderSecondaryNav(currentView);

    // Dispatch to the active module's loader (see VIEW_LOADERS above). Views
    // with no entry (mydevices, credvault, ...) intentionally no-op, matching
    // the previous fall-through behavior of the if/else chain.
    const loader = VIEW_LOADERS[currentView];
    if (loader) {
        const res = loader(subMenu);
        if (res && typeof res.finally === 'function') {
            res.finally(() => {
                if (typeof _lmActiveFetchCount !== 'undefined' && _lmActiveFetchCount === 0) {
                    setTimeout(window.dismissLoadingToast, 200);
                }
            });
        }
    }
}

function renderTopNav(viewId) {
    const topNav = document.getElementById('top-nav');
    if (!topNav) return;
    // CS (Simulations) is now a set of native LM views (see sim-views.js); it
    // gets a normal sub-nav strip like every other spoke.
    // Logs is dynamic: only show tabs for modules that are actually installed
    // (see logsSubmenu). Every other view uses its fixed VIEW_SUBMENUS list.
    const rawSubmenus = (viewId === 'logs') ? logsSubmenu() : (VIEW_SUBMENUS[viewId] || []);
    const subMenus = rawSubmenus.filter(m => {
        if (m === 'Diagnostics' && !isAdmin()) return false;
        if (m === 'Simulations' && !isAdmin()) return false;
        // The NW "Scan" tab lets a tenant configure + run discovery scans on
        // their own NW spoke(s) and set a recurring scan schedule + poll
        // jitter/caps — admin & tenant-admin only (writes tenant config).
        if (m === 'Scan' && currentView === 'nw' && !(isAdmin() || isTenantAdmin())) return false;
        // The External DNS subtab (under DNS) now has real per-tenant records
        // (each carries an explicit tenant_id) — visible to anyone with the
        // 'dns' right (DNS is "all things DNS", internal + external) OR the
        // distinct 'henet' right (grantable on its own, e.g. a user who should
        // manage External DNS but not the internal Unbound config). A DNS-view
        // / tenant-admin user sees only their OWN tenant's records (the server
        // filters /api/henet/records; write actions additionally need
        // tenant-admin tier — see canEdit()/isTenantAdmin() gating below).
        if (m === 'External DNS' && !(canSeeModule('DNS') || canSeeModule('HE.NET'))) return false;
        // It also only appears once ANY internet-facing DNS provider spoke
        // (HE.NET, …) is connected. See EXTERNAL_DNS_PROVIDERS.
        if (m === 'External DNS' && _externalDnsConnected().length === 0) return false;
        return true;
    });
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
    // Uniform sub-nav tab styling across every view (Setup / System / Logs / …)
    // so they all match: tighter horizontal padding + normal letter-spacing so
    // the many-tab views (Logs) fit without a per-view special case.
    const _tabCls = 'px-1.5 py-1 text-xs uppercase tracking-normal';
    topNav.innerHTML = subMenus.map((menu, i) => {
        const label = SUBMENU_LABELS[menu] || menu;
        return `<div class="sub-nav-item ${i === 0 ? 'active' : ''} ${_tabCls} cursor-pointer select-none" data-submenu="${menu}" onclick="setSubView('${menu}')">${label}</div>`;
    }).join('') + '<div id="top-nav-actions" class="ml-auto flex items-center gap-2"></div>' + helpBtn;
    // Keep the secondary child strip in sync with the active primary.
    renderSecondaryNav(viewId);
}

// Render the second-tier child strip (#top-nav-secondary) for the active
// primary of a two-tier module (cs) — or the middle tier of a three-tier one
// (settings/Cloud). Populates it with the primary's children and highlights
// currentSubChild; hides the strip entirely for primaries/modules without
// children so non-cs modules and childless cs primaries are unaffected. Also
// keeps the tertiary (grandchild) strip in sync, since it depends on the
// active child.
function renderSecondaryNav(viewId) {
    const sec = document.getElementById('top-nav-secondary');
    if (!sec) return;
    const kids = (VIEW_CHILDREN[viewId] || {})[currentSubView] || null;
    if (!kids || !kids.length) {
        sec.classList.add('hidden');
        sec.innerHTML = '';
        renderTertiaryNav(viewId);
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
    renderTertiaryNav(viewId);
}

// Render the third-tier grandchild strip (#top-nav-tertiary), nested under the
// active child (e.g. Settings → Cloud → Azure → SSO/NSG/…). Hides the strip
// when the active child has no grandchildren (VIEW_GRANDCHILDREN) — every
// module except Settings → Cloud today.
function renderTertiaryNav(viewId) {
    const ter = document.getElementById('top-nav-tertiary');
    if (!ter) return;
    const gkids = ((VIEW_GRANDCHILDREN[viewId] || {})[currentSubView] || {})[currentSubChild] || null;
    if (!gkids || !gkids.length) {
        ter.classList.add('hidden');
        ter.innerHTML = '';
        return;
    }
    const activeGrandchild = currentSubGrandchild || gkids[0];
    ter.innerHTML = gkids.map((gchild) =>
        `<div class="sub-nav-item ${gchild === activeGrandchild ? 'active' : ''} px-2 py-1 cursor-pointer select-none" data-subgrandchild="${gchild}" onclick="setSubGrandchild('${gchild.replace(/'/g, "\\'")}')">${gchild}</div>`
    ).join('');
    ter.classList.remove('hidden');
}

// Select a child tab within the current primary (two-tier nav, e.g. cs) — or
// the middle tier of a three-tier nav (settings/Cloud, e.g. 'Azure'/'OCI').
// Sets currentSubChild, resets currentSubGrandchild to the new child's first
// grandchild, updates the secondary strip's active state + the tertiary strip,
// and dispatches the child renderer.
async function setSubChild(child) {
    _lmNavSeq++;
    currentSubChild = child;
    currentSubGrandchild = _csDefaultGrandchild(currentView, currentSubView, child);
    document.querySelectorAll('#top-nav-secondary .sub-nav-item').forEach(el => {
        el.classList.toggle('active', el.dataset.subchild === child);
    });
    renderTertiaryNav(currentView);
    if (currentView === 'cs') {
        await loadCSData(currentSubView, child);
    } else if (currentView === 'settings') {
        // Re-render the current settings primary (e.g. Cloud) — it reads
        // currentSubChild/currentSubGrandchild to pick the right provider + tile.
        _renderSettingsSection(currentSubView);
    }
}
window.setSubChild = setSubChild;

// Select a grandchild tab within the current child (three-tier nav, e.g.
// Settings → Cloud → Azure → 'NSG'). Sets currentSubGrandchild, updates the
// tertiary strip's active state, and re-renders the settings tile.
function setSubGrandchild(gchild) {
    _lmNavSeq++;
    currentSubGrandchild = gchild;
    document.querySelectorAll('#top-nav-tertiary .sub-nav-item').forEach(el => {
        el.classList.toggle('active', el.dataset.subgrandchild === gchild);
    });
    if (currentView === 'settings') {
        _renderSettingsSection(currentSubView);
    }
}
window.setSubGrandchild = setSubGrandchild;

function renderView(viewId) {
    const vp = document.getElementById('viewport');
    if (!vp) return;
    vp.innerHTML = _viewTemplate(viewId);
    _applyEditVisibility();   // hide row Edit/Delete for view users (CSS-based)
}

function _viewTemplate(viewId) {
    const card = 'hpe-card rounded-lg p-5 shadow-sm';
    const input = 'w-full bg-white border border-slate-300 rounded-md px-4 py-2 text-sm outline-none focus:ring-2 focus:ring-green-500 text-slate-800';
    const btn = 'bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-6 py-2 rounded-md text-sm font-bold transition-all shadow-sm';

    switch (viewId) {
        case 'dashboard':
            if (isAdmin()) {
                return `<div class="space-y-6">
  <div class="${card}" id="infra-status-card">
    <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-3">Infrastructure Status</h3>
    <div id="infra-status-body"><p class="text-sm text-slate-400 italic">Loading…</p></div>
  </div>
  <div class="${card}" id="all-tenants-card">
    <div class="flex justify-between items-center mb-3">
      <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">All Tenants ${helpIcon('architecture-topology', null, 'Dashboard help')}</h3>
    </div>
    <div id="all-tenants-overview"><p class="text-sm text-slate-400 italic">Loading tenants…</p></div>
  </div>
</div>`;
            }
            return `<div class="space-y-6">
  <div class="${card}" id="infra-status-card">
    <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-3">Infrastructure Status</h3>
    <div id="infra-status-body"><p class="text-sm text-slate-400 italic">Loading…</p></div>
  </div>
  <div class="${card}" id="tenant-summary-card">
    <div class="flex justify-between items-center mb-3">
      <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Tenant Summary — <span id="dash-tenant-name" class="text-[#01A982] font-mono normal-case"></span> ${helpIcon('architecture-topology', null, 'Dashboard help')}</h3>
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

        case 'truenas':
            return `<div class="space-y-4">
  <div id="truenas-table-container" class="${card}">
    <div class="py-12 text-center text-slate-400 italic">Loading storage…</div>
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
    <div id="all-devices-tabs" class="mb-3"></div>
    <div id="all-devices-list" class="space-y-2"><p class="text-xs text-slate-400 italic animate-pulse">Loading…</p></div>
  </div>

  <div class="${card}">
    <div class="flex items-center justify-between mb-4">
      <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Spokes &amp; Agents</h3>
      <button onclick="loadMyDeviceSpokes()" class="text-xs text-[#01A982] hover:underline">Refresh</button>
    </div>
    <p class="text-xs text-slate-400 mb-3">Every spoke and agent bound to your tenant — approved or awaiting approval, connected or offline. Your first spoke can onboard itself with an onboarding key below (no admin approval needed).</p>
    <div id="my-spokes-list" class="space-y-2"><p class="text-xs text-slate-400 italic animate-pulse">Loading…</p></div>
  </div>

  <div class="${card}">
    <div class="flex items-center justify-between mb-4">
      <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Proxmox Node Agents</h3>
      <button onclick="loadMyDeviceAgents()" class="text-xs text-[#01A982] hover:underline">Refresh</button>
    </div>
    <p class="text-xs text-slate-400 mb-3">Proxmox host agents relayed through one of your tenant's spokes (see Proxmox Host Agent below) — connected, pending, or offline. A pending agent relayed through a spoke already bound to your tenant can be approved right here, no admin needed. An agent relayed through a spoke NOT bound to your tenant (e.g. a shared spoke) still needs an admin — or install it with an onboarding key's <code>--onboarding-psk</code>/<code>--tenant-hint</code> to skip approval entirely. Once approved, use <strong>Enable/Disable CS</strong> to toggle Client-Simulation mode — an agent that connects through a <strong>simulation (cs)</strong> spoke gets this turned on automatically; one on a hypervisor (pxmx) spoke starts off and can be enabled here.</p>
    <div id="my-pxmx-agents-list" class="space-y-2"><p class="text-xs text-slate-400 italic animate-pulse">Loading…</p></div>
  </div>

  <div class="${card}">
    <div class="flex items-center justify-between mb-4">
      <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider">Onboarding Keys</h3>
      <button onclick="_myDevGenPsk()" class="${btn}">+ Generate Key</button>
    </div>
    <p class="text-xs text-slate-400 mb-3">A one-time onboarding key lets a new spoke register and bind to your tenant automatically, without an admin. Generate a key, copy the install command shown beneath it (hub address and key are pre-filled — it runs as-is), run it on the new server, then revoke the key once it has connected. The new spoke loads its roles from this page; a copy-paste uninstall command is shown beneath each key too.</p>
    <div id="my-psk-list" class="space-y-2"><p class="text-xs text-slate-400 italic animate-pulse">Loading…</p></div>
  </div>

  <div class="${card}">
    <h3 class="text-sm font-bold text-slate-500 uppercase tracking-wider mb-2">Proxmox Host Agent</h3>
    <p class="text-xs text-slate-400 mb-3">Runs on a <b>Proxmox host</b> to report hypervisor telemetry (VM inventory, metrics, host actions) <b>and</b> execute client-sim provisioning on that node. It reports to a spoke's <code>/ws/agent</code> listener, not the hub, so it uses its own installer and does <b>not</b> need an onboarding key. The target listener is hosted by <b>either</b> a <b>pxmx (hypervisor) spoke</b>, <b>or</b> an agent running the <b>simulation role</b> — onboard that box with the key above and add <code>--roles simulation</code>, which makes it host the client-sim listener. <b>Prerequisite:</b> that target must already be running — if the installer reports <em>“no agent listener answered”</em>, no listener is up yet (deploy a pxmx spoke via <code>install_pxmx.sh</code>, or load the <code>simulation</code> role on the target). Run this on the Proxmox node — pick one of your tenant's connected hypervisor spokes below to pin <code>--spoke-ip</code>, or leave it on auto-discover to find a co-located spoke via DNS/mDNS.</p>
    <p class="text-[11px] font-bold text-slate-500 mb-1">Target spoke:</p>
    <select id="my-pxmx-spoke" onchange="_myDevPxmxUpdateInstall()" class="w-full bg-white border border-slate-300 rounded-md px-3 py-1.5 text-xs outline-none focus:ring-2 focus:ring-green-500 mb-2"><option value="">— auto-discover (omit --spoke-ip) —</option></select>
    <p class="text-[11px] font-bold text-slate-500 mb-1">Install command:</p>
    <pre id="my-pxmx-install" class="bg-slate-50 border border-slate-200 rounded-md p-3 text-[11px] font-mono overflow-x-auto whitespace-pre-wrap">curl -sSL https://raw.githubusercontent.com/lbockenstedt/pxmx/main/agent/install_agent.sh \\
  | sudo bash</pre>
    <button onclick="_myDevCopyEl('my-pxmx-install')" class="mt-1 text-xs text-[#01A982] hover:underline">Copy command</button>
    <p class="text-[11px] font-bold text-slate-500 mt-2 mb-1">Uninstall (removes all LM components from that host):</p>
    <pre id="my-pxmx-uninstall" class="bg-slate-50 border border-slate-200 rounded-md p-3 text-[11px] font-mono overflow-x-auto whitespace-pre-wrap">curl -sSL https://raw.githubusercontent.com/lbockenstedt/lm/main/uninstall.sh \\
  | sudo bash -s -- --yes</pre>
    <button onclick="_myDevCopyEl('my-pxmx-uninstall')" class="mt-1 text-xs text-[#01A982] hover:underline">Copy uninstall</button>
    <p class="text-[11px] text-slate-400 mt-2"><code>uninstall.sh</code> has no remote/spoke targeting — always run it locally on the box being removed. Other flags, not included above (add manually if needed): <code>--dry-run</code>/<code>-n</code> preview only, no changes; <code>--ollama</code> also remove the shared Ollama install; <code>--letsencrypt</code> also remove Let's Encrypt/certbot state; <code>--netbox-db</code> also <b>drop the NetBox Postgres database</b> (destructive); <code>--nginx-site</code> also remove the NetBox nginx site config; <code>--keep-ab</code> skip removing AppBuilder (removed by default).</p>
  </div>
</div>`;

        case 'console':
            return `<div class="space-y-4">
  <div id="console-container" class="${card}">
    <div class="py-12 text-center text-slate-400 italic">Loading serial consoles…</div>
  </div>
</div>`;

        case 'ldap':
            // Tenant-scoped Directory: TENANT == OU (1:1). A tenant-admin manages
            // ONLY their own tenant (the picker shows just theirs); a Global Admin
            // picks any tenant. The tenant_slug is injected + guarded server-side
            // (a tenant-admin cannot cross tenants). A plain ldap-right user can
            // view but not mutate.
            return `<div class="space-y-6">
  <div class="flex items-center justify-between gap-3 mb-2 flex-wrap">
    <div class="flex items-center gap-2">
      <label class="text-xs text-slate-500 uppercase font-bold">Tenant</label>
      <select id="ldap-tenant-select" onchange="onLDAPTenantChange()" title="Select tenant scope for directory objects" class="bg-white border border-slate-300 rounded-md px-3 py-1.5 text-sm outline-none focus:ring-2 focus:ring-green-500"><option>Loading…</option></select>
      <span id="ldap-ou-hint" class="text-xs text-slate-400 font-mono"></span>
    </div>
    ${(isAdmin() || isTenantAdmin()) ? `<button onclick="showLDAPModal(currentSubView)" title="Add new directory entity (user or group)" class="${btn}">+ Add</button>` : ''}
  </div>
  <div id="ldap-status-row" class="flex items-center gap-6 flex-wrap text-xs">
    <div class="flex items-center gap-2">
      <span id="ldap-health-dot" class="w-2.5 h-2.5 rounded-full bg-slate-300"></span>
      <span class="text-slate-500 font-semibold uppercase tracking-wide">LDAP Server</span>
      <span id="ldap-health-label" class="text-slate-400">checking…</span>
    </div>
    <div class="flex items-center gap-2">
      <span id="entra-health-dot" class="w-2.5 h-2.5 rounded-full bg-slate-300"></span>
      <span class="text-slate-500 font-semibold uppercase tracking-wide">Entra ID</span>
      <span id="entra-health-label" class="text-slate-400">checking…</span>
    </div>
  </div>
  <div class="${card} p-0 overflow-hidden">
    <table class="w-full text-left text-sm">
      <thead class="bg-slate-100 text-slate-600 uppercase text-xs"><tr id="ldap-table-head"></tr></thead>
      <tbody id="ldap-table-body" class="divide-y divide-slate-200"><tr><td class="px-4 py-8 text-center text-slate-400 italic">Loading…</td></tr></tbody>
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

        case 'bugs':
        case 'features':
            return `<div class="space-y-6">
  <div id="logs-content"></div>
</div>`;

        case 'templates':
            return `<div id="template-repo-content" class="space-y-6"></div>`;

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
            // No per-page ↻ Refresh button — the global footer Refresh (calls
            // refreshCurrentView → loadCSData(force=true)) covers it; the
            // auto-refresh throttle select stays in the top-right toolbar.
            return `<div class="space-y-3">
  <div class="flex justify-end items-center gap-3">
    ${typeof csAutoRefreshControl === 'function' ? csAutoRefreshControl() : ''}
  </div>
  <div id="cs-add-toolbar" class="flex gap-2 hidden"></div>
  <div id="cs-content" class="${card}">
    <div class="py-12 text-center text-slate-400 italic">Loading…</div>
  </div>
</div>`;

        case 'netbox':
            return `<div class="space-y-6">
  <div id="netbox-content" class="${card}"><p class="text-sm text-slate-400 italic">Loading…</p></div>
</div>`;

        case 'dns':
            // ALL per-tab action buttons ("+ Add Server", "+ Add Record",
            // "+ Add Forwarder") render into the trailing #top-nav-actions
            // strip in the sub-nav bar (pinned right next to the help "i"
            // icon) instead of a page-body button row — see loadDNSData().
            // No page-body actions row needed any more.
            return `<div class="space-y-6">
  <div id="dns-content" class="${card}"><p class="text-sm text-slate-400 italic">Loading…</p></div>
</div>`;

        case 'dhcp':
            // ALL per-tab action buttons ("+ Add Server", "+ Add
            // Reservation") render into the trailing #top-nav-actions strip
            // in the sub-nav bar (pinned right next to the help "i" icon)
            // instead of a page-body button row — see loadDHCPData(). No
            // page-body actions row needed any more.
            return `<div class="space-y-6">
  <div id="dhcp-content" class="${card}"><p class="text-sm text-slate-400 italic">Loading…</p></div>
</div>`;

        case 'le':
            return `<div class="space-y-6">
  <div id="le-status-bar" class="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-500"></div>
  <div class="space-y-2">
    <div class="flex items-center gap-2 flex-nowrap">
      <button onclick="showLeIssueModal()" title="Issue a new Let's Encrypt / ACME TLS certificate for a domain" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-3 py-1 rounded-md text-xs font-medium transition-all whitespace-nowrap">＋ Issue certificate</button>
      ${isAdmin() ? `<button onclick="leRenewAll()" title="Renew all eligible managed certificates nearing expiry" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-3 py-1 rounded-md text-xs font-medium transition-all whitespace-nowrap">↻ Renew all</button>
      <button onclick="leDistributeNow()" title="Immediately push all managed certificates to their configured distribution targets" class="bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982] px-3 py-1 rounded-md text-xs font-medium transition-all whitespace-nowrap">⚡ Distribute now</button>` : ''}
      <button onclick="showMtlsDebug()" class="bg-slate-600/10 hover:bg-slate-600/20 text-slate-700 border border-slate-400 px-3 py-1 rounded-md text-xs font-medium transition-all whitespace-nowrap" title="Debug: which connected spokes/agents are ACTUALLY presenting a verified mTLS client cert vs. connected cert-less, plus the hub's trust bundle + pinned AppBuilder cert check">🔒 mTLS status</button>
      <button onclick="showDnsCredentialsModal()" class="ml-auto bg-slate-100 hover:bg-slate-200 text-slate-700 px-3 py-1 rounded-md text-xs font-medium transition-all border border-slate-200 whitespace-nowrap" title="Manage this tenant's DNS credentials (Hurricane Electric, Cloudflare, rfc2136, Route53), used for DNS-based certificate issuance">🔑 DNS Credentials</button>
    </div>
    <div class="flex items-center gap-4 flex-wrap">
      <label class="flex items-center gap-1 text-xs text-amber-700 cursor-pointer select-none" title="When ON, a wildcard cert (*.domain) is pushed to EVERY connected cert-capable spoke + the hub on each distribution, not just its explicit targets. OFF by default while cert distribution is being tested — flip on once explicit-target distribution is confirmed working.">
        <input type="checkbox" id="le-wildcard-all-spokes" title="Fan wildcard certificates to all connected spokes" class="w-4 h-4 rounded" onchange="saveLeWildcardAllSpokes(this.checked)">
        Fan wildcard → all spokes
      </label>
      <button onclick="showLeWildcardCoverage()" class="text-xs text-slate-500 hover:text-slate-700 underline decoration-dotted" title="See which spokes would (eligible) and would not (ineligible + why) receive a wildcard cert via fan-out">Coverage</button>
      <label class="flex items-center gap-1 text-xs text-slate-600 select-none" title="How soon the hub retries a FAILED cert distribution to a target. The hub sweeps on this cadence and re-pushes any target whose last push errored (successful targets are skipped). Default 1 hour. Lower = faster retry but more hub→spoke chatter.">
        Retry failed every
        <input type="number" id="le-distribution-retry-hours" min="1" step="1" value="1" title="Hours between retry attempts for failed distributions" class="w-14 px-1 py-0.5 rounded border border-slate-300 text-xs" onchange="saveLeRetryInterval(this.value)">
        hrs
      </label>
    </div>
  </div>
  <div id="le-acme-info" class="text-xs"></div>
  <div id="le-content" class="${card}"><p class="text-sm text-slate-400 italic">Loading…</p></div>
</div>`;

        case 'reports':
            return `<div class="space-y-4">
  <div>
    <h2 class="text-xl font-bold text-slate-800">Reports &amp; Alerts</h2>
    <p class="text-sm text-slate-500">Scheduled email reports (per-tenant dashboard digests) and realtime alert rules (breach + recovery), delivered via Setup → Notifications.</p>
  </div>
  <div id="reports-content"><p class="text-sm text-slate-400 italic p-4">Loading…</p></div>
</div>`;

        case 'osupdates':
            return `<div id="osupdates-content"></div>`;

        case 'security':
            return `<div class="space-y-4">
  <div>
    <h2 class="text-xl font-bold text-slate-800">Security — Threat Monitor</h2>
    <p class="text-sm text-slate-500">Detects brute-force / faked-credential attacks on the API, logs invalid attempts, and (opt-in) auto-blocks the source IP via a NSG deny rule. Optionally subscribes to the shared threat database, so addresses other participants have already seen are known here before they arrive.</p>
  </div>
  <div id="security-content"><p class="text-sm text-slate-400 italic p-4">Loading…</p></div>
</div>`;

        case 'certmon':
            return `<div class="space-y-4">
  <div>
    <h2 class="text-xl font-bold text-slate-800">Cert Expiry Monitor</h2>
    <p class="text-sm text-slate-500">TLS certificates of the public Aruba Central / HPE GreenLake and Juniper Mist cloud endpoints (plus your custom hosts), checked once a day. <span class="text-red-600 font-semibold">Red</span> = under 30 days, <span class="text-amber-600 font-semibold">yellow</span> = under 90 days, <span class="text-green-700 font-semibold">green</span> = 90+ days.</p>
  </div>
  <div id="certmon-content"><p class="text-sm text-slate-400 italic p-4">Loading…</p></div>
</div>`;

        case 'credvault':
            return `<div class="space-y-4">
  <div>
    <h2 class="text-xl font-bold text-slate-800">Credential Vault</h2>
    <p class="text-sm text-slate-500">Per-tenant secret locker backed by Key Vault. Each bucket is unlocked with its own pass-phrase — your role decides which buckets you can reach, the pass-phrase decrypts the values. Revealed secrets are shown once and never cached.</p>
  </div>
  <div id="credvault-content"><p class="text-sm text-slate-400 italic p-4">Loading…</p></div>
</div>`;

        default:
            return `<div class="hpe-card rounded-lg p-5 shadow-sm"><p class="text-sm text-slate-500 italic">Loading…</p></div>`;
    }
}
