# REST API Reference

The Lab Manager Hub provides a REST API for integration with the WebUI and other external tools.

## 1. General
- **Base URL**: `http://<hub-ip>:8000`
- **Format**: JSON

## 2. Setup & Configuration

### System Status
- **`GET /status`**: Returns the current status of the Hub, including active connections, heartbeat health, and system metrics.
- **`GET /setup/config`**: Retrieves the global configuration.
- **`POST /setup/config`**: Updates the global configuration.

### Module Management
- **`GET /setup/modules`**: Lists all available modules and their installation status.
- **`POST /setup/install-module`**: Triggers the installation of a module.
  - **Payload**: `{ "module_id": "ldap", "spoke_id": "ldap-1", "display_name": "Main LDAP" }`
- **`GET /setup/pending_spokes`**: Lists all spokes that have connected but are not yet approved.
- **`POST /setup/approve_spoke`**: Approves or un-approves a spoke.
  - **Payload**: `{ "spoke_id": "...", "action": "approve" | "unapprove" }`
- **`POST /setup/spoke-name`**: Renames a spoke's display name.
  - **Payload**: `{ "spoke_id": "...", "display_name": "..." }`

### Tenant Management
- **`GET /setup/tenants`**: Lists all tenants.
- **`GET /setup/tenants/{tenant_id}`**: Gets details for a specific tenant.
- **`POST /setup/tenants`**: Creates a new tenant.
- **`POST /setup/tenant`**: Updates a tenant's config or sets it as active.

### Generic Provisioning
- **`POST /api/generic/provision`**: Commands a Generic Agent to clone a repo and install a module.
  - **Payload**: `{ "agent_id": "...", "module_id": "...", "repo_url": "...", "spoke_id": "...", "display_name": "..." }`

## 3. Functional APIs

### OPNsense
- **`GET /api/firewall/{firewall_id}/refresh`**: Triggers a rule cache refresh.
- **`GET /api/firewall/{firewall_id}/{endpoint}`**: Generic gateway to OPNsense spoke commands (e.g., `rules`, `interfaces`, `dhcp`).

### LDAP
- **`GET /api/ldap/ous`**, **`POST /api/ldap/ous`**: Manage OUs.
- **`GET /api/ldap/users`**, **`POST /api/ldap/users`**: Manage Users.
- **`GET /api/ldap/groups`**, **`POST /api/ldap/groups`**: Manage Groups.
- **`POST /api/ldap/users/group`**: Assign user to group.
- **`DELETE /api/ldap/users/group`**: Remove user from group.
- **`DELETE /api/ldap/entity`**: Delete any LDAP entity.

## 4. Diagnostics
- **`GET /setup/diagnostics`**: Returns a detailed health report of all known spokes.
- **`GET /setup/api-probe?spoke_id=...&path=...`**: Executes a raw API request against a spoke's local API.
