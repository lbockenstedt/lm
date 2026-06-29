# LDAP Module Guide

The LDAP module allows the Hub to manage directory services. In the standard deployment, the LDAP server is hosted as a spoke in an LXC container.

## 1. Capabilities
- **OU Management**: Create and view Organizational Units.
- **User Management**: Create and manage LDAP users.
- **Group Management**: Create and manage LDAP groups and handle user-to-group assignments.
- **Remote Server Support**: The Hub can be configured to manage a remote LDAP server rather than a local spoke.

## 2. Configuration
Configuration is managed via **Setup $\rightarrow$ LDAP Config**.

### Required Fields
- **LDAP Server URL**: The URL of the server (e.g., `ldap://172.16.1.50:389`).
- **Base DN**: The root of the directory (e.g., `dc=example,dc=org`).
- **Admin DN**: The distinguished name of the administrator.
- **Admin Password**: Password for the admin account.

## 3. Technical Implementation
The LDAP spoke acts as a bridge, executing the actual LDAP operations using the `python-ldap` library or shell-based `ldapadd`/`ldapmodify` commands. Commands are routed from the Hub via the control plane:
- `LIST_OUS`, `CREATE_OU`
- `LIST_USERS`, `CREATE_USER`
- `LIST_GROUPS`, `CREATE_GROUP`
- `ADD_USER_TO_GROUP`, `REMOVE_USER_FROM_GROUP`
