---
summary: "LDAP directory spoke. Repo: ldap. moduletype = 'directory'. See architecture-topology.md."
keywords: [backends, behaviors, commands, install_cert, install_ldap, ldap, ldap_server_url, lm, tenant_slug, update_config]
---

# ldap — Directory

LDAP directory spoke. Repo: `ldap`. `module_type = "directory"`. See [architecture-topology.md](architecture-topology.md).

## Role & module_type

Directory spoke for an OpenLDAP/389-DS-style server (install targets `slapd`; `ldap_manager.py` uses `python-ldap`). OU/user/group CRUD, group membership, password set, rename (modrdn), and a unified user/computer search. Not a discovery source for IPAM.

## What it does

ldap manages a real LDAP directory server for the lab — organizational units, user accounts, groups, group membership, and passwords — from the WebUI's **Directory** view instead of `ldapsearch`/`ldapmodify` on the command line.

It also feeds the hub's global search bar: any user or computer entry in the directory shows up when you search from anywhere in the WebUI, tagged as an LDAP result.

It is not an IPAM/NetBox discovery source — it doesn't push devices, IPs, or hosts into NetBox; its only outward integration points are the global search feed and (optionally) being a TLS certificate install target for the Certificate Management module.

## Entrypoints

`python3 -m src.main` (`LdapControlPlane`); spoke `LdapSpoke(BaseSpoke)`. systemd `lm-ldap.service` (`After=network.target slapd.service`). Installer `install_ldap.sh` (pre-seeds slapd debconf `slapd/domain string lm.local`, backend MDB, installs `slapd ldap-utils python3-pip python3-venv git curl jq libldap2-dev libsasl2-dev`, `.env`, unit). `base_structure.ldif` is a **reference template** (People/Groups OUs + an example admin user) — it is **not** auto-applied by the installer; load it manually with `ldapadd -Y EXTERNAL -H ldapi:/// -f base_structure.ldif` (adjust the `dc=…` suffix to your real base DN first).

> **Primarily a role now.** LDAP runs mainly as the **`ldap`** role hosted by the agent (`agent-<hostname>`, unit `lm-agent`): the agent opens a sub-spoke `{agent}-ldap` (module_type `directory`, parent-auto-approved) and self-installs it via `agent/src/agent_spoke.py::_install_role` (clones `lbockenstedt/ldap.git` + deps). The dedicated `lm-ldap.service` / `install_ldap.sh` `ldap-spoke-1` path is the **legacy/standalone** alternative. Connection config (`LDAP_SERVER_URL`/admin DN/PW/base DN) comes from the hub push (WebUI), not a per-module `.env`. A Global Admin sets up the directory in **Setup → Directory (LDAP)** with one form: **domain name** (e.g. `orange-tme.com`) and **admin account** (default `Administrator`; leave the password blank to have the hub generate one). `POST /setup/ldap-directory` (`core/src/routes/ldap.py` → `core/src/ldap_cluster.py::apply_setup`) derives `base_dn` (`dc=orange-tme,dc=com`) and `admin_dn` (`cn=Administrator,<base_dn>`), auto-discovers every agent holding the `ldap-server` deploy role, assigns stable server-ids, stores the password in the Credential Vault (`__admin__/ldap-directory-admin`, hub mode — automation-readable), then force-re-deploys `ldap-server` on every node with all the other nodes as mirror peers (this **resets the admin password** on every node). It refuses to run if any server is offline, and nothing is changed if the vault write fails. Finally it saves `global_config["ldap"]` with a multi-URI `server_url` (`ldap://a:389 ldap://b:389`, python-ldap fails over between them) and re-pushes `UPDATE_CONFIG` to every directory spoke. Loading `ldap-server` on a new agent after setup needs no fields: `ldap_cluster.join_config` gives it the stored domain/password and the next server-id, and re-pushes the existing nodes so they peer with it. Before setup has ever been applied the legacy per-role config + two-node auto-pairing is used. The old `GET`/`POST /setup/ldap-config` routes remain for API compatibility. Config lives under `global_config["ldap"]` (the admin password only inside Fernet-encrypted state, never echoed on GET — masked to `admin_pw_set`) and takes **precedence** over the legacy `ldap_instances` entry — `LabManagerHub._ldap_config_for_spoke` merges per field. This is the SERVER config, not per-tenant (TENANT == OU is unchanged).

## Ports / backends

Talks to the LDAP server via `python-ldap` (`ldap.initialize` + `simple_bind_s`), `src/ldap_manager.py`. Default `LDAP_SERVER_URL=ldap://localhost:389`. No port served.

## Environment variables

`SPOKE_ID`, `SPOKE_SECRET`, `HUB_SECRET`, `HUB_WS`, `HUB_API`, `LDAP_ADMIN_DN` (`cn=admin,dc=example,dc=org`), `LDAP_ADMIN_PW` (required; warned if empty), `LDAP_BASE_DN` (`dc=example,dc=org`), `LDAP_SERVER_URL` (`ldap://localhost:389`). Note: `.env.template` lacks `LDAP_SERVER_URL`; the installer writes it.

## Install flags

`install_ldap.sh`: `--hub`, `--id`/`--name`, `--secret`, `--hub-secret`, `--all-prereqs` (no-op). Only passes `--secret`/`--hub-secret` when non-empty (avoid argparse abort).

## Key commands / handlers (`ldap_spoke.handle_command`)

`GET_VERSION`, `UPDATE_CONFIG` (re-init `LdapManager`), `INSTALL_CERT` (hub-brokered Let's Encrypt cert install — writes leaf/key/CA under `/etc/ldap/tls`, points slapd `cn=config` `olcTLSCertificateFile`/`olcTLSCertificateKeyFile`/`olcTLSCACertificateFile` at them via `ldapmodify -Y EXTERNAL -H ldapi:///`, restarts `slapd`; root only), `LIST_OUS`, `CREATE_OU`, `UPDATE_OU` (modrdn rename), `LIST_USERS`, `CREATE_USER` (`inetOrgPerson`; `secrets.token_urlsafe(16)` random password if none, returned), `UPDATE_USER` (modify cn/sn/givenName/mail + optional uid rename), `LIST_GROUPS` (`groupOfNames` or `posixGroup`), `CREATE_GROUP` (`groupOfNames` requires ≥1 member → seeded with base DN), `UPDATE_GROUP` (cn modrdn), `ADD_USER_TO_GROUP`, `REMOVE_USER_FROM_GROUP`, `SET_PASSWORD` (`passwd_s` with `modify_s` userPassword fallback), `DELETE_ENTITY`, `SEARCH_USERS` (filter on uid/cn/mail/sn/givenName/dNSHostName, escapes `\*()`, tags `source="ldap"`, type `user`/`computer`).

## OUs inside a tenant

Tenant admins organise users into OUs (folders) below the tenant's
`ou=users` container, for example `ou=Lab,ou=Engineering,ou=users,ou=<tenant>,<base>`.
The WebUI shows an OU as a path such as `Engineering/Lab`.

- **Commands:** `LDAP_LIST_OUS`, `LDAP_CREATE_OU`, `LDAP_RENAME_OU`,
  `LDAP_DELETE_OU` and `LDAP_MOVE_USER`. `LDAP_CREATE_USER` takes an optional
  `ou_path`, and `LDAP_LIST_USERS` returns each user's `ou_path` and `upn`.
- **Users are found by uid anywhere in the tenant.** A uid is unique across the
  whole tenant, whatever OU it is in. Update, delete, password, group and
  lookup commands search for it instead of assuming `uid=X,ou=users,…`.
- **Moves stay inside the tenant.** A user moves between OUs of its own tenant;
  every path is built from the tenant slug, so a user can never be moved into
  another tenant.
- **Group memberships follow.** Groups are `groupOfNames` and store member DNs,
  so moving a user or renaming an OU rewrites those member values in the
  tenant's groups. The spoke does this itself, so no `refint` overlay is needed
  (it may manage a remote server it can't reconfigure).
- **Delete is safe.** Only an empty OU (no users, no child OUs) can be deleted,
  and the `ou=users` root can't be renamed or deleted. The WebUI's Delete
  button is disabled for an OU with users or child OUs, and it asks for
  confirmation, naming the tenant and OU path, before it sends the delete.
- **Downstream readers must search the subtree.** Anything that reads users
  (ClearPass, applications) must search `ou=users,ou=<tenant>,…` with subtree
  scope, or it will miss users in OUs.
- **A failed move is undone, or reported.** If rewriting group members fails,
  the spoke undoes the move. If the undo also fails, the reply has
  `error: PARTIAL_ROLLBACK` and a message listing what is still changed.
- **A malformed path is an error.** A path that is not a list of names or an
  `A/B` string is refused; it is never read as the top level.

Hub routes (tenant from the session, as for users and groups; writes need the
tenant-admin tier):

| Route | Body | Spoke command |
| :--- | :--- | :--- |
| `GET /api/ldap/ous` | | `LDAP_LIST_OUS` (hub cache) |
| `POST /api/ldap/ous` | `name`, `parent_path` | `LDAP_CREATE_OU` |
| `PUT /api/ldap/ous` | `path`, `new_name` | `LDAP_RENAME_OU` |
| `DELETE /api/ldap/ous` | `path` | `LDAP_DELETE_OU` |
| `POST /api/ldap/users/move` | `uid`, `target_path` | `LDAP_MOVE_USER` |
| `POST /api/ldap/users` | adds optional `ou_path` | `LDAP_CREATE_USER` |

Paths are a list of OU names (`["Engineering", "Lab"]`) or `"Engineering/Lab"`;
empty means the top level. A spoke too old for these commands gets a 501 that
says to update it. If an older spoke ignores `ou_path` on create, the reply
carries a `warning` that the user was created at the top level.

## Entra accounts and groups per tenant

Entra has no notion of an LM tenant, so each tenant gets its own Entra
security groups, made by the hub through Microsoft Graph and recorded on the
tenant (`directory_entra_groups`):

- **Base group `LM-<tenant>-Users`.** Created the first time the tenant
  creates an Entra account or group. Every Entra account created in the
  Directory joins it, and its direct members are the tenant's Entra accounts:
  the Directory lists them and can delete only them. Users of a group nested
  inside it are not counted. Add an account to it by hand in Entra only if it
  belongs to that tenant.
- **Tenant groups `LM-<tenant>-<name>`.** A tenant admin creates and deletes
  them, and adds or removes the tenant's Entra accounts. `Users` is reserved
  for the base group, which can't be deleted or edited directly.

These are separate from **Permission Groups** (Entra group → LM tenants and
rights), which decide who may manage LM. Those are never used to list a
tenant's accounts.

Creating an account never takes over an existing one (409 if the UPN is in
use). The password is the one the admin types, or a generated one returned
once in the reply; LM never stores or logs it. The sign-in does not force a
password change, so a linked LDAP login works straight away. If joining a
group fails, the new account is deleted again rather than left outside the
tenant.

Needs the SSO app (Settings → Single sign-on) with the Graph **application**
permissions `User.ReadWrite.All` and `Group.ReadWrite.All`, admin-consented.
Without SSO the list is empty with `configured: false` and writes return 503.

| Route | Body | Does |
| :--- | :--- | :--- |
| `GET /api/ldap/entra` | | `{configured, users, groups}` from the hub cache (refreshed every 5 minutes and after each write) |
| `POST /api/ldap/entra/users` | `upn`, `name`, `password` (blank = generate), `group_ids` | Create an account in the base group (and those groups) |
| `DELETE /api/ldap/entra/users` | `id` | Delete one of the tenant's accounts |
| `POST /api/ldap/entra/groups` | `name` | Create `LM-<tenant>-<name>` |
| `DELETE /api/ldap/entra/groups` | `id` | Delete one of the tenant's groups |
| `POST /api/ldap/entra/groups/members` | `group_id`, `user_id` | Add one of the tenant's accounts |
| `DELETE /api/ldap/entra/groups/members` | `group_id`, `user_id` | Remove a member |

All routes take the tenant like the LDAP routes (`tenant_id`; only an admin may
name another tenant) and need the tenant-admin tier to write.

## Active Directory (read-only stub)

`src/ad_directory.py` reads users from an AD domain, so the Directory view can
later show LDAP, Entra and AD accounts together. It is read-only for now:
`AD_DISCOVER`, `AD_TEST` and `AD_SEARCH_USERS`. The `ad` block of the spoke
config holds `domain`, `forest`, `site`, `discover`, `use_global_catalog`,
`use_ssl`, `dns_servers`, `servers`, `bind_user`, `bind_password`, `base_dn` and
`timeout`. The hub push, the WebUI form and the Credential Vault wiring for
`bind_password` are not built yet.

Which server the spoke uses, in order:

1. **DNS SRV discovery** (`discover`, default on). With `use_global_catalog`
   (the default) it looks up the global catalogs, `_gc._tcp.<site>._sites.<forest>`
   and then `_gc._tcp.<forest>`, on ports 3268/3269. Otherwise it looks up the
   domain controllers, `_ldap._tcp.<site>._sites.dc._msdcs.<domain>` and then
   `_ldap._tcp.dc._msdcs.<domain>`, on ports 389/636. Servers in the spoke's
   own AD site come first; within one answer, lower priority wins, then higher
   weight. The lookup uses a small standard-library DNS client (UDP with EDNS,
   retried over TCP when truncated), so no DNS package is needed.
   `dns_servers` points it at AD's DNS servers when the spoke's own resolver
   can't see the AD zones.
2. **Configured servers** (`servers`): the primary first, then the backup(s).
   They are always tried after the discovered ones, so AD still works when
   discovery fails.

Each server gets a short timeout (`timeout`, default 3 s), and the first one
that binds is used. A down server fails over to the next. A rejected password
is not retried on other servers, because it would fail the same way and could
lock the service account. An empty password is refused, since AD treats it as
an anonymous bind that "succeeds". The password is never sent in clear: LDAPS
(`use_ssl`, the default) or, with `use_ssl` off, StartTLS on 389/3268; a server
that can't do TLS is skipped. Either way the spoke must trust the AD
certificate authority.

## Key files

`src/main.py`, `src/ldap_spoke.py`, `src/ldap_manager.py` (~315 lines, whole `LdapManager`), `install_ldap.sh`, `base_structure.ldif`, `README.md`, `.env.template`, `requirements.txt`, `VERSION`.

## Notable behaviors & gotchas

- **Namespace-package loader (no `__init__.py`)** — `src/` has no `__init__.py`; works as a Python 3 namespace package. `main.py` runs as `-m src.main` and imports `from src.ldap_spoke import LdapSpoke`; `ldap_spoke.py` uses the **relative** import `from .ldap_manager import LdapManager`. `BaseSpoke` import uses the dual-path `try: from base_spoke import BaseSpoke except ImportError: from core.src.base_spoke import BaseSpoke`. Installer sets `PYTHONPATH=$INSTALL_DIR:$INSTALL_DIR/core/src:$INSTALL_DIR/ldap/src`.
- **`LdapControlPlane.register_module` is overridden locally** (assigns `self.modules[name]`) — minor duplication; the only one of this group that does this.
- **Password generation** — `create_user` never hardcodes a password (`secrets.token_urlsafe(16)` default; returns it).
- **`search`** is the cross-cutting directory query the hub uses for global search (returns `source="ldap"` records compatible with the hub's unified results).
- **Generic python-ldap** — works against any RFC-4511 server; nothing FreeIPA-specific. Install path targets OpenLDAP `slapd`; FreeIPA/389-DS work with the same `LDAP_ADMIN_DN`/`LDAP_BASE_DN`/`LDAP_SERVER_URL`.

## How it works

- **Hub connection.** Like every LM spoke, ldap dials the hub over a WebSocket. In the current unified model this is the sub-spoke `{agent}-ldap` opened by the agent (parent-auto-approved); the legacy path is the standalone `ldap-spoke-1` dialing the hub directly. Either way the wire protocol is identical.
- **Config delivery.** Connection settings — `LDAP_SERVER_URL`, `LDAP_ADMIN_DN`, `LDAP_ADMIN_PW`, `LDAP_BASE_DN` — are **not** read from a per-module `.env` when running as a role. The hub pushes them via `UPDATE_CONFIG`, normally right after you fill in the Directory setup form in the WebUI. On `UPDATE_CONFIG` the spoke discards its current config and rebuilds `LdapManager` from scratch with the new values, so a fixed typo (e.g. a wrong admin password) takes effect on the next push without restarting the process.
- **Command flow.** Every WebUI action (list/create/update/delete an OU, user, or group; add/remove group membership; reset a password; rename an entry) becomes one `LdapSpoke.handle_command` call, which runs the matching `LdapManager` method. Because `python-ldap` calls are synchronous/blocking, each one runs in a worker thread via `asyncio.to_thread` — this keeps the spoke's heartbeat to the hub alive even if the directory server is slow or unreachable. Without that, a stalled bind would freeze the spoke's event loop, queue every other command behind it, and get the spoke disconnected as unresponsive.
- **Connection hygiene.** `LdapManager._conn()` opens a fresh bind for each operation and always unbinds afterward, even on error. (An older code path bound once per call and never unbound, which could exhaust the directory server's connection limit on a long-running spoke.)
- **Global search integration.** `SEARCH_USERS` is the query the hub's cross-system search fans out to every connected directory spoke (alongside NetBox, DHCP, VM, and session searches). It matches on `uid`, `cn`, `mail`, `sn`, `givenName`, or `dNSHostName`, and returns each hit tagged `source="ldap"` with `type` `user` or `computer` (based on `objectClass`) so the WebUI can merge and label results consistently across modules.
- **Certificate installation.** The hub can push an `INSTALL_CERT` command to the ldap spoke — the same command it sends to firewall and hypervisor targets — when a certificate issued by the Certificate Management (le) module is targeted at this directory server. The spoke writes the leaf certificate and private key (plus any CA chain) under `/etc/ldap/tls`, points slapd's `cn=config` `olcTLSCertificateFile`/`olcTLSCertificateKeyFile`/`olcTLSCACertificateFile` at the new files via `ldapmodify -Y EXTERNAL -H ldapi:///`, and restarts `slapd` so the new TLS context takes effect. This only works when the ldap spoke runs on the OpenLDAP host itself as root (needed to restart the service and read the key file).

## How to use it

1. **Set up the directory.** Load the `ldap-server` role on each LDAP host (no fields needed), then in **Setup → Directory (LDAP)** enter the domain name and admin account and press **Apply**. The hub finds the servers, wires replication between them, resets/stores the admin password in the vault, and points the Directory spoke at all servers; a green/healthy status means the bind succeeded.
2. **Create an OU.** Give it a name (optionally under a parent OU/DN). It's created as an `organizationalUnit` entry.
3. **Create a user.** Provide first name, last name, username, email, and the OU to place them in. Leave the password field blank to have ldap generate a strong random one — it's returned once in the response, so copy it down or hand it to the user immediately; it is not shown again.
4. **Create a group.** Groups are `groupOfNames`, which requires at least one member to exist at all — ldap seeds a new group with the directory's base DN as a placeholder member so creation never fails; add real members afterward and remove the placeholder if you like.
5. **Add / remove a user from a group.** Pick the user and the group; this is a single membership add/remove, not a full group rewrite.
6. **Reset a password.** Set a new password for a user DN directly (no need to know the old one) — this uses LDAP's Password-Modify extended operation, falling back to a direct attribute replace if the server doesn't support it.
7. **Rename an entry.** Renaming an OU, user, or group changes its RDN (`modrdn`) — e.g. changing a username changes the `uid=` component of its DN, which is why the DN in the UI may change after a rename.

## Troubleshooting / common questions

- **"Connect fails / can't bind to the directory."** Double-check the server URL, admin DN, admin password, and base DN in the Directory setup form. An empty admin password is explicitly logged as a warning — the bind will fail with an authentication error until it's set.
- **"The Directory spoke shows offline/red."** The `ldap` role isn't installed on the agent, the agent process (`lm-agent`) is down, or the sub-spoke hasn't been approved yet. Confirm the role is active on the intended host.
- **"Creating a group fails."** `groupOfNames` entries require at least one `member` attribute — if creation still fails after that, check that the target OU exists and the admin account has write access there.
- **"Does this work with FreeIPA or 389-DS, not just OpenLDAP?"** Yes for directory operations — `python-ldap` speaks generic RFC-4511 LDAP, so any compliant server works once you point `LDAP_SERVER_URL`/`LDAP_ADMIN_DN`/`LDAP_BASE_DN` at it. The **installer** (`install_ldap.sh`) is OpenLDAP/`slapd`-specific; a FreeIPA/389-DS server is expected to already exist and just be pointed at.
- **"Why isn't there a config file I can edit for the connection settings?"** In the current agent+role model, config comes from the hub's `UPDATE_CONFIG` push (the WebUI form), not a per-module `.env` — this is deliberate so the hub is the single source of truth and a config change doesn't require touching the host.
- **"A user isn't showing up in the global search bar."** Confirm the Directory spoke is online, and that the search term matches one of the indexed fields (`uid`, `cn`, `mail`, `sn`, `givenName`, `dNSHostName`) — search does not match on arbitrary attributes like OU name or group membership.

## Related pages

[architecture-topology.md](architecture-topology.md), [lm-hub.md](lm-hub.md), [install-flags.md](install-flags.md).