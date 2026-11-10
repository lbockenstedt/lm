# 🌐 Lab Manager (LM) — Project Master Registry & Control Plane

Lab Manager (LM) is a unified "single pane of glass" datacenter and laboratory infrastructure orchestrator. Built on an asynchronous hub-and-spoke topology, LM coordinates 16 specialized modules across hypervisors, network switches, firewalls, IPAM, identity directories, client simulators, and automated quality assurance systems.

## Fleet Map & Module Registry

| Repo | Module Type | Description | Canonical Doc |
| :--- | :--- | :--- | :--- |
| **`lm`** | `hub` | Control plane, REST API, multitenant policies, and vanilla JS WebUI | [`docs/lm-hub.md`](docs/lm-hub.md) |
| **`dns`** | `dns` | Unbound DNS coordinator & clustered resolver tier | [`docs/dns.md`](docs/dns.md) |
| **`dhcp`** | `dhcp` | Kea DHCP (v4/v6) HA cluster, reservations, and lease tracking | [`docs/dhcp.md`](docs/dhcp.md) |
| **`nw`** | `nw` | Switch/AP discovery, LLDP/CDP topology, and VLAN provisioning | [`docs/nw.md`](docs/nw.md) |
| **`netbox`** | `ipam` | Source-of-truth IPAM, DCIM, and tenant virtualization sync | [`docs/netbox.md`](docs/netbox.md) |
| **`opnsense`** | `firewall` | OPNsense firewall rule, alias, and gateway operations | [`docs/opnsense.md`](docs/opnsense.md) |
| **`pxmx`** | `hypervisor`| Proxmox VE VM/LXC lifecycle and storage drive health pipeline | [`docs/pxmx.md`](docs/pxmx.md) |
| **`truenas`** | `storage` | TrueNAS ZFS pools, datasets, quotas, and SMB/NFS sharing | [`docs/truenas.md`](docs/truenas.md) |
| **`kvm`** | `compute` | QEMU/libvirt hypervisor domain lifecycle and XML parsing | [`docs/kvm.md`](docs/kvm.md) |
| **`cs`** | `simulation` | Client simulation runner, simulated Kea instances, and automation | [`docs/cs.md`](docs/cs.md) |
| **`cppm`** | `nac` | Aruba ClearPass Policy Manager, OAuth2, and endpoint sync | [`docs/cppm.md`](docs/cppm.md) |
| **`ldap`** | `directory` | OpenLDAP/389-DS directory spoke, Entra ID ROPC, user/group CRUD | [`docs/ldap.md`](docs/ldap.md) |
| **`le`** | `certificates`| Let's Encrypt / ACME cert lifecycle, DNS-01, and distribution | [`docs/le.md`](docs/le.md) |
| **`tsa`** | `app` | Technical Support Assistant (student competition event management) | [`docs/tsa.md`](docs/tsa.md) |
| **`qa`** | `qa` | Fleet integration testing, scenario filters, and audit engine | [`docs/qa.md`](docs/qa.md) |
| **`ab`** | `agent` | AppBuilder autonomous defect remediation and dual-panel PR audit | [`docs/appbuilder.md`](docs/appbuilder.md) |

## Core REST API Route Reference

The Hub exposes a comprehensive, fully-authenticated REST API:

### Network Services
- `GET|POST|PUT|DELETE /api/dns/records` — DNS record CRUD (A, AAAA, CNAME, PTR)
- `GET|POST|PUT|DELETE /api/dns/forwarders` — Upstream DNS forwarder management
- `GET /api/dns/stats` — Unbound performance and latency metrics
- `GET|POST|PUT|DELETE /api/dhcp/reservations` — Static DHCP host reservations
- `GET /api/dhcp/leases` — Real-time DHCP lease inspection
- `GET|POST|PUT|DELETE /api/firewall/{fw_id}/rules` — Firewall rule lifecycle
- `GET|POST|PUT|DELETE /api/firewall/{fw_id}/aliases` — Firewall alias definitions

### Compute, Hypervisors & Storage
- `GET /api/pxmx/nodes` — Proxmox cluster nodes and hardware telemetry
- `GET /api/pxmx/vms` — VM and LXC container status and controls
- `GET /api/pxmx/drives` — Storage drive health, smartctl telemetry, wear level
- `GET /api/truenas/pools` — ZFS storage pool usage and dataset quotas
- `GET /api/kvm/domains` — Libvirt QEMU virtual machine domain status

### Identity, Security & Certificates
- `GET|POST|PUT|DELETE /api/ldap/users` — Directory user lifecycle and passwords
- `GET|POST|PUT|DELETE /api/ldap/groups` — Directory group membership manipulation
- `GET /api/cppm/sessions` — ClearPass Access Tracker live session inspection
- `GET|POST|DELETE /api/le/certificates` — Let's Encrypt / ACME certificate issuance
- `POST /api/le/distribute` — Hub-brokered certificate distribution to spoke targets

### System Administration & Tenants
- `GET|POST|PUT|DELETE /setup/tenants` — Multitenancy isolation boundaries
- `GET /setup/spokes` — Connected spoke status, health, and latency

## WebUI Architecture & Invariants
- **Dependency-Free Vanilla JavaScript:** Clean, native JS without npm build steps.
- **Client-Side Navigation:** Seamless single-page view transitions.
- **Universal Tooltips:** Every interactive element (`<button>`, `<input>`, `<select>`) carries a descriptive `title=` tooltip.
- **Multitenancy Isolation:** Tenant boundaries strictly enforced across Proxmox tags and NetBox tenant IDs.

<!-- INSTALLERS:START -->
## Installation

Every installer in this repo, with every flag and environment variable it accepts.
Installers are idempotent — re-running one updates code and preserves credentials.

### Every module, one table

Each module is its own repo with its own installer. Unless noted, they take the
same core flags: `--hub`, `--id`/`--name`, `--secret`, `--hub-secret`,
`--all-prereqs`, and accept a bare hostname for `--hub`.

| Module | Installer | One-liner |
| :--- | :--- | :--- |
| **lm** (hub) | `install_menu.sh` | `curl -sSL https://raw.githubusercontent.com/lbockenstedt/lm/main/install_menu.sh \| sudo bash` |
| **agent** (any role) | `lm/agent/install_agent.sh` | `curl -sSL https://raw.githubusercontent.com/lbockenstedt/lm/main/agent/install_agent.sh \| sudo bash -s -- --hub HUB` |
| **cs** (simulation) | `cs/install_cs.sh` | `curl -sSL https://raw.githubusercontent.com/lbockenstedt/cs/main/install_cs.sh \| sudo bash -s -- --hub HUB` |
| **pxmx** (hypervisor) | `pxmx/install_pxmx.sh` | `curl -sSL https://raw.githubusercontent.com/lbockenstedt/pxmx/main/install_pxmx.sh \| sudo bash -s -- --hub HUB` |
| **pxmx agent** (Proxmox host) | `pxmx/agent/install_agent.sh` | `curl -sSL https://raw.githubusercontent.com/lbockenstedt/pxmx/main/agent/install_agent.sh \| sudo bash` |
| **netbox** (IPAM) | `netbox/install.sh` | `curl -sSL https://raw.githubusercontent.com/lbockenstedt/netbox/main/install.sh \| sudo bash -s -- --hub HUB` |
| **opnsense** (firewall) | `opnsense/install_opnsense.sh` | `curl -sSL https://raw.githubusercontent.com/lbockenstedt/opnsense/main/install_opnsense.sh \| sudo bash -s -- --hub HUB` |
| **cppm** (NAC) | `cppm/install.sh` | `curl -sSL https://raw.githubusercontent.com/lbockenstedt/cppm/main/install.sh \| sudo bash -s -- --hub HUB` |
| **ldap** (directory) | `ldap/install_ldap.sh` | `curl -sSL https://raw.githubusercontent.com/lbockenstedt/ldap/main/install_ldap.sh \| sudo bash -s -- --hub HUB` |
| **nw** (network devices) | `nw/install_nw.sh` | `curl -sSL https://raw.githubusercontent.com/lbockenstedt/nw/main/install_nw.sh \| sudo bash -s -- --hub HUB` |
| **le** (certificates) | `le/install_le.sh` | `curl -sSL https://raw.githubusercontent.com/lbockenstedt/le/main/install_le.sh \| sudo bash -s -- --hub HUB` |
| **truenas** (storage) | `truenas/install_truenas.sh` | `curl -sSL https://raw.githubusercontent.com/lbockenstedt/truenas/main/install_truenas.sh \| sudo bash -s -- --hub HUB` |
| **kvm** (compute) | `kvm/install_kvm.sh` | `curl -sSL https://raw.githubusercontent.com/lbockenstedt/kvm/main/install_kvm.sh \| sudo bash -s -- --hub HUB` |
| **qa** (quality assurance)| `qa/install_qa.sh` | `curl -sSL https://raw.githubusercontent.com/lbockenstedt/qa/main/install_qa.sh \| sudo bash -s -- --hub HUB` |
<!-- INSTALLERS:END -->
