# LM Documentation

Feature reference for the Lab Manager system — so you can look up what each thing does, what port it uses, what env vars/flags it takes, and its gotchas without scanning code.

The canonical doc set lives here in `lm/docs/`. Each separate repo also carries a `docs/` with its own feature page + the shared topology page (pointing back here for the full set).

## Installation — start here

**One master installer drives everything.** `install_menu.sh` is the single
interactive entry point — it calls every other installer for you, so you rarely
need to run them directly. Installers are **idempotent** (re-running updates code
and preserves credentials). Every flag and env var is in
[install-flags.md](install-flags.md) and [environment-variables.md](environment-variables.md).

```bash
curl -sSL https://raw.githubusercontent.com/lbockenstedt/lm/main/install_menu.sh | sudo bash
```

The menu offers:

| # | Choice | Drives | Notes |
| :-- | :--- | :--- | :--- |
| 1 | **Hub** | `install_all.sh` | this box becomes the hub + WebUI; checklist of co-located module roles |
| 2 | **Agent** | `agent/install_agent.sh` | leaf node; pick the module role(s) to run now (or none → load later in the WebUI) |
| 3 | **Proxmox Host Agent** | `pxmx/agent/install_agent.sh` | node-agent on a Proxmox host that reports to a pxmx/sim spoke (install **or** uninstall) |
| 4 | **Uninstall** | `uninstall.sh` | guarded master teardown |

Everything below is what the menu runs underneath — use these directly only for
non-interactive/automated installs.

### 1. Hub (non-interactive)

```bash
sudo bash /opt/lm/install_all.sh --hub-only
```

### 2. Agent (every remote node)

One agent **hosts many module roles at once** — each loaded role opens its own
auto-approving sub-spoke. Menu option 2 lets you pick the roles; or pre-load them
here. `dns`, `dhcp`, and `henet` need **no installer** — just load the role:

```bash
curl -sSL https://raw.githubusercontent.com/lbockenstedt/lm/main/agent/install_agent.sh \
  | sudo bash -s -- --hub HUB --roles dns,dhcp,henet
```

Roles: `dns dhcp network netbox opnsense ldap simulation cppm proxmox le console statuspage proxy truenas`.

> **Client sims on the agent:** load the `simulation` role (menu option 2 → check
> *Client Simulator*, or `--roles simulation`) and this box hosts the client-sim
> `/ws/agent` listener (`LM_CS_AGENT_LISTENER=1`, set automatically for a
> non-colocated simulation role). A Proxmox Host Agent (menu option 3,
> `--spoke-ip <this-box>`) then reports to it — no separate cs/pxmx spoke needed.

### 3. Per-module standalone installers

Each module is its own repo with its own installer. Unless noted they take the
same core flags (`--hub`, `--id`/`--name`, `--secret`, `--hub-secret`,
`--all-prereqs`) and accept a bare hostname for `--hub`.

| Module | Installer | One-liner |
| :--- | :--- | :--- |
| **lm** (hub) | `install_menu.sh` | `curl -sSL https://raw.githubusercontent.com/lbockenstedt/lm/main/install_menu.sh \| sudo bash` |
| **agent** (any role) | `lm/agent/install_agent.sh` | `curl -sSL .../lm/main/agent/install_agent.sh \| sudo bash -s -- --hub HUB --roles <csv>` |
| **cs** (simulation) | `cs/install_cs.sh` | `curl -sSL .../cs/main/install_cs.sh \| sudo bash -s -- --hub HUB` |
| **pxmx** (hypervisor) | `pxmx/install_pxmx.sh` | `curl -sSL .../pxmx/main/install_pxmx.sh \| sudo bash -s -- --hub HUB` |
| **pxmx host agent** (node-agent) | `pxmx/agent/install_agent.sh` | *(master menu option 3)* `curl -sSL .../pxmx/main/agent/install_agent.sh \| sudo bash -s -- --spoke-ip SPOKE` |
| **netbox** (IPAM) | `netbox/install.sh` | `curl -sSL .../netbox/main/install.sh \| sudo bash -s -- --hub HUB` |
| **opnsense** (firewall) | `opnsense/install_opnsense.sh` | `curl -sSL .../opnsense/main/install_opnsense.sh \| sudo bash -s -- --hub HUB` |
| **cppm** (NAC) | `cppm/install.sh` | `curl -sSL .../cppm/main/install.sh \| sudo bash -s -- --hub HUB` |
| **ldap** (directory) | `ldap/install_ldap.sh` | `curl -sSL .../ldap/main/install_ldap.sh \| sudo bash -s -- --hub HUB` |
| **nw** (network devices) | `nw/install_nw.sh` | `curl -sSL .../nw/main/install_nw.sh \| sudo bash -s -- --hub HUB` |
| **le** (certificates) | `le/install_le.sh` | `curl -sSL .../le/main/install_le.sh \| sudo bash -s -- --hub HUB` |
| **truenas** (storage) | `truenas/install_truenas.sh` | `curl -sSL .../truenas/main/install_truenas.sh \| sudo bash -s -- --hub HUB` |
| **bugfixer** | `bugfixer/install.sh` | `curl -sSL .../bugfixer/main/install.sh \| bash -s -- wss://HUB` |
| **dns**, **dhcp**, **henet** | *(no installer — agent roles)* | Load the `dns` / `dhcp` / `henet` role (§2), or run `/opt/lm/<mod>/install_<mod>.sh` |

Full one-liners (with the complete raw.githubusercontent.com paths) and every
flag live in the repo-root `README.md` **Installation** block and in
[install-flags.md](install-flags.md).

## Overview

- [architecture-topology.md](architecture-topology.md) — the backbone: hub/spoke/agent mesh, WebSocket + TLS scheme (unified `:443`, `/ws/spoke` + `/ws/agent` byte-proxy), mDNS/DNS discovery, message signing & keys, onboarding & clone detection, log relay, self-update & rollback, state & tenancy, module-type → spoke → repo map. **Start here.**

## Hub & UI

- [lm-hub.md](lm-hub.md) — the hub: `LabManagerHub`, FastAPI route groups, background loops, security, state, update pipeline, logging, dep guard.
- [webui.md](webui.md) — the browser UI: panels/tabs, view router, HTTP+WS comms.
- [credential-vault.md](credential-vault.md) — hub-side encrypted secret store (buckets, `psk` vs automation-readable `hub` modes, Azure Key Vault / local Fernet); the `{bucket,name}` reference + server-side resolve pattern LE / HE.NET / Console use.
- [generic-agent.md](generic-agent.md) — the agent-spoke `_ROLE_MAP` role loader (15 hosted roles + bugfixer/netbox-server deploy roles). The legacy `GenericLeafAgent` leaf was removed.

## Spokes

- [pxmx.md](pxmx.md) — Proxmox (`hypervisor`): bridge spoke + per-host agent; USB auto-provisioning brain; VNC relay; `/ws/agent` byte-proxy.
- [cs.md](cs.md) — Client Simulation (`simulation`): sim engine, client API :8080, per-client override panel, relay-only Proxmox.
  - [mist.md](mist.md) — Juniper Mist API twin of Aruba Central (full twin + sim-quota): own `MistClient`/poller/telemetry/`Mist:` source/tab; the 7d alarms-window fix; insights not yet shipped.
  - [central-on-prem.md](central-on-prem.md) — a second on-prem Aruba Central instance (full twin + sim-quota): reuses `ArubaClient`, separate config/poller/telemetry/`Central On-Prem:` source/tab; no-stepping guarantee vs cloud Central.
- [netbox.md](netbox.md) — IPAM/DCIM (`ipam`): sync_vms/devices/nw_device/access_tracker, staleness sweep, custom fields, Kea sync.
- [opnsense.md](opnsense.md) — Firewall (`firewall`): aliases/NAT/rules/DNS/DHCP-leases/ARP; categories-as-UUIDs; cache.
- [nw.md](nw.md) — Network Devices (`nw`): SSH/CLI + REST + SNMP fleet driver; ARP-as-discovery-feed.
- [cppm.md](cppm.md) — ClearPass NAC (`nac`): OAuth token strategy, endpoint sync tagging, non-BaseSpoke.
- [ldap.md](ldap.md) — Directory (`directory`): OU/user/group CRUD + search; namespace-package loader.
- [dhcp.md](dhcp.md) — DHCP (`dhcp`): thin Kea DHCP4 spoke; subnets/leases/reservations.
- [dns.md](dns.md) — DNS (`dns`): Unbound via `unbound-control`.
- [henet.md](henet.md) — HE.NET public DNS (`henet`): Hurricane Electric A/AAAA via dyndns; Credential-Vault DDNS key.
- [le.md](le.md) — Certificate Management (`certificates`): certbot ACME producer + ledger.
- [console.md](console.md) — Console (`console`): serial console access (USB + UART), baud auto-detect, xterm relay, auto-identify/fingerprint → NetBox, per-port + per-agent tenant binding.

## Agents

- [bugfixer.md](bugfixer.md) — autonomous GitHub-issue fixer bot; optional hub **agent** (not a spoke); signed `GET_LOGS`/`TRIGGER_ALL_UPDATES`.
- (pxmx per-host agents are documented under [pxmx.md](pxmx.md); the agent-spoke under [generic-agent.md](generic-agent.md).)

## Reference

- [backpressure-throttling.md](backpressure-throttling.md) — the hub's graceful-degradation control loop: message classification (must/coalesce/skippable), the escalation ladder (offender-first → fleet slow-down → hub-coalesce → protect shed), per-spoke TokenBucket (80% soft signal / 100% hard drop / DDoS quarantine), protect-mode pre-parse + source shed, spoke-side cooperation (`LM_BACKPRESSURE`), the `<sig>.<body>` sig-verify-over-raw-bytes ceiling raise, and the full config knob table.
- [environment-variables.md](environment-variables.md) — every `LM_*`/`HUB_*`/`CS_*`/`KEA_*`/`NETBOX_*`/`CPPM_*`/`LDAP_*`/`UNBOUND_*` var, what it does, default, where read.
- [install-flags.md](install-flags.md) — every installer + its flags.
- [logging-observability-contract.md](logging-observability-contract.md) — **MANDATORY** for every module/agent: relay all logs (INFO+ and uncaught exceptions) to the hub, installed once, buffered-while-disconnected + flushed on connect, so Setup → Logs + the BugFixer see everything without CLI access.

## Quick lookup

- **Hub port:** unified `0.0.0.0:443` wss (or `:443` plain, no cert); co-located callers dial `wss://127.0.0.1:443`. No separate loopback port.
- **pxmx agent link (standalone DEFAULT — agent → spoke → hub):** the pxmx spoke (own box) serves `wss://:443` and the agent dials `wss://<spoke>:443/ws/agent` **directly** (pinned via `--spoke-ip` — just the spoke's IP, the agent auto-determines the scheme/port/`/ws/agent` path by probing; no mDNS auto-discovery for a standalone spoke). **Loopback (opt-in — agent → hub → spoke):** only when co-located all-in-one (`install_all.sh --loopback` path) — the agent dials `wss://<hub>:443/ws/agent` and the hub byte-proxies to the pxmx spoke's loopback `:8443` (`LM_PXMX_AGENT_LOOPBACK=1`). See [pxmx.md](pxmx.md).
- **cs client API:** 8080.
- **TLS verify:** off by default; opt in with `--tls-verify` (+ `--tls-ca-cert`).
- **Discovery:** mDNS `_lm-hub._tcp.local.` TXT (`agent_port`=443, `tls_port`) + DNS `lm-hub.<search>`; same-box = IP-equality.
- **Auto-provisioning brain:** the pxmx agent, not the hub or cs spoke.
- **Sim-quota sources / product tabs:** three independent monitoring products under the Simulations left-nav — **Central** (cloud Aruba Central), **Central On-Prem** (a second on-prem Aruba Central instance), **Mist** (Juniper Mist) — each its own sim-quota source (`Central:` / `Central On-Prem:` / `Mist:`), own config/poller/telemetry, own Sites/Alerts/Insights/Clients/Hardware/Diagnostic tab + Setup API subtab. See [cs.md](cs.md), [mist.md](mist.md), [central-on-prem.md](central-on-prem.md).
- **Spoke ERROR → hub HTTP 502** with the real reason.
- **`request_response` for a spoke reply** (e.g. VNC ticket); `send_to_spoke_command` is fire-and-forget.