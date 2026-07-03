# LM Documentation

Feature reference for the Lab Manager system — so you can look up what each thing does, what port it uses, what env vars/flags it takes, and its gotchas without scanning code.

The canonical doc set lives here in `lm/docs/`. Each separate repo also carries a `docs/` with its own feature page + the shared topology page (pointing back here for the full set).

## Overview

- [architecture-topology.md](architecture-topology.md) — the backbone: hub/spoke/agent mesh, WebSocket + TLS scheme (unified `:443`, `/ws/spoke` + `/ws/agent` byte-proxy), mDNS/DNS discovery, message signing & keys, onboarding & clone detection, log relay, self-update & rollback, state & tenancy, module-type → spoke → repo map. **Start here.**

## Hub & UI

- [lm-hub.md](lm-hub.md) — the hub: `LabManagerHub`, FastAPI route groups, background loops, security, state, update pipeline, logging, dep guard.
- [webui.md](webui.md) — the browser UI: panels/tabs, view router, HTTP+WS comms.
- [generic-agent.md](generic-agent.md) — `GenericLeafAgent` leaf agent + the agent-spoke `_ROLE_MAP` role loader (10 roles + bugfixer deploy role).

## Spokes

- [pxmx.md](pxmx.md) — Proxmox (`hypervisor`): bridge spoke + per-host agent; USB auto-provisioning brain; VNC relay; `/ws/agent` byte-proxy.
- [cs.md](cs.md) — Client Simulation (`simulation`): sim engine, client API :8080, per-client override panel, relay-only Proxmox.
- [netbox.md](netbox.md) — IPAM/DCIM (`ipam`): sync_vms/devices/nw_device/access_tracker, staleness sweep, custom fields, Kea sync.
- [opnsense.md](opnsense.md) — Firewall (`firewall`): aliases/NAT/rules/DNS/DHCP-leases/ARP; categories-as-UUIDs; cache.
- [nw.md](nw.md) — Network Devices (`nw`): SSH/CLI + REST + SNMP fleet driver; ARP-as-discovery-feed.
- [cppm.md](cppm.md) — ClearPass NAC (`nac`): OAuth token strategy, endpoint sync tagging, non-BaseSpoke.
- [ldap.md](ldap.md) — Directory (`directory`): OU/user/group CRUD + search; namespace-package loader.
- [dhcp.md](dhcp.md) — DHCP (`dhcp`): thin Kea DHCP4 spoke; subnets/leases/reservations.
- [dns.md](dns.md) — DNS (`dns`): Unbound via `unbound-control`.
- [le.md](le.md) — Certificate Management (`certificates`): certbot ACME producer + ledger.

## Agents

- [bugfixer.md](bugfixer.md) — autonomous GitHub-issue fixer bot; optional hub **agent** (not a spoke); signed `GET_LOGS`/`TRIGGER_ALL_UPDATES`.
- (pxmx per-host agents are documented under [pxmx.md](pxmx.md); GenericLeafAgent under [generic-agent.md](generic-agent.md).)

## Reference

- [environment-variables.md](environment-variables.md) — every `LM_*`/`HUB_*`/`CS_*`/`KEA_*`/`NETBOX_*`/`CPPM_*`/`LDAP_*`/`UNBOUND_*` var, what it does, default, where read.
- [install-flags.md](install-flags.md) — every installer + its flags.

## Quick lookup

- **Hub port:** unified `0.0.0.0:443` wss (or `:443` plain, no cert); co-located callers dial `wss://127.0.0.1:443`. No separate loopback port.
- **pxmx agent link (standalone DEFAULT — agent → spoke → hub):** the pxmx spoke (own box) serves `wss://:443` and the agent dials `wss://<spoke>:443/ws/agent` **directly** (pinned via `--spoke-url`; no mDNS auto-discovery for a standalone spoke). **Loopback (opt-in — agent → hub → spoke):** only when co-located all-in-one (`install_all.sh --loopback` path) — the agent dials `wss://<hub>:443/ws/agent` and the hub byte-proxies to the pxmx spoke's loopback `:8443` (`LM_PXMX_AGENT_LOOPBACK=1`). See [pxmx.md](pxmx.md).
- **cs client API:** 8080.
- **TLS verify:** off by default; opt in with `--tls-verify` (+ `--tls-ca-cert`).
- **Discovery:** mDNS `_lm-hub._tcp.local.` TXT (`agent_port`=443, `tls_port`) + DNS `lm-hub.<search>`; same-box = IP-equality.
- **Auto-provisioning brain:** the pxmx agent, not the hub or cs spoke.
- **Spoke ERROR → hub HTTP 502** with the real reason.
- **`request_response` for a spoke reply** (e.g. VNC ticket); `send_to_spoke_command` is fire-and-forget.