# generic-agent (lm/generic_agent + lm/agent)

Two related things in the `lm` repo: (1) a **leaf agent** that calls home to a hub/spoke-gateway, and (2) an **agent-spoke** that can morph into any role on `LOAD_ROLE`. Not a separate repo — lives under `lm/`.

## Role & module_type

- `generic_agent/src/agent.py::GenericLeafAgent` — a leaf agent (`module_type` inherited from its gateway). Calls home, receives `SPOKE_COMMAND`.
- `agent/src/agent_spoke.py::GenericAgent` — a spoke of the hub that, on `LOAD_ROLE`, clones a sibling repo and swaps in a real spoke class.

## Entrypoints

- **GenericLeafAgent:** `generic_agent/src/agent.py`. systemd unit (built by `generic_agent/install_github.sh`), `--spoke-url` (default `auto` → discover), `--id` (default `generic-agent-1`), `--secret`.
- **Agent-spoke:** `agent/src/control_plane.py` (argparse entrypoint), `--id` (required), `--secret`, `--hub-secret`, `--hub` (required), `--role` (default `STARTUP_ROLE` env). systemd unit built by `agent/install_agent.sh`.

## Ports

- GenericLeafAgent: none served; dials `wss://127.0.0.1:443/ws/spoke` (same-box, verify-off) or `wss://<hub>:443/ws/spoke` (remote), or a SpokeGateway.
- Agent-spoke: none served; dials the hub.

## Environment variables

`LM_HUB_TLS_VERIFY`, `LM_HUB_CA_CERT` (client TLS verify), `STARTUP_ROLE` (agent-spoke default role), `LM_ONBOARDING_PSK`, `LM_TENANT_ID_HINT`.

## Install flags

- `generic_agent/install_github.sh`: `--spoke-url` (optional/`auto`), `--id`, `--secret`, `--hub-secret`, `--tls-verify` (+ `--tls-ca-cert`; defaults to `/opt/lm/certs/hub.crt` if present, else requires it), `--clone` (install but don't start).
- `agent/install_agent.sh`: `--hub` (required), `--id`, `--secret`, `--role` (one of `dns|dhcp|network|netbox|opnsense|ldap|simulation|cppm|proxmox|le`).

## Key commands / handlers

- **GenericLeafAgent:** receives `SPOKE_COMMAND` from the gateway; mutual auth (`HUB_VERIFIED` → `HUB_OK`); reconnect loop with backoff + re-discovery.
- **Agent-spoke `_ROLE_MAP`** (rel_path, class, module_type, repo):
  - `dns` → `dns/src/dns_spoke.py::DNSSpoke` (`dns`, in-repo)
  - `dhcp` → `dhcp/src/dhcp_spoke.py::DHCPSpoke` (`dhcp`, in-repo)
  - `network` → `nw/src/nw_spoke.py::NwSpoke` (`nw`, `lbockenstedt/nw.git`)
  - `netbox` → `netbox/src/netbox_spoke.py::NetboxSpoke` (`ipam`, `lbockenstedt/netbox.git`)
  - `opnsense` → `opnsense/src/opn_spoke.py::OpnSpoke` (`firewall`, `lbockenstedt/opnsense.git`)
  - `ldap` → `ldap/src/ldap_spoke.py::LdapSpoke` (`directory`, `lbockenstedt/ldap.git`)
  - `simulation` → `cs/lm-spoke/src/cs_spoke.py::CSSpoke` (`simulation`, `lbockenstedt/cs.git`)
  - `cppm` → `cppm/src/spoke.py::CPPMSpoke` (`nac`, `lbockenstedt/cppm.git`)
  - `proxmox` → `pxmx/src/proxmox_spoke.py::ProxmoxSpoke` (`hypervisor`, `lbockenstedt/pxmx.git`)
  - `le` → `le/src/le_spoke.py::LESpoke` (`certificates`, `lbockenstedt/le.git`)
  - `_DEPLOY_ROLES`: `bugfixer` (curl|bash install of `lbockenstedt/bugfixer`, module_type `agent`).
  - `_RoleAdapter` wraps non-BaseSpoke roles (e.g. cppm). `LOAD_ROLE`/`UNLOAD_ROLE`/`UPDATE_CONFIG` handling; `_load_role_class`/`_sync_load_role`/`_install_role` (git clone + venv pip install).

## Key files

`generic_agent/src/agent.py`, `generic_agent/src/hub_discovery.py` (4th vendored copy), `generic_agent/install_github.sh`, `generic_agent/install_agent.sh`, `agent/src/agent_spoke.py`, `agent/src/control_plane.py`, `agent/install_agent.sh`.

## Notable behaviors & gotchas

- **GenericLeafAgent was missed by the TLS rollout** — it used to take `--spoke-url` verbatim with no `ssl=`. Symptom: `Connecting to Spoke Gateway at ws://<hub>:443...` → `timed out during opening handshake` = plaintext-into-TLS-port. Fixed: vendored discovery, `--spoke-url auto` default, `_client_ssl_ctx` (verify-off default), reconnect + re-discovery, auto-upgrade of a pinned `ws://...:443` to `wss://`.
- **Boot `--role` does NOT run `_install_role`** — `install_agent.sh` stages a boot `--role` but only pre-installs system packages; the role class loads on first `LOAD_ROLE` from the hub.
- **9 sibling repos auto-clone on `LOAD_ROLE`** — covers every canonical hub module type except `agent`.

## Related pages

[architecture-topology.md](architecture-topology.md), [lm-hub.md](lm-hub.md), [install-flags.md](install-flags.md).