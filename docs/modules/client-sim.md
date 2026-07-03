# Client Simulator Module Guide

The Client Simulator (CS) module is used to generate synthetic traffic and simulate end-user behavior for testing network policies and firewall rules. The spoke source lives in `client_sim/`; the Hub-side operator UI is ported into the Simulations module and exposed under `/sim/api/*`.

## 1. Capabilities
- **Traffic Generation**: Simulating various protocols and traffic patterns.
- **DNS Configuration**: Setting custom DNS profiles for simulated clients.
- **Schedules**: Automating when simulation loads are triggered.
- **USB Auto-Provisioning status**: surfaces live provisioning state from the pxmx host agent (the brain runs in the agent, not the Hub — see [pxmx.md](pxmx.md)).

## 2. Configuration
Configuration is managed via **Setup $\rightarrow$ Global Config $\rightarrow$ CS**. It uses a JSON-based profile system allowing multiple simulation profiles to be defined.

## 3. `/sim/api` surface

The ported Client-Sim operator UI is served by the Hub. All `/sim/api/*` routes
require a valid `lm_session`; superadmin routes additionally require an admin
session. Telemetry is also streamed over a WebSocket. See [api.md](../api.md)
§"Simulations (cs) — `/sim/api/*`" for the full endpoint table (init, health,
auth, superadmin tenants/users/USB VID:PID lists, per-tenant aggregate shapers,
spoke config, hub-owned USB-provisioning config, onboarding PSK, auto-provision
toggle, config-push, and the `/sim/ws` telemetry stream). Route handlers live in
`core/src/simulations/routes.py`; the per-tenant store is
`core/src/simulations/store.py` (`simulations_store.json`).

## 4. Installation

```bash
sudo bash install_cs.sh \
  --hub wss://<hub-ip>:443/ws/spoke \
  --id cs-spoke-1 \
  --secret <first-secret>
```

Installs under `/opt/lm/cs/` and provisions the `lm-cs` systemd unit. The cs
unit does **not** redirect output to a file — see Logging below.

## 5. Technical Implementation
The Client Sim spoke runs a series of traffic generators. It is primarily used as a validation tool to ensure that the rules configured in OPNsense or CPPM are actually working as intended by observing the resulting traffic patterns.

## 6. Logging

The cs spoke logs to **journald only** — there is no file redirect. Read with:

```bash
journalctl -u lm-cs -f
```

This differs from the file-logged spokes (pxmx, dns, dhcp, …), which append to
`/var/log/lm/lm-<module>.log`. The opnsense spoke is also journald-only.
See [log_format.md](../log_format.md) for the format and the full log-location
table.
