# Installation Guide

This guide describes how to deploy the Lab Manager Hub and its associated Spokes.

## 1. Hub Installation
The Hub is designed to run on a Linux host (preferably in an LXC container or VM).

### Prerequisites
- Python 3.10+
- `git`
- `pip`
- `systemd` (for service management)

### Production deployment (recommended)
Run the full installer as root on the host — it creates the `svc_lm` service user, installs the Hub + WebUI under `/opt/lm/core`, seeds `LM_FERNET_KEY`, provisions the `lm.service` systemd unit (with `ExecStop` and the update-recovery helpers), and writes the log/state directories:

```bash
sudo bash install_all.sh        # full stack (hub + webui + all local spokes)
# or, for a production-only hub with no spokes:
sudo bash install_production.sh
```

The legacy `install.sh` / `install_hub.sh` / `install_ui.sh` entrypoints are deprecated; use `install_all.sh` (full) or `install_production.sh` (prod) instead. For post-install operations, recovery, and the root helpers, see [operations.md](operations.md).

### Dev quickstart (no systemd, manual)
For local development only — not for a deployed host:
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/lbockenstedt/lm.git
   cd lm
   ```
2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
3. **Configure the Hub**:
   Edit the system configuration via the WebUI after starting, or by modifying the `data/system.json` file.
4. **Start the Hub**:
   ```bash
   python3 core/src/main.py
   ```
   The Hub will start a single unified server on port `443` (wss when a cert is configured, plaintext otherwise) serving the REST API, WebUI, and the `/ws/spoke` + `/ws/agent` WebSocket routes.

### Hub / WebUI Update Recovery

The hub has two update paths. **Both now snapshot the code before swapping and
roll back automatically if the new version fails to boot** — so a bad push no
longer leaves the hub dark:

- **Manual path** — `install_all.sh` (run on the host). It snapshots `core/src`
  + `WebUI` before its destructive `rm -rf`, starts the hub, and polls
  `https://localhost:443/status` for 200 for 60s. If the poll fails it restores
  the snapshot, reinstalls the rolled-back `requirements.txt`, restarts, and
  re-polls for 30s. Exits 0 if the rollback boots ("install failed but rolled
  back…"), 1 only if the rollback *also* fails.
- **Auto path** — `Hub.perform_update` (`core/src/main.py`, driven by
  `run_autoupdate_loop`, `POST /setup/update`, or BugFixer). It snapshots before
  the `git pull`/tarball swap, writes a "pending update" manifest, then hands
  off to the root-run `/usr/local/bin/lm-update-restart` helper (a
  `systemd-run` transient unit outside `lm.service`'s cgroup, so it survives
  the restart). The helper restarts the hub, polls `/status` for 60s; on
  failure it restores the snapshot, marks the version bad, restarts again, and
  re-polls for 30s.

**Recovery state** (all under `/var/lib/lm/state/`, svc_lm-writable; formats
shared by both paths and defined in `core/src/update_recovery.py`):

| File | Purpose |
|---|---|
| `update-backup/<ts>/{src,WebUI}` | Pre-swap code snapshot; newest 3 kept, older pruned. |
| `pending_update.json` | `{backup_dir, from_version, to_version, ts}` — present only mid-update; cleared on success/rollback. |
| `bad_versions.json` | `{"versions": [...]}` — versions that failed to boot and were rolled back. |
| `update_failed.json` | Written only on **double failure** (rollback also failed); carries `to_version` + `backup_dir` for manual recovery. The backup is preserved on disk. |

**Bad-version policy** — a rolled-back version is appended to `bad_versions.json`
and the auto loop **skips re-pulling it** until a **newer** remote version
ships (stale entries older than the new remote are auto-cleared). `?force=true`
on `POST /setup/update` bypasses the skip (operator explicitly re-trying). To
clear manually, delete the entry from `bad_versions.json` or re-run
`install_all.sh`. The downside: if unnoticed, the hub can stay on an older
version until something newer ships.

**Manual recovery after a double failure** — if `update_failed.json` exists,
the hub is down and the snapshot is preserved at its `backup_dir`. Restore by
hand: `cp -a $backup_dir/src /opt/lm/core/src && cp -a $backup_dir/WebUI
/opt/lm/WebUI`, reinstall deps (`/opt/lm/core/venv/bin/python3 -m pip install
-r /opt/lm/core/requirements.txt`), then `systemctl restart lm`.

---

## 2. Spoke Installation (Manual)
Each module (OPNsense, Proxmox, CPPM, etc.) has its own installation script.

### General Workflow
1. **Run the Install Script**:
   Navigate to the module directory and execute the provided `.sh` script.
   ```bash
   # Example for OPNsense
   bash opnsense/install_opnsense.sh --hub wss://<hub-ip>:443/ws/spoke --id opn-spoke-1 --secret <first-secret>
   ```
2. **Parameters**:
   - `--hub`: The WebSocket URL of the Hub.
   - `--id`: The unique identifier for the spoke.
   - `--secret`: The initial "First Secret" generated by the Hub for onboarding.
3. **Approval**:
   After the spoke connects, go to **Setup $\rightarrow$ Spoke Approvals** in the WebUI and approve the new spoke.

---

## 3. Automated Provisioning (Generic Agent)
The Generic Agent is a "bootstrapper" that allows the Hub to remotely deploy other modules.

### How it Works
1. A "Generic Agent" is installed on a clean LXC container.
2. The Generic Agent connects to the Hub.
3. From the WebUI (**Setup $\rightarrow$ Generic Nodes**), the admin can "Provision" a specific module.
4. The Hub sends a `PROVISION_MODULE` command, telling the agent to:
   - Clone the module's repository from GitHub.
   - Run the installation script.
   - Configure the spoke ID and secret.
   - Restart as the target module service.

### Deploying a Generic Agent
Run the generic agent installation script:
```bash
bash install_agent.sh --hub wss://<hub-ip>:443/ws/spoke --id generic-agent-1 --secret <secret>
```

---

## 4. Module Specifics
Install scripts live at the repository root (or under the module dir where noted). Run them as root; they install under `/opt/lm/<module>/` and provision a `lm-<module>.service` systemd unit.

| Module | Requirements | Install Script |
| :--- | :--- | :--- |
| **OPNsense** | OPNsense API Access | `install_opnsense.sh` |
| **Proxmox** | PVE API / SSH | `install_pxmx.sh` |
| **NetBox** | NetBox REST API access | Spoke source in a sibling repo — `install_all.sh` clones `github.com/lbockenstedt/netbox.git` and runs `/opt/lm/netbox/install.sh` (with `--spoke-only`). A local stub also exists at `provisioning_repos/netbox/install.sh`. See [modules/netbox.md](modules/netbox.md). |
| **Client Sim** | Python 3 | `install_cs.sh` |
| **DHCP** | Kea DHCP4 server | `dhcp/install_dhcp.sh` |
| **DNS** | Unbound DNS server | `dns/install_dns.sh` |
| **CPPM** | ClearPass REST API | _Spoke source not in this repo_ — `install_all.sh` clones `github.com/lbockenstedt/cppm.git` and runs its `install.sh`. See [modules/cppm.md](modules/cppm.md) for the integration contract. |
| **LDAP** | LDAP directory access | _Spoke source not in this repo_ — `install_all.sh` clones `github.com/lbockenstedt/ldap.git` and runs `install_ldap.sh`. The Hub-side API and config surfaces for LDAP are in-repo (see [api.md](api.md) §LDAP). |

> No `kvm/` module ships in this repository, so no `kvm/install_kvm.sh` is
> provided. No `ldap/` directory ships in this repository either, but LDAP
> **is** installed by `install_all.sh` — it clones the sibling
> `github.com/lbockenstedt/ldap.git` repo and runs its `install_ldap.sh`
> (pre-approving `ldap-spoke-1`), so an operator running the full installer
> gets an `lm-ldap` spoke even though no `ldap/` dir lives in this tree. The
> KVM column in §6 below is forward-looking and **not shipped**.

---

## 5. Self-Registration (All Spokes)

Spoke installers authenticate to the Hub at install time with the **first secret** (or hub secret) flags — `--secret` and `--hub-secret` — not an admin token. With no pre-shared secret the spoke connects unauthenticated and awaits admin approval in the WebUI (Setup → Spoke Approvals).

```bash
# Pre-shared first secret (generated by the Hub at /setup/generate-secret)
sudo bash install_pxmx.sh \
  --hub wss://<hub-ip>:443/ws/spoke \
  --id pxmx-spoke-1 \
  --secret <first-secret> \
  --hub-secret <hub-root-secret>
```

The secret is stored in `/opt/lm/<module>/.env` as `SPOKE_SECRET=…` (and `HUB_SECRET=…`) and is preserved on re-runs.

---

## 6. Co-Existence: Proxmox (+ KVM, future)

The Proxmox spoke registers as `module_type="hypervisor"`. The Hub resolves a
hypervisor via `hub.get_spoke_by_type("hypervisor")` — whichever hypervisor
spoke is connected is used.

| | Proxmox | KVM |
|--|---------|-----|
| Ships in this repo | yes | **no** — not shipped (future) |
| Agent listen port | 443 (`/ws/agent`, proxied to spoke loopback `8443`) | 8767 (planned) |
| Systemd service | `lm-pxmx` | `lm-kvm` (planned) |
| Config dir | `/opt/lm/pxmx/.env` | `/opt/lm/kvm/.env` (planned) |
| Log file | `/var/log/lm/lm-pxmx.log` | `/var/log/lm/lm-kvm.log` (planned) |

A KVM spoke that implements the same `module_type="hypervisor"` command contract
could co-exist with the Proxmox spoke; the Hub routes to whichever is connected,
and if both are connected the first registered wins. No `kvm/` directory or
`install_kvm.sh` is present in this repository today, so the KVM column above is
forward-looking and is **not shipped**.

---

## 7. Hub Security Configuration

`install_all.sh` (and `install_production.sh`) seed the **`LM_FERNET_KEY`**
environment variable automatically — this is the symmetric key the
`StateManager` uses to encrypt `keys.json` and `hub_secret.json` on disk (see
[security.md](security.md) §4). An operator following the installer alone does
**not** need to set it by hand.

`LM_ADMIN_TOKEN` (the admin token that gates `/setup` POST/PUT/DELETE endpoints —
see [api.md](api.md) §Authentication) is an **optional, post-install manual
hardening step**. The installer does **not** seed it. To enable it:

```bash
# Generate a token
TOKEN="$(openssl rand -hex 32)"
# Write it into the hub's systemd EnvironmentFile (created by the installer)
echo "LM_ADMIN_TOKEN=$TOKEN" >> /opt/lm/core/.env
# Or export it inline for a dev run:
#   export LM_ADMIN_TOKEN="$TOKEN"
sudo systemctl daemon-reload
sudo systemctl restart lm
```

If `LM_ADMIN_TOKEN` is not set, the hub starts with a `WARNING` and the `/setup`
mutation endpoints are unauthenticated. `/setup/generate-secret` is always
exempt so spokes can still self-register at install time (using `--secret` /
`--hub-secret`, not an admin token — see §5).
