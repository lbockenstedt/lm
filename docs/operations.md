# Operations & Runbook

Day-2 operations for a Lab Manager host installed by `install_all.sh` /
`install_production.sh`. Covers the root helper scripts, the sudoers grants, the
on-disk state inventory, and the three most common recovery runbooks.

> Log locations and format: see [log_format.md](log_format.md).
> Install + update-recovery background: see [installation.md](installation.md)
> §"Hub / WebUI Update Recovery".

## 1. Root helper scripts

All three helpers are provisioned by `install_all.sh` into `/usr/local/bin/` and
are the **only** commands the `svc_lm` service user is allowed to run as root
(see §2 sudoers). They exist because systemd stops a service inside its own
cgroup — a restart triggered **by** the hub cannot outlive the hub process that
requested it. Each helper launches via `systemd-run` as a **transient unit
outside `lm.service`'s cgroup** so it survives the restart it just requested.

| Helper | When to call | What it does |
|---|---|---|
| `/usr/local/bin/lm-self-restart` | The hub needs to restart itself without losing the request (e.g. after a config change that requires a clean re-init). | `systemd-run` a transient unit (outside `lm.service`'s cgroup) that runs `sleep 3; exec systemctl restart lm` — a **bare restart with no health gate**. It does **not** poll `https://localhost:443/status` and does **not** exit non-zero on a boot failure; the caller is expected to verify health separately. Contrast with `lm-update-restart`, which *does* poll `/status` and rolls back on failure. |
| `/usr/local/bin/lm-update-restart` | After a code swap (auto-update via `Hub.perform_update` in `core/src/main.py`, `POST /setup/update`, or BugFixer). | Restarts the hub from the new code, polls `/status` for 60 s; on failure restores the pre-swap snapshot from `update-backup/<ts>/`, marks the version bad in `bad_versions.json`, restarts again, and re-polls for 30 s. On **double failure** writes `update_failed.json` and preserves the backup. |
| `/usr/local/bin/lm-spoke-recover` | A spoke unit is stuck `status=203/EXEC` (missing binary, bad `ExecStart`, broken venv, wrong `User`/`WorkingDirectory`). | `--inspect <unit>` reads six `systemctl show` properties — `ActiveState`, `SubState`, `Result`, `ExecMainStatus`, `ExecMainCode`, `NRestarts` — and prints them as one JSON line. The recover path does `systemctl reset-failed <unit>` (only if `SubState==failed`) followed by `systemctl restart <unit>` — **no unit-file rewrite, no `daemon-reload`**. It returns JSON with the pre-recovery state plus `reset` and `restarted` flags. |

Rationale and exact provisioning: see `install_all.sh` (the systemd unit
`ExecStop` + helper-provisioning block) and `core/src/update_recovery.py` for
the snapshot/rollback state machine shared by both update paths.

## 2. Sudoers grants (`/etc/sudoers.d/lm`)

The installer writes a least-privilege sudoers fragment that lets `svc_lm` run
**only** the three helpers above, by absolute path, with no other root rights:

```sudoers
svc_lm ALL=(root) NOPASSWD: /usr/local/bin/lm-self-restart
svc_lm ALL=(root) NOPASSWD: /usr/local/bin/lm-update-restart
svc_lm ALL=(root) NOPASSWD: /usr/local/bin/lm-spoke-recover
```

No wildcard, no shell, no `ALL` commands. This is what lets the hub
self-restart / self-update without being a full sudoer. Do **not** broaden this
file — if a new privileged action is needed, add a new scoped helper in
`install_all.sh` and a matching single-line grant here.

## 3. State-file inventory (`/var/lib/lm/state/`)

All hub state lives under `/var/lib/lm/state/` (writable by `svc_lm`; formats
shared by both update paths and defined in `core/src/update_recovery.py` and
`core/src/state/manager.py`).

| Path | Purpose | When present | Who writes it |
|---|---|---|---|
| `system.json` | Global config, known/approved modules, module metadata, active sessions/tenant. Encrypted at rest via `hub_encryption` (`LM_FERNET_KEY`). | Always (created on first boot). | `StateManager` (`core/src/state/manager.py`). |
| `tenants.json` | Per-tenant config (quotas, scoping fields like `netbox_tenant_slug`, `proxmox_tag`, `ldap_base_dn`). | Always. | `StateManager`. |
| `sessions.json` | Active session→tenant bindings. | Always. | `StateManager` (`active_sessions` view). |
| `simulations_store.json` | Per-tenant simulation cache + endpoint-sync status (`endpoint_sync` key: last `status`/`pushed`/`errors`/`last_sync_ts`). | Always. | `SimulationsStore` (`core/src/simulations/store.py`). |
| `pending_update.json` | `{backup_dir, from_version, to_version, ts}` — manifest for the in-flight update. | Mid-update only; cleared on success/rollback. | `core/src/update_recovery.py` `write_pending`. |
| `bad_versions.json` | `{"versions": [...]}` — versions that failed to boot and were rolled back; auto loop skips re-pulling them until a newer remote ships. | After any failed update. | `core/src/update_recovery.py` `_write_bad_versions`. |
| `update_failed.json` | Written **only** on double failure (rollback also failed); carries `to_version` + `backup_dir` for manual recovery. | Only after a double failure; the hub is dark when this exists. | `core/src/update_recovery.py` `write_update_failed`. |
| `update-backup/<ts>/{src,WebUI}` | Pre-swap code snapshot; newest 3 kept, older pruned. | After any update attempt (until pruned). | `core/src/update_recovery.py` `snapshot_before_swap`. |

## 4. Runbooks

### (a) Spoke stuck `status=203/EXEC`

Symptom: `systemctl status lm-<module>` shows `code=exited,
status=203/EXEC` (or `EXEC` with a missing-binary message). This means systemd
could not run the unit's `ExecStart` — the venv python is gone, the entrypoint
module path is wrong, or `User`/`WorkingDirectory` point at a path that no
longer exists (common after a partial re-install or a `pip` that wiped the
venv).

```bash
sudo /usr/local/bin/lm-spoke-recover --inspect lm-pxmx
# prints one JSON line, e.g.:
#   {"unit":"lm-pxmx","ActiveState":"failed","SubState":"exec","Result":"exec",
#    "ExecMainStatus":203,"ExecMainCode":1,"NRestarts":5}
sudo /usr/local/bin/lm-spoke-recover lm-pxmx     # reset-failed (if SubState==failed) + restart
```

`--inspect` emits **only** the six `systemctl show` properties above
(`ActiveState`, `SubState`, `Result`, `ExecMainStatus`, `ExecMainCode`,
`NRestarts`) as JSON — it does **not** print `ExecStart`/`User`/`WorkingDirectory`,
does **not** check whether the venv/entrypoint exists, and does **not** tail
journald. Use `systemctl cat lm-<module>` and `journalctl -u lm-<module>` to
inspect the unit file and recent logs yourself.

The recover action is a `reset-failed` (only when `SubState==failed`) followed
by `systemctl restart` — it does **not** rewrite the unit file or run
`daemon-reload`, so a hand-edited unit that drifted is **not** corrected by
this helper. If the unit file itself is wrong, re-run the module's installer
(e.g. `install_pxmx.sh`) to regenerate it. Logs: `journalctl -u lm-<module>`
and the file in [log_format.md](log_format.md).

### (b) Hub dark after a failed update

Symptom: `systemctl status lm` is `failed` / `inactive`, the WebUI does not
load, and `/var/lib/lm/state/update_failed.json` exists. This is a **double
failure** — the new version failed to boot **and** the rollback also failed.
The pre-swap snapshot is preserved on disk at the `backup_dir` named in
`update_failed.json`.

1. Read `update_failed.json` to get `to_version` and `backup_dir`:
   ```bash
   sudo cat /var/lib/lm/state/update_failed.json
   ```
2. Follow the manual recovery in [installation.md](installation.md) §"Hub / WebUI
   Update Recovery" → "Manual recovery after a double failure": restore
   `core/src` + `WebUI` from `backup_dir`, reinstall deps into
   `/opt/lm/core/venv`, then `systemctl restart lm`.
3. Once the hub is back up, clear the bad version so the auto loop will retry:
   delete the `to_version` entry from `bad_versions.json` (or re-run
   `install_all.sh`, which clears it).

### (c) Spoke shows configured in UI but `host not configured` on reconnect

Symptom: the WebUI shows the spoke (e.g. NetBox / CPPM / LDAP) as configured,
but on spoke reconnect the spoke logs `host not configured` / `count=None` and
comes up unconfigured — every restart.

Cause: NAC / IPAM / Directory config was migrated to `*_instances` **lists**
(`nac_instances`, `ipam_instances`, `ldap_instances`; legacy single
`global_config.cppm` / `.netbox` / `.ldap` keys are cleared). On spoke reconnect
the Hub must **re-push the config from the `*_instances` list**; if it doesn't,
the spoke's in-memory config is empty after a restart even though the UI still
shows the instance row.

Fix / verification:
- Confirm the instance is in the right `*_instances` list via
  `GET /setup/config` (`core/src/api.py` multi-instance routes).
- Confirm the reconnect path re-pushes: the Hub's
  `push_config_to_spoke` (`core/src/main.py`, `_type_to_key` map:
  `nac→"cppm"`, `ipam→"netbox"`, `directory→"ldap"`) must fire on spoke
  reconnect and send the config derived from the list, not the cleared legacy
  key. This was fixed (commit `409e796`) — if you see this symptom on a recent
  build, check that the spoke reconnect handler is actually invoking
  `push_config_to_spoke` for the spoke's `module_type`.
- See [modules/netbox.md](modules/netbox.md) and [modules/cppm.md](modules/cppm.md)
  for the per-module config shape, and the memory note on multi-instance config
  push for the background.

## 5. Log locations

Cross-reference [log_format.md](log_format.md) for the full table. Quick
reference:

- Hub: `/var/log/lm/hub.log` (`journalctl -u lm` also works)
- pxmx spoke: `/var/log/lm/lm-pxmx.log`
- dns spoke: `/var/log/lm/lm-dns.log`
- dhcp spoke: `/var/log/lm/lm-dhcp.log`
- cs spoke: **journald only** — `journalctl -u lm-cs` (no file redirect)
- opnsense spoke: **journald only** — `journalctl -u lm-opnsense` (no file redirect)
- netbox / ldap / cppm spokes: path depends on the sibling-repo installer cloned by `install_all.sh` — see [log_format.md](log_format.md)