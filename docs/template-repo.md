# Template Repo — hub-local Proxmox template backups

A **Global Admin backs up a Proxmox template to the hub's own disk** (the hub runs
on a full VM now), and a **tenant refreshes a host's template** from that stored
backup. This is a hub-local alternative to the original project's Azure-Blob backup
path — the archive lives on the hub, not in cloud storage.

## Role & where it lives

- Hub: `core/src/template_repo.py` (`TemplateRepo` store) + `core/src/routes/templates.py`
  (routes). `hub.template_repo` is instantiated in `main.py`.
- Agent: the pxmx agent's `START_BACKUP` + `REFRESH_TEMPLATE` handlers (`pxmx/agent/src/agent.py`).
- WebUI: **Template Repo** admin page (`renderTemplateRepo`, `WebUI/main.js`) + a
  "⬆ Back up to Hub" button on a VM, and a multi-select **Refresh Template(s)** action
  on **VM Server / VMs** (`WebUI/sim-views.js`).

## Storage layout

One directory per template under `<data_dir>/template-repo/`:

    <data_dir>/template-repo/<id>/
        image.vma.zst     the vzdump archive
        meta.json         the record (authoritative — index rebuilt from it on load)

`meta.json` fields: `id`, `name`, `source_vmid`, `source_node`, `source_agent`,
`source_spoke`, `size`, `sha256`, `status`, `progress`, `created_at`/`created_by`,
the editable `version`/`os`/`purpose`, and the **derived** `tenant`/`tenant_id`.
Private (never in the API view): `_upload_token`, `_refresh_token`.

## Backup flow (Global Admin → hub)

1. Admin clicks **⬆ Back up to Hub** on a VM (or POST `/setup/templates/backup`).
   The hub creates a *pending* record + a one-time `_upload_token`, resolves the
   owning agent (from the VM's `unique_id` / `agent_info`), and relays
   `SPOKE_RELAY START_BACKUP {template_id, vmid, node, upload_url, upload_token}`.
2. The agent runs `vzdump <vmid> --compress zstd --mode stop --dumpdir <tmp>` and
   **streams** the `.vma.zst` to `PUT /api/templates/{id}/upload` with the token
   (`X-Upload-Token`) + `Content-Length`. The hub writes it straight to disk
   (no buffering), enforces a size cap (`LM_TEMPLATE_MAX_GB`, default 300) + a
   free-space guard, computes `sha256`, and finalizes (consuming the token).
3. Progress (`dumping`/`uploading` %) flows via `POST /api/templates/{id}/progress`.

The upload/progress/download endpoints are **token-authed** (agents have no browser
session); the access-control middleware exempts exactly those paths.

## Tenant binding

The template's tenant is **derived from the source PXMX host, per host** — the
agent's Client-Simulation `tenant_id` (Agent Config), falling back to the owning
spoke's tenant (`get_spoke_tenant`); a display name is resolved via `state.get_tenant`.
It is authoritative — not an editable free-text field. The Template Repo table groups
by tenant.

## Refresh flow (tenant or admin → restore to host, DESTRUCTIVE)

**Refresh Template(s)** on **VM Server / VMs**: select one/some/all hosts and refresh
each host's template from its latest stored backup. For each host the hub resolves
the latest complete template by `source_spoke` (`latest_complete_for_spoke`), checks
tenant ownership, mints a `_refresh_token`, and relays
`SPOKE_RELAY REFRESH_TEMPLATE {template_id, template_vmid, download_url, refresh_token}`.

The agent runs the sequence (background task, reports each step via
`/api/templates/{id}/refresh-progress`):

1. **Pause auto-provisioning** (`usb_provision.set_refresh_paused` — the provision
   loop short-circuits so it can't fight the wipe).
2. **Wipe the host's sim VMs only** — VMIDs in this host's sim range
   (`_host_vmid_range`), PROTECTED_VMIDS excluded, guarded `cs_sim.destroy_vm`.
3. **Download** the archive from the hub (`GET /api/templates/{id}/download`,
   FileResponse, refresh-token-authed).
4. **`qmrestore <archive> <template_vmid> --force`** (overwrites the old template —
   no raw destroy of an arbitrary VMID) then **`qm template <vmid>`** to re-mark it,
   so clones/auto-prov keep pointing at the same template id.
5. **`finally:` always resume auto-provisioning** — even on failure.

## Routes

| Route | Who | Purpose |
|---|---|---|
| `GET /setup/templates` | Global Admin | list all |
| `GET /tenant/templates` | tenant-admin | list own-tenant (admin sees all) |
| `POST /setup/templates/backup` | Global Admin | trigger a backup |
| `PATCH /setup/templates/{id}` | Global Admin | edit version/os/purpose/name |
| `DELETE /setup/templates/{id}` | Global Admin | delete a stored template |
| `POST /setup/templates/{id}/refresh` | Global Admin | refresh one template's host |
| `POST /tenant/templates/{id}/refresh` | tenant-admin (own) | refresh (anti-IDOR 404) |
| `POST /tenant/templates/refresh-hosts` | tenant-admin/admin | fleet multi-host refresh `{spoke_ids}` |
| `PUT /api/templates/{id}/upload` | agent (upload token) | streamed backup upload |
| `GET /api/templates/{id}/download` | agent (refresh token) | streamed archive download |
| `POST /api/templates/{id}/{,refresh-}progress` | agent (token) | status pings |

## Notable behaviors & gotchas

- **Agent↔hub reachability**: agents dial the *spoke*, so the direct HTTPS upload/
  download needs the agent to reach the hub URL (carried in the command, defaulting
  to the admin's browser URL or `LM_HUB_PUBLIC_URL`). Set `LM_HUB_PUBLIC_URL` when
  the agent-facing hub address differs from the browser-facing one.
- **qmrestore storage**: uses the storage recorded in the backup — that storage must
  exist on the target node.
- **Metadata authority**: `tenant` is derived (not editable); `version/os/purpose/name`
  are the only editable fields.

## Related pages

[pxmx.md](pxmx.md) (the agent that runs vzdump/qmrestore), [lm-hub.md](lm-hub.md),
[le.md](le.md) (the other hub-brokered agent-file flow — cert distribution).
