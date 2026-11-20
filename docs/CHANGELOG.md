---
summary: "Rolling summary of recent user-facing changes to the LM hub and its modules, newest first, each linking to the module doc that covers it in full."
keywords: [changelog, whats-new, release-notes, recent-changes, lm]
---

# What's new

A rolling, human-readable summary of recent **user-facing** changes, newest
first. This is a pointer index, not the source of truth — each entry links to
the module doc that describes the behaviour in full. Internal refactors and
CI/tooling changes are omitted unless they change what an operator sees.

## Week of 2026-11-16

### Users & access

- **A Global Admin can name the common VRFs.** Shared infrastructure serves NetBox's global table plus the common VRFs, and a VRF counted as common whenever two or more tenants had prefixes in it, even one shared infrastructure does not serve (such as a VRF two tenants of one customer share). System → General → **Common VRFs** lists the VRFs tenants have prefixes in, by name, from the hub's NetBox cache. Tick the ones shared infrastructure serves and click **Save**, and exactly those are common: a ticked VRF one tenant uses is common, and an unticked VRF several tenants share is cut. With nothing ticked, the default, the hub infers them as before, so nothing changes until a list is saved. A change applies the next time the hub filters shared data, with no restart. The API is `GET`/`PUT /admin/common-vrfs` (`{"vrf_ids": ["12"]}`); a value that is not a list of NetBox VRF ids is refused. See [architecture-topology.md](architecture-topology.md).
- **Syncing tenants from NetBox no longer holds up the hub on a large fleet.** The 5-minute NetBox tenant and tenant-group sync, **Sync from NetBox** on the Tenants card, and the Test Data Feed's tenant set-up used to rebuild the hub's tenant caches (group members, the shared tenant, and the ids that only case tells apart) after every tenant they wrote. At 500 tenants that cost about 1.1 s each cycle, and the hub answered no other request in that time. Each loop now rebuilds the caches once, when it ends. Saving a single tenant still updates them at once. See [netbox.md](netbox.md#notable-behaviors--gotchas).
- **Tenants in a shared VRF see their DNS and DHCP again.** Since shared infrastructure started ignoring prefixes a tenant has only in its own VRF, every prefix outside NetBox's global table was cut, including a VRF all tenants share. Where every tenant sits in a VRF, the DNS and DHCP pages went empty for every tenant, the Admin tenant a Global Admin starts on included. A VRF that more than one tenant has prefixes in now counts as common, like the global table; a VRF only one tenant uses is still its own and still cut (DXP's, for example). Which VRFs are common is decided from every tenant's prefixes in the hub's background NetBox cache, so it does not depend on which tenants were opened since the hub started. See [architecture-topology.md](architecture-topology.md).
- **Generate certificate names the path it can't write.** When the hub can't write the SSO key's directory, Settings → Azure → SSO → Generate certificate now says which path it needs write access to, instead of a bare "Internal server error". See [entra-sso.md](entra-sso.md#troubleshooting).

### OS Updates

- **VMs hosted behind a spoke that cannot snapshot are patched, with a warning.** A node whose VM sits on a cluster whose agents dial a spoke without VM-action support (the Client-Sim spokes) used to fail every run with "Unknown command: PXMX_VM_ACTION" and was never patched. It now patches with a warning on the run item, like storage that cannot snapshot; a snapshot that fails for any other reason still blocks patching.
- **A repository that answers 404 is named.** When `apt-get update` or the upgrade gets a `404 Not Found` from the package repository, the message now says the OS release may be past end of support (its repository moved to an archive) and to fix the apt sources or upgrade the OS, instead of reading like a transient error.
- **Log levels follow the outcome.** A node that patched fine, an approval, a cancel and a reboot that scheduled are INFO; a failed apply, a failed reboot, a node left in maintenance mode and a node not patched because its snapshot failed are ERROR (so AB's log sentinel opens on them). Healthy nodes no longer log at WARNING. Each failure is logged once: a failed snapshot is one ERROR that carries the reason (a failed scheduled or Run-now snapshot run is one ERROR listing each VM's error, a run that could not start is one WARNING, and the Run-now request itself is an INFO audit line), a degraded patch is one WARNING, and a failed cluster reboot is one ERROR (plus a second only if the node was left in maintenance mode).
- **Nodes are grouped by tenant, then by state.** The Nodes card used to be one long list. Each tenant is now a collapsible card (named, never an id: a deleted tenant reads "Unknown tenant", the hub is "Hub" and a node with no tenant is "Unassigned"; two tenants that share a name stay separate cards) whose header counts the nodes needing attention, the packages pending and the nodes waiting for a reboot. Inside, nodes sit in state groups, worst first: Needs attention (failed or interrupted in the last run, skipped by it, unreachable, a deploy blocker, or a reboot nobody scheduled), Patching, Updates pending, Not checked yet and Up to date (collapsed unless it is all the tenant has). A node whose deploy left packages pending (a package-by-package deploy) stays under Updates pending with an "updated, N left" badge while the deploy runs (afterwards the refreshed inventory shows "N pending"). While a deploy runs, a node it just finished is shown with what the run reports (packages left, a reboot now needed), not its pre-deploy inventory, so the tenant's totals and order stay right too. That includes a failed apply that got as far as re-listing what is pending. A node being rebooted after its patch (an automatic cluster reboot through maintenance mode, or a manual one) is listed under Patching as "rebooting…", not as updated, and no longer counts as needing a reboot. A patched node whose automatic reboot did not end cleanly is listed under Needs attention with a red badge that says which of four things happened, because each needs different follow-up: "not rebooted" (maintenance mode could not be entered, its guests would not move off, or the command could not be sent, such as when its spoke is updating), "reboot failed" (the spoke answered that the reboot did not happen, and the node was handed back), "reboot not confirmed" (the reboot command went out, or may have because the connection broke while sending, but no answer came back, so the node may be rebooting or may never have got it: check it before rebooting again; a Proxmox cluster node in that case is not handed back, because its guests could return and the next node start while it goes down, so it stays in maintenance mode, reads "left in maintenance" and the run stops), or "left in maintenance" (the node is still in HA maintenance mode, rebooted or not: take it out of maintenance, do not reboot it again). It never reads as up to date while drained. An unexpected error in the reboot cycle fails that node's reboot, takes the node out of maintenance mode when it can (otherwise the node reads "left in maintenance"; if the error struck before the reboot command was sent it reads "not rebooted", after it "reboot failed") and stops the rest of the run instead of leaving the run "running". Rebooting a node by hand with the Reboot button clears its "not rebooted", "reboot failed" or "reboot not confirmed" mark once the reboot goes through, so the page stops flagging a node that has been fixed. A run saved before this upgrade keeps flagging a bad reboot too: its state is derived from the saved reboot text when the hub loads it (a maintenance-mode request that got no answer loads as "left in maintenance", since the earlier code never took the node out again). A run the hub restarted in the middle of no longer leaves a node "patching": one cut off mid-apply or mid-reboot is interrupted (a node cut off mid-reboot may still be in maintenance mode, and its message says so), one never started is skipped. Each group has a "Select all" that ticks only its deployable nodes, and a Sort box orders the tenants and nodes: needs attention first (default), name A–Z, or most updates first. A group you open or close stays that way across the page's 5-second refresh.
- **Nothing is listed until you pick a tenant or a state.** The Nodes card used to open on every node. It now reads "N nodes. Pick a tenant or a state above to list them." under a bar with a Tenant row (tenants A–Z by name, then Hub, then Unassigned; two tenants that share a name are separate chips) and a State row (Needs attention, Patching, Updates pending, Not checked yet, Up to date; hover a state for what it holds: Needs attention is the failed, interrupted, skipped, unreachable and blocked nodes and the reboots due or not finished cleanly, Up to date the patched ones). Each chip counts the nodes a click would list under the other row's pick, and a chip with none is hidden. Pick a tenant, a state or both; click a picked chip again to clear it (there is no "All" chip). A row shows only when it offers a choice or holds a pick, so a fleet whose nodes are all one tenant in one state is listed straight away. Changing a pick unticks every node and package, so nothing stays ticked on a node the new pick hides, and leaving the page or switching tenant starts again with nothing picked. A re-check or a run that moves a ticked node out of the pick unticks it too. **Select fixes** under *Who is affected?* ticks only the listed nodes and says how many fixes are on nodes not listed (the CVE results still show every affected node). The summary of failed nodes above the list names only the listed ones, plus nodes whose spoke went offline: those drop out of the list, so they are named (even a lone one) while no tenant is picked and no state other than Needs attention, and always when no node reports at all. A tenant card's header still counts the whole tenant, and with a state picked it says how many of its nodes are listed ("2 of 5 node(s)"). A picked state that empties stays picked, its chip at 0, and the card reads "No nodes are in this state right now."; a picked tenant whose nodes are all gone is un-picked. See [lm-hub.md](lm-hub.md#how-to-use-it).
- **Approve & deploy covers only the listed nodes.** "Approve & deploy all" used to deploy every node you manage that had pending updates, including nodes the list hid, such as another tenant's while one tenant was picked, or every node while nothing was listed yet. It is now "Approve & deploy listed (N)": it deploys the N listed nodes that have pending updates (the ones each group's Select all would tick), and is disabled until a pick lists one and while a run is going. To deploy a whole tenant, pick its tenant; picking only Updates pending lists every tenant's nodes that are waiting for updates. See [lm-hub.md](lm-hub.md#how-to-use-it).

### Managed Devices

- **Nothing is listed until you pick a tenant or a device type.** Setup →
  Module Management → Managed Devices (and My Devices for a Tenant Admin) used
  to open on every device with an "All" tab selected. It now reads "N devices.
  Pick a tenant or a device type above to list them." The Tenant row shows
  when the devices belong to two or more tenants: tenants A–Z by name, then
  Unassigned. A Tenant Admin assigned to several tenants gets it too, with only
  their own tenants and each device under its own tenant (shown by id, as in
  the header picker); before, My Devices listed every assigned tenant's
  devices with no tenant shown. Tenant ids match as the hub's tenant checks
  match them (trimmed and case-folded, so "ACME" and "acme" are one tenant, and
  so are "Straße" and "STRASSE"): devices on spokes bound in different
  capitalisations share one chip, under the tenant's name. A device goes
  under the tenant its own record names, whatever its spoke is bound to, as
  on My Devices and as the hub decides a device's owner, so a Global Admin
  who picks a tenant sees what that tenant sees. Only a record that names no
  tenant takes its spoke's, and it goes under Unassigned when that is blank
  too or it has no spoke. The page groups by
  the `tenant_key` the hub now adds to each row of `/setup/pending_spokes`,
  `/setup/tenants`, `/tenant/devices/*`, `/setup/firewalls`,
  `/setup/nw-devices`, `/setup/truenas-appliances` and the
  `/setup/*-instances`, `/setup/nw-scan-credentials` and
  `/setup/ad-connections` lists, never by a
  case fold of its own (a browser folds "ß" differently from the hub). The
  key is computed for each response and never stored. The Type row
  shows when there are two or more device types. Each chip counts the devices
  a click would list under the other row's pick, and a chip with none is
  hidden; click a picked chip again to clear it. With nothing to choose (one
  tenant and one type) the list shows straight away. The picks survive the
  refresh after an add, an edit, a delete or a discovered-device import, and
  clear on a new visit; switching tenant in the header moves a tenant pick to
  that tenant. A pick whose tenant or type has no device left is cleared,
  but only after a load in which every list answered: a device or spoke list
  that fails to load is named in a red "Could not load" line, and the picks
  stay until it loads. See [lm-hub.md](lm-hub.md#how-to-use-it).

### Network devices

- **Network → Scan no longer drops saved vault logins during a vault
  conflict.** While several Credential Vault buckets name a tenant, the Scan
  tab lists none of its vault logins. **Save config** used to save only the
  ticked sets, so the tenant's saved vault logins were lost, and a scan left
  them out too. They are now kept, though not shown, and sent with every save
  and scan, so a scan stays refused (409) until the conflict is fixed instead
  of running without them. The tab's hint now says what a scan with no set
  ticked does: it uses the saved selection, or every set the tenant owns when
  none is saved. See [nw.md](nw.md#how-to-use-it).
- **A tenant's own id is recognised in any case when it is sent in a
  request body.** Saving the NW tenant config (`POST /api/nw/tenant-config`),
  the topology's manual links or the sweep settings accepts a tenant admin's
  own tenant named in another case ("ACME" for "acme") and saves it under
  the session's spelling. A `?tenant=` query parameter is unchanged: the
  hub's auth middleware accepts from a non-admin only a tenant spelt exactly
  as in their tenants list (403 otherwise), and the WebUI sends that
  spelling. A scan no longer offers to add a device again when its record
  names the tenant in another case, and it updates a monitor-only host
  recorded that way instead of keeping a stale duplicate. See [nw.md](nw.md).

### Spokes and agents

- **Renamed hosts show their new name.** When a spoke's or agent's host is
  renamed, a display name marked as hub-derived follows the new hostname.
  Operator names are preserved even when they match the hostname; ambiguous
  legacy names and suffixes inferred from pinned `agent-` ids are kept. A role
  sub-spoke of a generic agent is named `<host>-<role>` instead of repeating
  its parent's name. See [architecture-topology.md](architecture-topology.md).
- **Failover no longer doubles up a spoke.** A NAC, IPAM or directory
  instance with a failover pool could fail over, or be rebalanced, onto a pool
  spoke already serving another instance of the same product. A spoke is sent
  only one instance of a product, so one of the two went unserved, and two
  tenants' ClearPass instances on one spoke left it serving neither tenant.
  Failover and rebalancing now skip such a spoke; failover logs
  `[instance-relocate] … already serves …` and tries the next pool spoke, or
  stays put when none is left. See [dhcp.md](dhcp.md#tenant-isolation).

### Test Data Feed

- **Feed and load-test spokes never act on the hub's own box.** The feeder runs as a child of the receiving hub, so OS updates, a reboot or a Remote Console command sent to one of its spokes acted on the hub itself, under a production spoke's name. These synthetic spokes now refuse host commands, skip hub pushes that would write files or restart them, and never write the host's `.env` or cert directory (a load test used to write its recovery PSK into the host's `.env`). The hub also leaves them out of OS Updates, Remote Console, mTLS cert issuance, the hub URL, hub-contact watchdog and Hub TLS Verification pushes (listed as `skipped`), and code updates. See [lm-hub.md](lm-hub.md#synthetic-spokes-have-no-host-of-their-own).
- **Stop feed no longer reports an error.** Stop sends the feeder SIGTERM, which used to kill it outright, so the status showed `stopped · exit -15` in red. The feeder now exits cleanly and the status reads `stopped`, even while a poll of a slow source is still waiting. Once Stop is clicked the feeder starts no new token rotation, and one already in flight is allowed to finish first, so the new tokens are kept (Stop now kills a feeder that is still running after 75 seconds, up from 10). A load test stopped with SIGTERM also exits cleanly.

### Simulations

- **Learned-value approvals are saved again.** Since Aug 6 a stable Learning-lab row's proposal never reached Setup → Simulations → Learned Values, approving one left it in the queue, and rejecting one failed with a server error. All three work again. The first pass after the update proposes each known-good whose proposal was lost, including those whose row no longer learns; one rejected before Aug 6 may be proposed once more, and rejecting it again is final. A proposal now carries the floor learned with its count. When several sites learn the same alert, the tenant keeps the best of them (the highest count, then a learned floor) and proposes it once. See [cs.md](cs.md).

### External DNS

- **The HE.NET re-sync's last run says why it failed.** A scheduled re-sync
  that hit an error was recorded only as `error`. Its status now carries a
  short reason, such as `2 of 5 scopes failed (1 HE.NET login or connection
  failure, 1 credential conflict); 3 records rejected by HE.NET`, shown in
  red after the schedule on a Global Admin's HE.NET status line. Every user
  with HE.NET or DNS access can read that status, so the reason holds only
  counts and failure kinds: it never names a tenant, record, login or vault
  secret, nor quotes an error. The details are in the hub log. See
  [henet.md](henet.md#webui).
- **A re-sync that wrote nothing is no longer recorded `ok`.** When
  dns.he.net refused the login or couldn't be reached, the scheduled re-sync
  counted nothing and recorded the run `ok`; each of that scope's records
  now counts as an error. An exception from the web write used to end the
  run, leaving the other scopes unwritten and the previous run's status in
  place; that scope now fails the same way and the others are still
  written. A record list the spoke failed to return, for example on a
  timeout, was recorded `ok` as if there were no managed records; it is now
  an error.

### WebUI

- **History selectors match on Firewalls and Storage.** On both Firewalls →
  Overview and Storage → Overview the History time selector now sits between
  the summary tiles and the charts, and both open on 24 hours. See
  [opnsense.md](opnsense.md#how-to-use-it).
- **The header search no longer covers Help on a narrow window.** Below
  1280px the search box shrinks to fit, and below 1024px Help and Updates
  show only their icons.

## Week of 2026-11-09

### Firewalls

- **Adding an impairment no longer fails with "rule.interface: Option [] not
  in list."** The Interface field was free text (default `lan`), and the
  firewall refuses a shaper rule on an interface it doesn't have or hasn't
  enabled. Interface is now a dropdown filled from the firewall (description
  and key), and the spoke refuses any other interface before creating
  anything. Editing an impairment whose interface is gone says so. See
  [opnsense](opnsense.md).
- **Impairments can target aliases and devices, and run on a schedule.**
  Pick IP / CIDR (one or more), a firewall alias (optionally one member at a
  time) or LM devices, and choose Always on or Scheduled ("every 3 h for
  15 min", optional start). Several targets rotate, one per window. The list
  shows the schedule, the next on/off time and any switching error, with an
  On/Off button. The firewall spoke switches the rules and turns an
  impairment off if switching fails. See [opnsense](opnsense.md).
- **Impairments work on current OPNsense again.** Adding an impairment
  failed with "10 Gbit/s exceeds the maximum bandwidth of 4 Gbit/s": LM made
  its shaper pipes at 10 Gbit/s, which OPNsense now refuses. Pipes are now
  made at 4 Gbit/s. The form also takes an optional bandwidth limit; a limit
  above 4 Gbit/s is refused with a clear message. See [opnsense](opnsense.md).
- **Both firewalls of an HA pair now work from one spoke.** When two
  firewalls were bound to the same spoke, only the first was configured, and
  every page and change for the second (impairments included) ran on the
  first. Each firewall now gets its own connection and cache on the spoke.
  An impairment is reported as added only when the firewall confirmed it.
  A spoke with no firewall bound no longer borrows another firewall's
  settings; bind each firewall to its spoke in Setup → Firewalls.
  See [opnsense](opnsense.md).

### DHCP

- **Static hosts are reserved automatically.** When a tenant's agent reports
  a static address, or the network sweep sees a host with a live MAC, no
  Kea lease and an address outside the Kea pools, inside a DHCP-enabled
  prefix, LM marks its NetBox IP as a DHCP
  reservation so Kea never hands that address to another client. Existing
  reservations for another MAC, in NetBox or directly in Kea, are never
  overwritten; they are reported as conflicts in the sync status. The netbox
  spoke does the work and records each change with its before and after; a
  pass whose writes fail is rolled back, and so is a tenant's part of a pass
  when that tenant's DHCP sync after it fails. It needs an
  updated netbox spoke (an older one shows "unsupported"). See
  [dhcp.md](dhcp.md#static-hosts-become-reservations).
- **Replaced devices keep their address.** When a device at a static IP is
  replaced and answers with a new MAC, its reservation (and the interface
  MAC in NetBox) now moves to the new MAC once the old MAC has been gone a
  day and the new one has shown for 30 minutes, with every other check kept.
  The System → Sync card lists these, and a **Use new MAC** button on a
  conflict does it at once. Turn the automatic part off with the card's
  checkbox. Needs the updated netbox spoke. See
  [dhcp.md](dhcp.md#static-hosts-become-reservations).

### Firewalls

- **Firewall performance history.** Firewalls → Overview now has History
  charts per firewall: throughput (bits/s), packets/s with interface errors,
  CPU and memory, and pf states, for all interfaces or one picked interface.
  It uses the same time selector as Storage → Overview (1h to 7d or a
  custom range; 24 hours is the default). The firewall spoke keeps 7 days of
  5-minute averages and pushes them to the hub. Needs the opnsense spoke
  update. See [opnsense.md](opnsense.md#how-to-use-it).

### Simulations

- **The Simulation Build Assistant uses the whole screen.** Simulations →
  Assistant now fills the window width and height, with a one-line header.
  Your messages are green bubbles on the right labelled "You"; the
  assistant's replies are white cards on the left labelled "Assistant", with
  headings, lists and code blocks formatted. The agent's working notes
  ("› Reading …") are small grey lines under its turn. The spec panel shows
  each filled field on one line, shortens long text (click to expand), puts
  touch-points in a collapsible list, names the fields still to fill on one
  "Still needed" line, and adds **Clients keep an IP** (Yes / No (by
  design)). The reply box grows as you type. On narrow screens the spec
  panel moves under the chat. See [appbuilder](appbuilder.md).

- **Rogue DNS (static IP + fixed DNS)** (`rogue_dns`) adds a default-off
  wireless Linux/Windows simulation to the catalog, client controls and bucket
  editor, with a DNS server IP field and three timing fields. Clients browse
  for 30 minutes on DHCP, retain the same IP/mask/gateway with fixed DNS for
  60 minutes while browsing, then restore DHCP and repeat. No alert is linked.
  Requires the companion cs#257 client update; deploy the LM catalog first.
  See [cs.md](cs.md#rogue-dns-static-ip--fixed-dns).

- **WWW Discover - Network Diagnostics** (`www_discover`) adds a separate,
  default-off Linux/Windows web-traffic flag to the client controls and bucket
  editor. Each run opens one uniformly random Teams, Zoom, Okta, Google, or
  LinkedIn URL in headless Firefox with a 60-second limit, using its own
  `www_discover_websites.txt`; `www_traffic` and `websites.txt` are unchanged.
  Requires the companion cs client update. See
  [cs.md](cs.md#www-discover---network-diagnostics).

### OS Updates

- **Proxmox hosts drain before a reboot.** Every Proxmox host (clustered or standalone) goes into maintenance mode first: HA guests migrate, other running guests live-migrate where possible and are otherwise shut down gracefully, then the host reboots, maintenance clears, and the guests that were shut down are started again. Hosts reboot one at a time.
- **VMs on storage that cannot snapshot are patched** (with a warning on the run item) instead of being skipped; other snapshot failures still block patching.

### Credential Vault

- **TrueNAS appliance API keys go in the vault.** Add/edit now requires selecting a vault credential when the vault is enabled; the key is no longer stored inline. Existing appliances must be re-saved with a vault credential. See [credential-vault.md](credential-vault.md).

### NetBox auto-rack

- **Devices are racked from their name.** `MIPBE-SSPLM-N31-R45-VPNC1` goes to
  rack N31, RU 45 (`R45R` = rear, `R43H` = half width, lower-numbered device on
  the left). Rack height comes from NetBox or the LLM. Renamed devices are
  renamed in place in NetBox, keeping history, and are racked on the next flush
  (about 15 minutes after the poll). See [netbox.md](netbox.md#auto-rack-rack-placement-from-the-device-name).
- **NetBox → Rack Placement** lists conflicts and devices that cannot be
  racked, with a **Re-check now** button.
- **Duplicate stubs are merged.** Firewall/ARP entries for the same switch are
  folded into the polled device, by shared base MAC or by polling the stub's IP
  and matching the serial.
- **Rack elevation** looks like NetBox: U rails, device blocks with front-panel
  artwork per device type, half-width chassis side by side, longer names, and
  loads faster (parallel reads). **Click a device** for everything the search
  shows, now including Zabbix monitoring and DNS records.

### Network devices

- New **IPMI** object type (iLO/iDRAC/BMC) with vendor-neutral identity
  (serial, host model, MAC); a server's iLO is linked to it by serial.
- Switch and gateway serials/MACs/models are read at poll time on CX, AOS-S and
  gateways.

### Storage (TrueNAS)

- Storage opens on an **Overview** tab and loads from the background cache.
- **Performance** tab charts IOPS and throughput over a selectable range
  (7 days of averages are stored); down interfaces are hidden.
- TrueNAS appliances can use an API-key user; SNMP hosts are typed `truenas` for
  Zabbix.

### Monitoring

- Only SNMP-verified devices are sent to Zabbix, with an IPAM **Monitor**
  toggle; seen hosts join Zabbix under their sysName.

## Week of 2026-11-02

### DNS

- **DNS Overview loads fast after a quiet spell.** Each resolver now reads its
  query log every 5 minutes, not only when someone opens the page, so the first
  view no longer parses hours of log (one took 14.8s). See [dns.md](dns.md).
- **Time-window picker on the DNS Overview.** Choose the last hour, day,
  week or month. Total Queries, Cache Hit Ratio, Recursive Replies, Queries by
  Type and Queries by Destination now cover that window instead of counting
  since Unbound started. Each resolver snapshots its counters every 5 minutes,
  so longer windows fill in as history builds up (the page says so).
- **Cache Hit Ratio and Recursive Replies are back** when a tenant is
  selected, for Global Admins and for tenants with their own resolver. On the
  shared resolver they still show "—" for tenant users.

### Users & access

- **Impersonate user.** Settings → Users has an **Impersonate** button
  (Global Admin only) on every other user, and the header tenant picker has a
  small **i** beside each tenant's star that lists that tenant's users to
  impersonate. LabManager reloads with that user's
  permissions and tenants, and an amber banner at the top shows who you are
  acting as, with **Stop impersonating** to switch back. While impersonating
  you cannot mint or revoke API tokens or start a second impersonation. Every
  start and stop is logged on the hub as `IMPERSONATION start/stop` with the
  admin, the target, and the source IP.
- **Login password encrypted in the browser.** The local login page encrypts
  the password with a one-time hub key (RSA-OAEP), so it no longer shows in
  clear text in the browser's developer tools. A captured request cannot be
  replayed. Scripts that send a plain password still work.

## Week of 2026-10-26

### Users & access

- **Read-only accounts.** Settings → Users → Add/Edit User has a **Read-only**
  checkbox (Global Admin only). The account sees everything its role allows,
  but the hub rejects every change it attempts (403, logged as
  `[read-only] BLOCKED`); it can still log out. Meant for automated UI checks
  such as the AB walker — see [security-pentest.md](security-pentest.md).

### Hypervisors (Proxmox)

- **Snapshot schedules.** Hypervisors → Settings → Snapshot schedules snapshots
  picked VMs, or every VM with a Proxmox tag or in a pool, every N hours and
  keeps the last K. Schedules are per tenant (only that tenant's VMs), and a
  VM's detail view has a **🕒 Schedule…** button to see or set its schedule.
  See [pxmx.md](pxmx.md#how-to-use-it).

### OS Updates

- **Snapshot before patching.** A node that runs in a Proxmox VM is snapshotted
  (`lm-prepatch-*`, keep 2 by default) right before it is patched — manual
  deploys and auto-patch. If the snapshot fails the node is not patched. Each
  node shows the VM it was matched to; Proxmox hosts themselves are bare metal
  and are patched without one. Toggle it under "Snapshot VMs before patching".

### Firewalls (OPNsense)

- **Network impairment tab.** Firewalls → Impairment adds latency and packet
  loss for a host or subnet (both directions, download or upload), driven
  entirely from LM. Needs the `os-netimpair` plugin on the firewall. See
  [opnsense.md](opnsense.md).

### Credential Vault

- **"API key + secret" secret type.** Store a firewall's API key and secret (e.g.
  OPNsense) as one vault secret and pick it when adding the firewall.
- **Vault on → no inline secrets in device forms.** With the vault enabled, the
  Add/Edit device and instance forms hide the secret fields (they were rejected
  anyway), and a firewall must use a Credential Vault credential. The Firewall
  module's Edit button now opens the same form. See
  [credential-vault.md](credential-vault.md#how-modules-consume-vault-secrets).

### Cert Monitor

- **Hourly checks near expiry.** While a cert expires within 24 hours (or has expired),
  Cert Monitor re-checks every hour instead of daily, so a renewal stops the reminder
  emails within the hour. See [cert-monitor.md](cert-monitor.md#schedule--storage).
- **Mist / Central host list updates itself daily.** The built-in endpoint list is
  refreshed from Juniper's and Aruba's published endpoint pages before each daily check —
  new endpoints (e.g. Mist SRX log terminators, RadSec, New Central GB1/IN1/CN1) are added
  and retired ones dropped; a bad read keeps the last list. See
  [cert-monitor.md](cert-monitor.md#built-in-host-list-auto-update).
- **Reminder emails with an escalation ladder.** A Cert Monitor alert rule can now repeat
  its email every N hours while a cert stays bad, and an expiring rule can escalate, e.g.
  one email at 30 days, daily inside 7 days, every 6 hours once expired. Set it in
  Reports → Alert Rules. See [cert-monitor.md](cert-monitor.md#alert-rules).

### NetBox

- **Network-device pushes to NetBox work for tenant-attributed devices again.** POLL NOW /
  nw device pushes failed with "failed to list NetBox devices: 400 Bad Request" (wrong tenant
  filter). See [netbox.md](netbox.md).
- **VM primary IPs move off stale owners.** The hypervisor VM sync no longer fails with
  "Cannot reassign IP address while it is designated as the primary IP for the parent
  object": the IP's old device (or stale duplicate VM) gives it up as primary first, and gets it
  back if the move still fails.
- **Quieter hub log for a tenant with sim quotas but no client-sim spoke bound.** The 45s
  re-push now logs once when it stalls plus the hourly "STILL stale" warning, not two INFO lines
  every tick.

### WebUI

- **Choose your default tenant.** In the header tenant picker, click **☆** next to a tenant
  to open LM on it every time you sign in (saved on your user, so it follows you to any
  browser); click **★** to clear it. See [webui.md](webui.md#how-to-use-it).

### DNS

- **Editable DNS overrides with comments.** DNS → **Overrides** → *Assigned clients* now has
  an edit icon to change an applied override's IP/subnet, profile, label or comment, and every
  override can carry a one-line **Comment** documenting why it exists.
  See [dns.md](dns.md#per-client-override-profiles).
- **DNS override Live check.** DNS → **Overrides** now proves overrides work: per DNS server,
  whether each profile is loaded in the running Unbound; per assigned client, how many queries
  were answered from its override; and the recent override answers. Resolvers turn on
  Unbound `log-local-actions` with the next push (automatic, reload only).
  See [dns.md](dns.md#per-client-override-profiles).

## Week of 2026-10-19

### Simulations
- **Clearer 802.1X configuration.** Simulation Engine editor exposes 802.1X
  EAP method, TLS cert paths and PSK/1X SSID select. PEAP password fallback
  and Linux-only TLS support are explicit; saved custom values are preserved.
  No client behavior or config defaults change. See [cs.md](cs.md).
- **Client offline windows (`client_offline`).** Linux and Windows clients can
  now pause their simulation interface at the end of each cycle for a random,
  configurable duration (default 60–240 minutes). Off by default, enabled per
  bucket or user, with minute-range fields in the Simulation config editor.
  Management adapters carrying `169.253.*` addresses are never disabled, and
  the agent/spoke API stays online. Requires the companion cs client update;
  keep legacy `allow_offline=no`. See
  [cs.md](cs.md#client-offline-window-client_offline).
- **Site Pool clients join the plain SSID.** Clients on a pxmx server
  assigned to a Site Pool (RF chamber) now connect to the SSID exactly as
  configured (e.g. `CC-BRIDGE`), not `<site>-<ssid>`. The site prefix applies
  only to Tenant-Wide Pool servers. See [cs.md](cs.md).
- **Server to Site Assignments are tenant-scoped, with Delete.** A pxmx
  server that moved to another tenant no longer shows up here. Offline rows
  have a **Delete** button that removes the stale record and its site
  assignment from every Client-Sim spoke in the tenant. See [cs.md](cs.md).
- **Interactive Simulation Build Assistant.** Simulations → Assistant is now a
  live AppBuilder agent session. It reads the real cs and lm code, rules and the
  add-simulation recipe, streams what it's reading, asks one question at a time
  (with suggested answers), and fills in a Spec panel. Once the spec is ready, a
  Global Admin can **Submit to AppBuilder**, which files one issue per repo and
  builds it as PRs to dev. Build status shows in the chat. Other users file it
  for admin approval. It only makes cosmetic Simulations UI changes, or
  creates, changes, removes or explains simulations. UI changes (move or add a
  button) only touch the two `sim-views.js` copies and are never duplicated.
  Removing a simulation needs confirmation and a reason. Changing
  a working simulation needs confirmation and a code check, and it steers you to
  duplicating it first. Each in-place change is built as its own PR, recorded
  with the requesting LM user. See [cs.md](cs.md#how-to-use-it) and
  [appbuilder.md](appbuilder.md#how-it-works).

### Hub
- **Guided Bug/Feature Requests.** The footer **🐞 Bug/Feature Request**
  button now opens a chat with an AppBuilder assistant, the same kind as the
  Simulation Build Assistant. It asks one question at a time (with suggested
  answers) and reads the code to point at the likely area. **File report**
  stays disabled until everything needed is captured. For a bug that means
  steps, expected vs actual, how often, environment, severity and evidence.
  For a feature it means the problem, who uses it, desired behaviour,
  acceptance criteria, scope and priority. The report goes through the usual
  pipeline: bugs are fixed by AppBuilder, and features wait for admin approval.
  The assistant never changes code. **Use quick form** keeps the old one-step
  form, which is also used when AppBuilder can't run the assistant. See
  [appbuilder.md](appbuilder.md#how-it-works).
- **Cert Expiry Monitor (Global Admin, opt-in).** Enable it in System → General
  and a **Cert Monitor** menu item appears. It checks the TLS certificates of
  every public Aruba Central / GreenLake and Juniper Mist endpoint once a day
  and lists them red (under 30 days), yellow (under 90 days) or green. Results
  are saved as JSON on the hub. See [cert-monitor.md](cert-monitor.md).
- **Cert Monitor alert rules.** Reports → **Alert Rules** now offers Cert
  Expiry Monitor sources in **+ Add alert** (Global Admin, while the monitor is
  enabled). Reports has one Alert Rules tile for every alert kind,
  like the Simulation realtime alerts. Each rule watches one trigger (cert
  expiring in under N days, endpoint unreachable, or cert untrusted), optionally
  limited to some services. It emails once when hosts breach and once when they
  recover, as a human-readable email or raw JSON, and has a **Test** button.
  See [cert-monitor.md](cert-monitor.md#alert-rules).
- **Auto-updates no longer restart the hub while you're logged in.**
  - Scripted deploys through `/admin/ops/self-update` now follow the
    maintenance window (pass `{"force": true}` to override).
  - The window hour now uses a configurable timezone: System → General →
    Update / Maintenance Window → *Window timezone*, or `LM_UPDATE_GATE_TZ`.
    Without it, "02:00" meant 02:00 UTC.
  - The panel offers *When no users online — else the daily window*, and it now
    has its Save button.

## Week of 2026-10-05

### Console
- **Direct Port Access over SSH, with a live on/off knob.** Console → 🔌 Direct Port
  Access enables per-port SSH listeners on a console server, using a password and/or
  keys. The setting persists across agent restarts. Each port row now shows a
  click-to-copy `🔐 DPA host:port` badge, and the port's ⚙ Settings let you pin a
  specific SSH/telnet port. See [console.md](console.md#direct-port-access-dpa--enabling-it).

### DHCP / DNS / multitenancy
- **Per-client DNS override profiles.** DNS → **Overrides** lets a Global Admin define
  named profiles (e.g. `PAVO-DEVICE`) of custom answers and blocked names; apply one to a
  device from **Records → Override…** (tenant Admins: their own devices) or to a subnet,
  and only those clients get the custom answers. See [dns.md](dns.md#per-client-override-profiles).
- **Tenant isolation for DHCP/DNS.** A tenant-bound DHCP/DNS spoke now only gets
  its own tenant's NetBox subnets/records; the shared tenant is the only one
  that may manage other tenants, and automatic instance failover never moves a
  role onto another tenant's agent. See [dhcp.md](dhcp.md#tenant-isolation).
- **No more phantom DHCP role on simulation hosts.** The `dhcp-server` badge
  only appears for LM-installed Kea, not the distro Kea a simulation host
  runs for its sim; unloading the role there leaves that Kea running. See [dhcp.md](dhcp.md#troubleshooting--common-questions).

## Week of 2026-09-15

### DNS
- **The "Statistics" tab is now "Overview" and is the module's first tab.** Same
  tiles and per-query-type breakdown (`GET /api/dns/stats`), just renamed and
  moved to the front so it opens by default. See [dns.md](dns.md).

### Console
- **Direct Port Access (DPA) can now be enabled from the UI.** DPA (per-port
  telnet terminal server) is off by default and previously had no operator
  toggle, so the Console page never showed a DPA endpoint. The **Load Role**
  modal now has an "Enable Direct Port Access" control (safe `127.0.0.1`
  default, allow-list + warning when widened). See
  [console.md](console.md#direct-port-access-dpa--enabling-it) and
  [console-role-design.md](console-role-design.md).
- **Auto-identify now tries every stored credential set** and skips a net-new
  forced password-change during the identify probe, so a switch on defaults is
  profiled instead of stalling. See [console.md](console.md).
- **The Console page no longer slows down with console count.** Per-spoke
  serial-port polls (cold-start fetch, credential seeding, background refresh)
  now run concurrently instead of in a serial loop. See [console.md](console.md).

### IPAM (NetBox)
- **Tenant users see the prefixes assigned to their tenant.** The subnet list is
  now filtered server-side by the *selected* tenant, so a non-admin no longer
  gets an empty list where the Global Admin saw the rows. See
  [netbox.md](netbox.md).

### Global Admin / multitenancy
- **The ADMIN (default) tenant no longer accumulates every tenant's stats.** As a
  Global Admin, selecting the default tenant shows only that tenant's resources
  (Hypervisors, Network Devices, credential sets) — pick a specific tenant to
  see its totals. See [lm-hub.md](lm-hub.md).

### Updates
- **Self-update shows "update in progress" instead of a false failure.** The hub
  no longer queries a spoke/agent while it is updating, so a mid-update poll can
  no longer surface a misleading "Timed out waiting for spoke response". See
  [lm-hub.md](lm-hub.md).

### Test Data Feed
- **The feed now carries the whole fleet's telemetry, not just top-level rows.**
  A spoke's VMs and USB devices usually ride *nested per host* under the frame's
  `proxmox_hosts` (the same lists the Simulations views render); the export only
  read the top level, so a host-structured fleet reached the target with **zero
  VMs and no USB devices**. The snapshot now harvests every host's VMs and USB
  devices — attributed to their spoke and stamped with the host node — and stops
  hard-coding the USB list empty, so the target mirrors the full fleet.
  See the "Test Data Feed" section of [lm-hub.md](lm-hub.md#test-data-feed).
- **A momentarily-empty source no longer kills the feed.** If the source has no
  spokes when the feed comes up — e.g. no simulations are producing telemetry
  yet, which a restart's auto-resume can easily race — the feeder now waits and
  keeps polling instead of exiting, so the feed goes live on its own the moment
  the source has data (a bounded `--duration` run still gives up when it lapses).
  See the "Test Data Feed" section of [lm-hub.md](lm-hub.md#test-data-feed).
- **The feed now picks up spokes that appear after it started.** Previously the
  feeder fixed its spoke set at the first poll, so a production spoke that began
  reporting mid-run (e.g. a simulation that was idle at feed start) never showed
  up on the target until an operator restarted the feed. Each re-poll now *adds*
  any new source spokes, so the target keeps converging on the full source fleet
  on its own. It stays **add-only**: a spoke that disappears from the source is
  left running so its registration on the target is never orphaned.
- **A feed now survives hub restarts.** An enabled feed auto-resumes when the hub
  self-updates or restarts (it used to silently stay stopped), and the feeder
  persists its own token rotations back to config — so an expired access token no
  longer leaves a spent refresh token behind for the next restart to trip on and
  get the whole token family revoked. See the "Test Data Feed" section of
  [lm-hub.md](lm-hub.md#test-data-feed).
- **New Setup → Test Data Feed panel (Global-Admin only).** One hub *publishes* a
  snapshot of its fleet; another *subscribes* and replays it as synthetic spokes,
  so a dev/qa hub carries a realistic fleet without duplicate hardware. Publishing
  is off by default and every change is audit-logged. See the "Test Data Feed"
  section of [lm-hub.md](lm-hub.md#test-data-feed).
