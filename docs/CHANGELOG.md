---
summary: "Rolling summary of recent user-facing changes to the LM hub and its modules, newest first, each linking to the module doc that covers it in full."
keywords: [changelog, whats-new, release-notes, recent-changes, lm]
---

# What's new

A rolling, human-readable summary of recent **user-facing** changes, newest
first. This is a pointer index, not the source of truth — each entry links to
the module doc that describes the behaviour in full. Internal refactors and
CI/tooling changes are omitted unless they change what an operator sees.

## Week of 2026-10-26

### Cert Monitor

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
