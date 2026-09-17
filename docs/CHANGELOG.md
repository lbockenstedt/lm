---
summary: "Rolling summary of recent user-facing changes to the LM hub and its modules, newest first, each linking to the module doc that covers it in full."
keywords: [changelog, whats-new, release-notes, recent-changes, lm]
---

# What's new

A rolling, human-readable summary of recent **user-facing** changes, newest
first. This is a pointer index, not the source of truth — each entry links to
the module doc that describes the behaviour in full. Internal refactors and
CI/tooling changes are omitted unless they change what an operator sees.

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
- **New Setup → Test Data Feed panel (Global-Admin only).** One hub *publishes* a
  snapshot of its fleet; another *subscribes* and replays it as synthetic spokes,
  so a dev/qa hub carries a realistic fleet without duplicate hardware. Publishing
  is off by default and every change is audit-logged. See the "Test Data Feed"
  section of [lm-hub.md](lm-hub.md#test-data-feed).
