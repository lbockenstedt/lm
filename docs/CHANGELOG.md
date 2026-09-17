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
