---
summary: "Fleet automated QA auditor spoke master documentation. Repo: qa."
keywords: [qa, testing, automation, spoke, integration, verification]
---

# QA Spoke — Fleet Automated Quality Assurance & Testing

The **QA spoke** (`module_type = "qa"`) provides autonomous integration testing across the entire Lab Manager fleet.

- **Repo:** `github.com/lbockenstedt/qa`
- **Spoke Type:** `module_type = "qa"`
- **Default Port:** `8080` (FastAPI REST service & WebSocket log streaming)
- **Canonical Docs:** [`lm/docs/qa.md`](qa.md)

## Architecture & Responsibilities

The QA spoke acts as an independent auditor that validates that spokes, hub REST routes, WebSocket connections, and external systems are operating correctly according to contract.

### Test Tiers
1. **Tier 1 (Connectivity & Security):** Hub status, WebSocket handshake, and HMAC signature rejection.
2. **Tier 2 (Basic Fleet Protocol):** Spoke version discovery and configuration update (`UPDATE_CONFIG`) round-trip.
3. **Tier 3 (Spoke Capabilities):** OPNsense firewall rule management, NetBox VM documentation, ClearPass device queries, Client Simulator test scenarios, and Proxmox VM lifecycle.

### Key Commands
- `QA_RUN_TESTS`: Trigger execution of the test suite (supports optional `module` filter).
- `QA_GET_LAST_RESULTS`: Retrieve cached test run results.
