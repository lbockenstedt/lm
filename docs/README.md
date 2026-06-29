# Lab Manager Documentation

Welcome to the Lab Manager documentation suite. This directory contains all the technical and operational guides for the system.

## 📖 Table of Contents

### Core Guides
- [Architecture Overview](architecture.md) - High-level design and Hub-Spoke communication.
- [Installation Guide](installation.md) - How to deploy the Hub and Spokes.
- [Operations & Runbook](operations.md) - Root helpers, sudoers, state inventory, recovery runbooks.
- [Security Guide](security.md) - Mutual authentication, encryption, and key rotation.
- [API Reference](api.md) - Detailed documentation of the REST API.

### Module Guides
- [Core (Hub)](modules/core.md) - The Hub backend: control plane, state, auth, cs relay.
- [Agent](modules/agent.md) - The LM host agent spoke.
- [OPNsense](modules/opnsense.md) - Firewall and interface management.
- [Proxmox](modules/pxmx.md) - VM inventory and "Stitched View".
- [NetBox](modules/netbox.md) - IPAM spoke + IPAM→ClearPass sync source.
- [CPPM](modules/cppm.md) - Network Access Control integration.
- [LDAP](modules/ldap.md) - Directory services management.
- [Client Simulator](modules/client-sim.md) - Traffic generation and validation.
- [DHCP](modules/dhcp.md) - Kea DHCP4 management.
- [DNS](modules/dns.md) - Unbound DNS record management.
- [QA](modules/qa.md) - Mock-spoke QA harness.

---
*Last Updated: 2026-06-28*
