# Lab Manager Architecture Overview

## 1. System Concept
Lab Manager (LM) is a centralized orchestration and management platform designed to control a fleet of network and security appliances (Spokes) from a single administrative Hub. It provides a unified WebUI for managing disparate systems like OPNsense firewalls, Proxmox hypervisors, and ClearPass (CPPM) NAC.

## 2. Hub-Spoke Model
The system follows a **Hub-and-Spoke architecture**:

- **The Hub**: Acts as the central control plane. It manages state, authentication, configuration, and API requests. It provides a REST API for the WebUI and a WebSocket server for the Spokes.
- **The Spokes**: Lightweight agents installed on target appliances. They handle the actual execution of commands (e.g., calling a local REST API on OPNsense) and report telemetry back to the Hub.

### Communication Flow
1. **Control Plane (WebSocket)**: The primary communication channel. All commands from the Hub to Spokes, and all heartbeats/results from Spokes to Hub, travel over an encrypted and signed WebSocket connection.
2. **Management Plane (REST API)**: The WebUI communicates with the Hub via a FastAPI-based REST server.
3. **Data Plane**: The Spokes interact with the underlying appliance's native API (e.g., OPNsense REST API) to perform actual configuration changes.

## 3. Component Breakdown

### Hub Core
- **`LabManagerHub`**: The main orchestrator managing active connections and the message loop.
- **`Mailbox`**: Implements an asynchronous queue for outgoing messages to spokes, including a retry mechanism for offline nodes.
- **`StateManager`**: Handles persistence of global configuration, tenant settings, and module registration.
- **`KeyManager`**: Manages the cryptographic lifecycle, including root secrets and per-spoke session keys.

### Spoke Core
- **`BaseControlPlane`**: The shared logic for all spokes, handling the WebSocket handshake, mutual authentication, and command routing.
- **`BaseSpoke`**: The abstract base class that defines how a module handles commands.
- **`MessageSigner`**: Ensures every message is signed using HMAC-SHA256 for authenticity and integrity.

## 4. Design Goals
- **Resilience**: Using a "Restore-Safe" key rotation window, ensuring that VM snapshots don't break authentication.
- **Security**: Mutual authentication prevents rogue hubs or spokes from joining the control plane.
- **Scalability**: The Generic Agent bootstrapper allows for rapid deployment of new modules without manual configuration of every instance.
- **Tenant Isolation**: Support for multi-tenancy via the `StateManager`, allowing different users to manage distinct sets of resources.
