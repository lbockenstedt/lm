# 🛡️ Mutual Authentication Technical Specification

## Overview
The Lab Manager (LM) uses a mutual authentication handshake to ensure that both the Hub and the Spoke (Module) verify each other's identities before any configuration or commands are exchanged. This prevents unauthorized spokes from connecting to the Hub and unauthorized "fake hubs" from hijacking spokes.

## ⚙️ Authentication Flow

### Phase 1: Spoke $\rightarrow$ Hub (Standard Auth)
The Spoke initiates the connection to the Hub via WebSocket.
1. **Request**: The Spoke sends a JSON payload containing its `spoke_id` and the shared `secret` (First Secret or Rotated Key).
2. **Verification**: The Hub's `KeyManager` validates the secret. If invalid, the connection is immediately terminated.

### Phase 2: Hub $\rightarrow$ Spoke (Identity Proof)
To prove it is the legitimate Hub, the Hub must respond to the Spoke.
1. **Challenge Generation**: The Hub generates a cryptographically secure random 32-byte challenge.
2. **Signing**: The Hub signs this challenge using its persistent `hub_secret` (stored in `hub_secret.json`) using HMAC-SHA256.
3. **Response**: The Hub sends a `HUB_VERIFIED` message:
   ```json
   {
     "status": "HUB_VERIFIED",
     "challenge": "<random_challenge>",
     "signature": "<hmac_signature>"
   }
   ```

### Phase 3: Spoke $\rightarrow$ Hub (Verification)
The Spoke verifies the Hub's identity.
1. **Signature Check**: The Spoke uses its local copy of the `hub_secret` to compute the expected HMAC of the challenge.
2. **Validation**: If the computed signature matches the provided signature, the Hub is verified.
3. **Confirmation**: The Spoke sends a `HUB_OK` message to signal the completion of the mutual handshake.

## 🏗️ Multi-Module Spoke Architecture

To support "multi-module" spokes (where one process hosts multiple specialized modules), the `ControlPlane` now implements a registry pattern.

### The Registry Pattern
*   **`BaseControlPlane`**: Provides the core WebSocket logic, mutual authentication, and a `modules` registry (`Dict[str, BaseSpoke]`).
*   **Module Registration**: Each specific module (e.g., `pxmx`, `opn`) implements the `BaseSpoke` interface and is registered with a unique name.
*   **Command Routing**: When the Hub sends a command, the `ControlPlane` iterates through registered modules. It routes the command to the first module that acknowledges the `command_type` or matches the module name prefix.

## 🗝️ Key Management
*   **Hub Secret**: Generated once on Hub startup and persisted to `hub_secret.json`. Distributed to spokes during installation.
*   **Spoke Secrets**: Managed by the Hub, rotated every 7 days, with 4 keys of history maintained for recovery.
