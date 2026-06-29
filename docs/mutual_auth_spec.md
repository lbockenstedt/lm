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
2. **Deterministic Serialization**: Before signing, the challenge payload is serialized to a canonical JSON string to ensure consistency across different platforms and languages. This is achieved using `json.dumps` with `sort_keys=True` and `separators=(',', ':')`.
3. **Signing**: The Hub signs this canonical string using its persistent `hub_secret` (stored in `hub_secret.json`) using HMAC-SHA256.
4. **Response**: The Hub sends a `HUB_VERIFIED` message:
   ```json
   {
     "status": "HUB_VERIFIED",
     "challenge": "<random_challenge>",
     "signature": "<hmac_signature>"
   }
   ```

### Phase 3: Spoke $\rightarrow$ Hub (Verification)
The Spoke verifies the Hub's identity.
1. **Signature Check**: The Spoke uses its local copy of the `hub_secret` to compute the expected HMAC of the challenge. The Spoke must apply the same deterministic serialization (`sort_keys=True`, `separators=(',', ':')`) to the challenge payload before hashing.
2. **Criticality of Serialization**: Deterministic serialization is critical to prevent signature mismatches. Without it, different environments might introduce varying whitespace or key orders in the JSON representation, resulting in different HMAC signatures for the same logical data.
3. **Validation**: If the computed signature matches the provided signature, the Hub is verified.
4. **Confirmation**: The Spoke sends a `HUB_OK` message to signal the completion of the mutual handshake.

## 🏗️ Multi-Module Spoke Architecture

To support "multi-module" spokes (where one process hosts multiple specialized modules), the `ControlPlane` now implements a registry pattern.

### The Registry Pattern
*   **`BaseControlPlane`**: Provides the core WebSocket logic, mutual authentication, and a `modules` registry (`Dict[str, BaseSpoke]`).
*   **Module Registration**: Each specific module (e.g., `pxmx`, `opn`) implements the `BaseSpoke` interface and is registered with a unique name.
*   **Command Routing**: When the Hub sends a command, the `ControlPlane` iterates through registered modules. It routes the command to the first module that acknowledges the `command_type` or matches the module name prefix.

## 🗝️ Key Management and Trust Model
The system employs a **symmetric trust model**, where both the Hub and the Spoke share identical secret keys for specific verification paths. Trust is not hierarchical but mutual; neither party is trusted until they have proven possession of the shared secret.

*   **Hub Secret (Root Secret)**: Generated on Hub startup and persisted (encrypted) to `hub_secret.json`. Distributed to spokes during installation. Rotated every **30 days**; the Hub and Spokes maintain a validity window of the **last 3 root secrets** so a restored spoke can still verify the Hub after a rotation. This key allows the Spoke to verify the Hub. See [security.md](security.md) §2 and [key_rotation.md](key_rotation.md) §2 for the full rotation flow.
*   **Spoke Secrets (Session Keys)**: Managed by the Hub, rotated every **30 days**; the Hub recognizes a **2-key window** (Current + Previous) so a spoke restored from a snapshot can still authenticate and then be updated to the current key. This key allows the Hub to verify the Spoke. See [key_rotation.md](key_rotation.md) §2 "Spoke Key Rotation" for the `SPOKE_UPDATE_SESSION_KEY` distribution flow.
