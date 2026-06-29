# Security and Key Rotation Architecture

## Overview
The Lab Manager (LM) employs a multi-tiered authentication and encryption system to ensure secure communication between the Hub and its remote Spokes. To mitigate the risk of long-term key compromise and to support system resilience (e.g., recovery from VM snapshots), the system implements a periodic, automated key rotation mechanism.

---

## 1. Cryptographic Foundations

### Hub Root Secret
The **Hub Root Secret** is a high-entropy, 64-character token that defines the Hub's identity. It is used to sign a "challenge" during the initial mutual authentication handshake. This prevents "Rogue Hub" attacks where a malicious server attempts to impersonate the Lab Manager Hub.

### Spoke Session Keys (`ManagedKey`)
Every Spoke has a unique **Session Key** used for HMAC-SHA256 signing of every message exchanged. This ensures:
- **Authenticity**: Messages are guaranteed to come from the identified Spoke.
- **Integrity**: Messages cannot be tampered with in transit.

---

## 2. The Rotation Mechanism

### Spoke Key Rotation (Session Keys)
Session keys are rotated every **30 days**. 

#### The Validity Window (Current + Previous)
To avoid disconnecting spokes during a rotation or breaking authentication after a system restore, the Hub maintains a **validity window of two keys**:
1. **Current Key**: The most recently generated secret. Used for all new signatures.
2. **Previous Key**: The secret immediately preceding the current one.

**Why a window?**
If a Spoke is restored from a backup taken 5 days ago, its local secret will be the "Previous Key" from the Hub's perspective. By allowing the previous key to remain valid, the Spoke can still authenticate and then be seamlessly updated to the current key by the Hub.

#### Rotation Flow
1. **Detection**: The Hub's `run_key_rotation_loop` identifies spokes whose keys are older than 30 days.
2. **Generation**: The Hub generates a new `ManagedKey` and moves the existing current key into the history slot.
3. **Distribution**: The Hub sends a `SPOKE_UPDATE_SESSION_KEY` message over the WebSocket.
4. **Update**: The Spoke updates its local `MessageSigner` with the new secret.

### Hub Root Secret Rotation
The Hub root secret is also rotated every **30 days**.

#### The Validity Window (3-Key Window)
The Hub maintains a window of the **last 3 root secrets**. 

#### Rotation Flow
1. **Generation**: The Hub generates a new root secret and prepends it to the `hub_secrets` list.
2. **Persistence**: The list (up to 3 entries) is encrypted and saved to `hub_secret.json`.
3. **Distribution**: The Hub pushes the new root secret to all approved spokes using the `SPOKE_SET_HUB_SECRET` command.
4. **Verification**: During the mutual auth handshake, the Spoke iterates through its known list of hub secrets. If any of them produce a valid signature for the Hub's challenge, the Hub's identity is verified.

---

## 3. Implementation Details

### Key Components
- **`KeyManager` (`core/src/security/key_manager.py`)**: The authoritative manager of all secrets. Handles rotation logic, window truncation, and encrypted persistence.
- **`BaseControlPlane` (`core/src/messaging/control_plane.py`)**: The spoke-side logic that manages the `hub_secrets` list and handles session key updates.
- **`LabManagerHub` (`core/src/main.py`)**: The orchestrator that runs the hourly rotation loop and triggers the push of new keys.

### Summary Table: Rotation Policies

| Secret Type | Rotation Interval | Window Size | Effect of Rotation |
| :--- | :--- | :--- | :--- |
| **Session Key** | 30 Days | 2 (Cur + 1 Prev) | Spoke receives `SPOKE_UPDATE_SESSION_KEY` |
| **Hub Root Secret** | 30 Days | 3 (Cur + 2 Prev) | All spokes receive `SPOKE_SET_HUB_SECRET` |
