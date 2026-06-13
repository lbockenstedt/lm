# Security Architecture

Lab Manager implements a "Zero Trust" approach to Hub-Spoke communication, ensuring that neither the Hub nor the Spokes can be impersonated.

## 1. Mutual Authentication
The system employs a two-way handshake to verify identities before any management traffic is exchanged.

### Spoke $\rightarrow$ Hub Verification
When a spoke connects, it sends its `spoke_id` and `session_secret`.
1. The Hub looks up the `spoke_id` in its `KeyManager`.
2. It verifies the secret against the current session key or the previous key (rotation window).
3. If valid, the Hub accepts the connection.

### Hub $\rightarrow$ Spoke Verification
To prevent "Rogue Hub" attacks, the spoke must verify the Hub's identity:
1. The Hub sends a random `challenge` and a `signature` of that challenge created with the **Hub Root Secret**.
2. The Spoke maintains a list of valid Hub Root Secrets. It iterates through this list, calculating the HMAC-SHA256 of the challenge for each.
3. If any signature matches, the Hub's identity is confirmed.

## 2. Key Rotation Policy
To mitigate the risk of key compromise and support system restores (VM snapshots), all secrets are rotated periodically.

### Session Key Rotation (Spoke-specific)
- **Interval**: 30 Days.
- **Mechanism**: The Hub generates a new `ManagedKey` and pushes it via the `SPOKE_UPDATE_SESSION_KEY` command.
- **Window**: The Hub recognizes the **Current Key** and the **Previous Key**. This allows a restored VM to authenticate using its old key and then receive the latest update.

### Hub Root Secret Rotation (Global)
- **Interval**: 30 Days.
- **Mechanism**: The Hub generates a new root secret and pushes it to all approved spokes via `SPOKE_SET_HUB_SECRET`.
- **Window**: The Hub and Spokes maintain a window of the **last 3 root secrets**.

## 3. Message Integrity and Authenticity
Every message sent over the WebSocket is signed using HMAC-SHA256.

### Signing Process
1. The sender constructs the message (Header + Payload).
2. The data is canonically serialized (sorted keys, no spaces) to ensure deterministic results.
3. The result is signed using the current session secret.
4. The signature is appended to the message.

### Verification Process
The receiver:
1. Extracts the signature.
2. Re-serializes the remaining data.
3. Calculates the expected signature using the known secret for that spoke.
4. Compares the signatures using `hmac.compare_digest` to prevent timing attacks.

## 4. Persistence
Secrets are not stored in plain text. The `StateManager` uses an encryption layer (`hub_encryption`) to encrypt the `keys.json` and `hub_secret.json` files on disk.
