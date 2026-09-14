---
summary: "How long an agent may be offline before it can no longer reconnect on its own, why deleting an offline spoke/agent does not fix it, and the recovery runbook."
keywords: [offline, agent, spoke, key, rotation, hub_secret, session_key, reconnect, lockout, delete, decommission, re-onboard, zero-touch, mutual auth, hub identity, recovery]
---

# Agent offline limits, key rotation, and delete semantics

**Read this before deleting an agent that is showing offline.** Deleting an
offline agent does not bring it back and can make recovery harder. The reason is
not obvious from the WebUI, which shows only "offline".

## The two secrets (they are not the same thing)

Almost every confusing symptom here comes from conflating them.

| | **Hub root secret** | **Per-spoke session key** |
| :-- | :-- | :-- |
| Proves | the **hub's** identity **to the spoke** | the **spoke's** identity **to the hub** |
| Stored on hub | `hub_secrets` list, newest first | `keys[spoke_id]` + `history[spoke_id]` |
| Retained | last **3** (`KeyManager.rotate_hub_secret`) | current + **3** previous (`rotate_key`) |
| Rotation | every 30 days, **fanned out to every approved spoke** | every 30 days, **only for spokes currently connected** |
| Delivered by | `SPOKE_SET_HUB_SECRET` | `SPOKE_UPDATE_SESSION_KEY` |
| If the spoke's copy is stale | **the spoke refuses the hub** | the hub closes 1008; the spoke self-heals to zero-touch |

The asymmetry in the last row is the whole story. A stale *session key* is a
recoverable, self-healing condition. A stale *hub root secret* is the spoke
deciding the hub might be an impostor — and a spoke that distrusts the hub will
not accept anything the hub sends, including a fix.

## How long may an agent be offline?

### The session key is not the limit

Two reasons a merely-old session key never locks an agent out:

* `KeyManager.get_valid_key` compares secrets and **never checks `expires_at`**.
  Age alone never rejects a key.
* The rotation loop only rotates spokes in `active_connections`, so an offline
  agent's key is not rotated out from under it while it is away.

An agent that has been powered off for a year still holds a session key the hub
will accept. This is deliberate.

### The hub root secret is the limit

The hub rotates its root every 30 days and keeps the newest 3. A returning agent
can verify the hub only if the root **it** holds is still in that window.

Walk the list for an agent holding `R0`:

| Event | Hub's retained roots | Agent holding `R0` |
| :-- | :-- | :-- |
| agent goes offline | `[R0, R-1, R-2]` | verifies |
| rotation 1 (+30d) | `[R1, R0, R-1]` | verifies |
| rotation 2 (+60d) | `[R2, R1, R0]` | verifies |
| rotation 3 (+90d) | `[R3, R2, R1]` | **locked out** |

**An agent survives 2 root rotations and fails on the 3rd — so 60 days
guaranteed, up to 90 depending on where in the rotation cycle it dropped.**
Quote the 60-day figure when planning; the extra 30 is phase luck.

Because the hub re-provisions the current root to any spoke that verified on an
older one, this budget applies only to a **single continuous absence**. An agent
that reconnects even briefly is reset to current and starts its 60 days over. It
cannot accumulate drift across several short outages.

> **Hubs that predate this behavior tolerate ZERO missed rotations.** Before the
> 3-signature hub proof, `sign_hub_challenge` signed with `hub_secrets[0]` only,
> so the retained window existed on disk but was never used to verify — a single
> missed rotation locked the agent out permanently. If a fleet is running an
> older hub, assume the limit is "one 30-day rotation", not 60 days.

## What a locked-out agent looks like

The agent process is healthy and retrying, which is exactly why the box looks
fine while the hub says offline. Confirm from the agent's journal:

```bash
journalctl -u lm-agent -n 100 --no-pager | grep -i "hub identity"
```

The signature line, emitted on every retry:

```
Hub identity verification failed for all known secrets AND TLS verify is OFF —
refusing unverified hub (possible MITM). Keeping hub_secret(s); close + back off.
Re-onboard OOB or set LM_HUB_TLS_VERIFY=1.
```

The agent then closes with 1008 and retries on a 5→300s backoff, forever. On the
hub side this is recorded as a `hub_identity_rejected` spoke event and surfaces
in `/setup/diagnostics`.

Three conditions must all hold to reach this state — any one of them absent and
the agent recovers by itself:

1. its stored root is outside the hub's retained window, **and**
2. `LM_HUB_TLS_VERIFY=0` (with TLS verify on, the TLS layer authenticates the
   hub, so the spoke treats a failed proof as a benign stale rotation and falls
   back to zero-touch), **and**
3. no valid onboarding PSK is configured (a valid PSK independently
   authenticates the hub and also triggers the zero-touch fallback).

## What deleting a spoke or agent actually does

### `DELETE /setup/spokes/{id}` — hard delete

Closes the live socket, drops the approval mirror, removes the persisted
registration and metadata, and **wipes the crypto material — current key and
history**. Also purges the identity-correlation indices (`spoke_id_alias`,
`install_uuid_index`) so a clone-correlated spoke cannot resurrect itself on the
next reconnect. The spoke must fully re-onboard to return.

### `POST /setup/spokes/{id}/decommission` — soft retire

Keeps the registration record so the box stays visible and re-onboardable,
suppresses out-of-contact alerting, badges it grey in the UI. Reversible via
`/setup/spokes/{id}/restore`. **This is the right choice for a box that is
temporarily down.**

### Why deleting an offline agent does not fix it

This is the trap that sends people in circles:

1. You delete the agent. The hub wipes its session key and history.
2. You re-add it. The hub mints a **first secret that expires in 1 hour** — and
   has no way to deliver it, because the box is not connected.
3. The agent, still holding its old session secret, reconnects and presents it.
   The hub no longer has it, so the hub closes 1008 "Authentication failed".
4. The agent does the right thing: it clears its stored secret and reconnects in
   zero-touch mode to be re-provisioned.
5. **On that very next connect it hits the hub-identity wall and refuses.** The
   session-key self-heal works perfectly and gets you nowhere, because the
   blocker was never the session key.

Net effect: you destroyed recoverable state, the agent is no closer to
connecting, and it now also needs re-approval. **If an agent is offline and you
do not know why, decommission it — do not delete it.**

## Recovery runbook

Try these in order; stop at the first that works.

**1. Clear the stored hub secret on the agent** (cheapest, no hub-side change).
With no `hub_secrets`, the spoke skips hub verification entirely, sends
`HUB_OK`, connects, and the hub re-provisions a fresh root and mTLS cert on the
approved connect. On the agent box, blank the stored hub secret and restart
`lm-agent`.

**2. Turn on TLS verification** — `LM_HUB_TLS_VERIFY=1` in the agent's
environment, where the hub presents a valid publicly-trusted certificate. This
permanently removes condition 2 above, so a stale root becomes self-healing
rather than fatal. Prefer this as the durable posture wherever the hub has a
real certificate.

**3. Configure an onboarding PSK** (`LM_ONBOARDING_PSK` + `LM_TENANT_ID_HINT`).
The hub signs its challenge with the tenant's PSK as an independent
authenticator, so the spoke recovers even with TLS verify off. Best for fleets
that must stay on verify-off.

**4. Reinstall the agent.** Always works, never necessary if the above are in
place.

Note that a hub-side fix cannot revive an already-locked-out agent: it reads
only the singular `signature` field until it has new code, and it cannot receive
new code while it refuses to talk to the hub. Recovery is always an on-box
action.

## Why it is built this way

The refusal is not a bug. With `LM_HUB_TLS_VERIFY=0`, the hub's signed challenge
is the *only* thing authenticating the hub — TLS is not checking it. A spoke that
shrugged off a failed hub proof could be redirected to an attacker's hub, which
could then push `SPOKE_UPDATE` (remote code execution), `SPOKE_SET_HUB_SECRET`,
or `SPOKE_UPDATE_SESSION_KEY`. Wiping the stale secrets on a failed proof is
precisely the attacker's goal, so the spoke keeps them and backs off instead.

The cost of that correct decision is that an agent gone longer than the retained
window needs an operator. The 3-deep window and the re-provision-on-old-verify
behavior exist to make that window generous enough that it should effectively
never happen to a machine in service.

## Related

* [generic-agent.md](generic-agent.md) — the agent-spoke, roles, sub-spoke connections
* [lm-hub.md](lm-hub.md) — hub responsibilities and the mutual-auth handshake
* Code: `core/src/security/key_manager.py` (`rotate_hub_secret`, `rotate_key`,
  `get_valid_key`, `sign_hub_challenge_all`), `core/src/main.py` (mutual-auth
  proof, key-rotation loop), `core/src/messaging/control_plane.py` (spoke-side
  hub verification and the zero-touch fallback), `core/src/routes/setup.py`
  (`delete_spoke`, `decommission_spoke`)
