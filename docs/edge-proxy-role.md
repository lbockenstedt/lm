# Edge Proxy Role — Design

> Status: **DESIGN / not yet built.** Canonical design doc per the feature-docs convention.
> Consult this before touching proxy code.

## 1. Problem & goals

**Problem.** The hub runs one unified `:443` uvicorn that serves the browser WebUI **and**
the spoke/agent mTLS control plane on the same socket. Because mTLS is enabled, that socket
sends a TLS `CertificateRequest` to *every* client (`server_verify_mode()` → `CERT_OPTIONAL`,
`core/src/security/mtls.py:191`; CA loaded via `ssl_ca_certs`, `core/src/api.py:1925-1935`).
`CERT_OPTIONAL` does not *gate* the WebUI, but it still *asks* — so a macOS browser holding a
client cert in Keychain gets prompted / blocked. The advertised CA bundle also includes the
entire system root store, so almost any Keychain cert matches.

**Goals.**
1. A macOS (or any) browser can load the WebUI with **no client-cert prompt**.
2. The WebUI can be reached **locally per tenant** (low latency), not only via the central hub.
3. **Console traffic (VNC / shell / serial) stays on the tenant LAN**, off the central hub's
   byte path — the hub (often Azure) only *brokers* the session.
4. Deploy/operate at fleet scale (~100 tenants) using existing machinery.

**Non-goals.**
- A standalone WebUI service. The browser layer is tightly coupled to the hub's live in-memory
  `hub` object (`app.state.hub`, `core/src/api.py:1062`) — sessions, RBAC, spoke registry,
  console queues are all in-process. Moving *logic* off-box is a multi-week RPC refactor and is
  explicitly out of scope. **The proxy stays dumb** (mirrors the "dumb agent" principle):
  a front door + a local byte relay, no logic, no state, no RBAC of its own.
- Changing where auth/RBAC/tenant isolation is enforced — that stays hub-side.

## 2. Shape: a first-class `proxy` agent role

The edge proxy is a new **agent role** (`agent/src/agent_spoke.py::_ROLE_MAP`, `agent_spoke.py:60`),
deployed exactly like every other role. Closest existing analog: the **`statuspage`** role, which
"serves its own HTTPS page (fastapi/uvicorn), hub pushes the tenant's config."

Reused for free (because it is a spoke):
- **Identity + link to hub** — the role's control-plane WS to the hub (outbound-only, mTLS).
  No new inbound on the hub, no new principal. It authenticates like any spoke.
- **Provisioning** — cert distribution (`INSTALL_CERT`), config push, `SPOKE_SET_HUB_URL` repoint.
- **Lifecycle** — `LOAD_ROLE`/`UNLOAD_ROLE`, sibling auto-clone, spoke-update fanout,
  dep self-heal, out-of-contact alerting, Setup → Agents management.

New pieces this role adds (the actual work):
- A browser-facing TLS listener with **no client-cert request** (kills the prompt).
- A reverse-proxy data plane to the hub for WebUI/REST/browser-WS (**Option A**).
- A local console-relay engine (**Phase 2**) that pipes console frames browser↔proxy↔spoke.

Registration:
- Add `proxy` → `proxy/src/proxy_spoke.py::ProxySpoke` (`module_type "proxy"`, in-repo or own
  repo `lbockenstedt/proxy.git`) to `_ROLE_MAP`.
- Add `proxy` to the `install_agent.sh` role list and `docs/generic-agent.md`.
- `module_type "proxy"` is new — thread it wherever module types are enumerated
  (spoke registry, approved_modules, RBAC gating, Setup → Agents display).

## 3. Topology

```
                         ┌─────────────────────────── tenant LAN ───────────────────────────┐
                         │                                                                   │
  operator's browser ───TLS (LE server cert, NO CertificateRequest)──▶  proxy role (agent)   │
                         │                                              │        │           │
                         │            control/API (Option A, mTLS) ─────┘        │ console    │
                         │                    │                                  │ relay      │
                         │                    ▼                                  ▼ (Phase 2)  │
                         │             ┌───────────────┐                 pxmx/console spoke   │
                         │             │  central hub  │◀──control plane──── (same LAN)       │
                         │             │  (Azure :443) │    (spoke WS)         │              │
                         │             └───────────────┘                       ▼              │
                         │                                            Proxmox :8006 / PTY /   │
                         │                                            /dev/tty*  (LOCAL)      │
                         └───────────────────────────────────────────────────────────────────┘
```

- **WebUI / REST / browser-WS** → proxy → hub (small payloads; logic stays central).
- **Console bytes** → proxy → spoke → real target, all on the tenant LAN. Hub brokers only.

## 4. Phase 1 — WebUI front door (Option A)

### 4.1 Browser-facing listener
- Binds the tenant's public hostname on `:443`.
- **Server cert only** — `ssl.CERT_NONE`, no `ssl_ca_certs`, no `ssl_cert_reqs`. OpenSSL sends
  no `CertificateRequest` → **no Keychain prompt**. This is the fix.
- Server cert supplied by the **LE module** (§6).

### 4.2 Upstream to the hub
- Standard reverse proxy (recommended: **Caddy or nginx**, or a small in-process `httpx` proxy
  inside `ProxySpoke` if we want it fully in the LM codebase).
- Upstream = the hub's existing `:443` (or a dedicated internal hub port), reached **outbound**
  over the same network path the spoke WS already uses (so no new reachability requirement).
- The proxy presents its **spoke mTLS client cert** on the upstream leg (the hub already does
  permissive mTLS; the proxy is just a well-behaved client that *does* present a cert).
- Forward: `/`, `/api/*`, `/auth/*`, `/sim/*`, static WebUI, and browser WebSockets
  (`/ws/console*`, `/sim/ws`). **WebSocket upgrade passthrough is required** (all off-the-shelf
  proxies do this; verify `Connection: upgrade` + `Upgrade` headers are preserved).

### 4.3 Headers / cookies / origin
- Set `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host`; preserve the `lm_session`
  cookie and `Authorization` bearer.
- Cookie `Secure` / `SameSite` / domain must match the proxy's public hostname
  (`_cookie_secure`, `core/src/api.py:383`).

### 4.4 Hub-side changes (Phase 1)
- **Honor `X-Forwarded-For`** — the single most important change. The per-IP login lockout and
  IP-spray defense (`api_login_ratelimit`) otherwise see every request from the proxy's one IP
  → false global lockouts. Trust the forwarded header **only** when the peer is an approved proxy
  (verified by the proxy's mTLS cert identity — add a `proxy_cert_identities` pin, mirroring
  `bugfixer_cert_identities`, `core/src/main.py:5321`).
- **Origin allowlist** — if any route checks `Origin`, allow the proxy hostname(s).
- Cookie domain/Secure aligned to the public hostname.

### 4.5 What Phase 1 delivers
Cert prompt gone; WebUI reachable locally per tenant. **No route refactor**, auth/RBAC unchanged.
Console still hairpins through the hub (unchanged) until Phase 2.

## 5. Phase 2 — Console shortcut (hub brokers, proxy relays to spoke)

### 5.1 Why relay-to-spoke (not dial-the-target)
Investigation of the three console types:

| Type | Ultimate target | Direct network endpoint? | Target-leg auth |
|---|---|---|---|
| **VNC** | Proxmox `<pve-host>:8006/vncwebsocket` (`pxmx/agent/src/pve_cmds.py:1112`) | Yes | `vncticket` **+** `PVEAPIToken=root@pam!lm-vnc` header — **both** (`pve_cmds.py:1104`) |
| **Shell** | local `/bin/bash -il` on `pty.openpty()` (`pxmx/agent/src/console_relay.py:195`) | **No** — in-process PTY | none on the wire (root PTY, gated hub-side) |
| **Serial** | local `/dev/tty*` via pyserial (`console/src/serial_manager.py:142`) | **No** — local device fd | OS device perms |

Only VNC has a dialable endpoint, and dialing it directly would require **shipping the
`root@pam!lm-vnc` API token to the proxy** — a security downgrade we reject. Shell/serial have
no network target at all. Therefore the **uniform** model is: the proxy replaces the hub as the
**byte relay to the spoke**; the spoke keeps terminating the real target.

```
Today:     browser ── hub(Azure) ── spoke/agent ── [Proxmox WSS | PTY | /dev/tty]
Phase 2:   browser ── proxy(LAN) ── spoke/agent ── [same targets]      (hub out of byte path)
```

Advantages: uniform across all three types (they already share the `VNC_FRAME_*` / `SHELL_*` /
`CONSOLE_DATA_*` relay frame protocol); no PVE token leak; hub leaves the byte path; console
stays on the tenant LAN.

### 5.2 Session broker flow
The `*_START` / `*_OPEN` handshakes are already synchronous `request_response` and cleanly
separable from the fire-and-forget byte stream. Reuse them; add a relay descriptor.

1. Browser calls the proxy's `POST /api/pxmx/console` (or `/shell`, `/api/console/open`). The
   proxy forwards it to the hub (Option A path).
2. Hub brokers the session on the spoke exactly as today
   (`VNC_START` / `SHELL_START` / `CONSOLE_OPEN`, `routes/pxmx.py:1171` / `1095`,
   `routes/console.py:481`), registering the in-memory session + `ws_token`.
   **New:** the hub also
   - marks the session **edge-relayed** for this tenant's proxy,
   - mints a **per-session relay token** (short TTL, single session),
   - returns to the proxy a **relay descriptor**: `{ spoke_id / agent target, relay_token,
     session_id }` alongside the normal `{session_id, ws_token, …}` body.
3. Browser opens the proxy's local `/ws/console/{session_id}?token=<ws_token>`.
4. Proxy validates `ws_token` (from the brokered response), opens a **local relay leg to the
   spoke's `/ws/agent` listener** authenticated by the `relay_token`, and pipes the console
   frames bidirectionally (`VNC_FRAME_DOWN`/`_UP`, `SHELL_IN`/`SHELL_OUT`,
   `CONSOLE_DATA`/`CONSOLE_DATA_UP`).
5. Spoke terminates the real target as today (opens Proxmox WSS with its local API token /
   spawns the PTY / opens `/dev/tty`). **The root PVE token never leaves the spoke.**

### 5.3 Proxy ↔ spoke auth
- The spoke's `/ws/agent` listener is **secret-authenticated + per-frame HMAC**
  (`agent_secret`, `core/src/messaging/agent_hosting.py:396-514`) — *not* loopback-trusted.
- **Preferred:** the hub brokers a **per-session relay token** the spoke accepts for that one
  console session, rather than sharing the long-lived `agent_secret` with the proxy.
  Extend the listener to accept `{ relay_token }` for a brokered console relay leg and verify it
  against the hub (or a hub-signed token the spoke can validate offline).
- The relay leg is local (tenant LAN); TLS optional there but recommended (the proxy already has
  a spoke cert).

### 5.4 Hub-side changes (Phase 2)
- Broker changes above: mark edge-relayed, mint `relay_token`, return relay descriptor.
- **Relax the VNC 60s hard reap for edge sessions** — `VNC_SESSION_TTL = 60`
  (`hub_vnc_console.py:27`) hard-reaps regardless of `connected`; an edge-relayed VNC session
  must survive once the proxy attaches (align it with the shell/serial `connected`-flag rule,
  `hub_vnc_console.py:69,95`).
- Spoke registry must resolve, for a given VM/host, the spoke + agent target the proxy should
  attach to (`get_spoke_for_agent`, host-pinned for VNC per `routes/pxmx.py:1142`).

### 5.5 Spoke-side changes (Phase 2)
- `/ws/agent` listener (`agent_hosting.py:396`) accepts a brokered `relay_token` for a console
  relay leg (in addition to the existing agent-secret path).
- Console frames are emitted onto the relay leg (proxy) instead of up to the hub for
  edge-relayed sessions. Note serial UP currently arrives on a different code path
  (`main.py:4761`) than VNC/shell (`main.py:3766`) — on the direct proxy↔spoke relay both are
  just frames on the relay leg, which actually *simplifies* ingestion.

## 6. Certificates (LE module)

- **Browser-facing server cert** (per proxy public hostname) is issued/renewed by the **LE
  module** and distributed via the existing cert pipeline (`le` → hub broker → target install;
  see `le-cert-module-hub-brokered-distribution.md`). The `proxy` role is a new **cert target**.
- **Upstream mTLS client cert** (proxy → hub) = the proxy's **spoke cert** from the hub CA,
  already provisioned by cert distribution. Reuse the "one cert = WebUI + mTLS client" pattern
  where practical.
- Renewal/rotation is the standard LE flow — no new mechanism.

## 7. Fallback / degradation

- **Tenant without a proxy** → browser hits the hub directly; console uses today's hub-relay
  path. Unchanged. The edge path is strictly additive and feature-detected.
- **Proxy up but can't reach the spoke** (Phase 2) → fall back to hub-relay for that session.
- **Hub down** → proxy serves nothing (no data exists without the hub); no worse than today,
  and no false promise of offline WebUI.

## 8. Security model

- **Browser leg:** LE server cert, no client cert. AuthN/AuthZ unchanged — the proxied
  `lm_session` cookie + hub-side RBAC; per-console `ws_token` (`secrets.token_urlsafe(32)`,
  60s, single session, validated at WS accept → close `4401`).
- **Proxy → hub upstream:** mTLS with the proxy's spoke cert; hub trusts it via a
  `proxy_cert_identities` pin (only from which it honors `X-Forwarded-For`).
- **Proxy → spoke relay (Phase 2):** per-session hub-brokered `relay_token`, short TTL — the
  proxy never holds the long-lived `agent_secret` or the PVE root token.
- **Tenant isolation** stays hub-RBAC. The proxy does *not* enforce isolation unless we
  deliberately hard-pin a proxy to one tenant (optional hardening, not required).
- **Audit** unchanged — the hub logs the session broker + admin actions as today.

## 9. Build order

- **Phase 1 (front door):** `proxy` role + `_ROLE_MAP`/`install_agent.sh` wiring + browser
  listener (CERT_NONE) + Option-A reverse proxy + LE server cert + hub `X-Forwarded-For` trust
  (+ `proxy_cert_identities`) + cookie/origin. **Ships the cert-prompt fix and local WebUI.**
- **Phase 2 (console shortcut):** hub broker descriptor + `relay_token` + VNC TTL relaxation +
  spoke `/ws/agent` relay-token acceptance + proxy console-relay engine. **Ships local
  VNC/shell/serial.**

## 10. Open questions / risks

1. **Proxy engine:** Caddy/nginx (least code, config-driven) vs. in-process Python in
   `ProxySpoke` (fully in the LM codebase, hub can push config as native role config). Leaning
   Caddy for Phase 1 speed; revisit for Phase 2 since the console relay is custom code anyway.
2. **How the proxy validates the browser `ws_token`** — carried in the brokered response body
   (simplest) vs. a hub validation call. Prefer carrying it.
3. **`relay_token` verification** — hub-signed token the spoke validates offline (no hub round
   trip per session) vs. spoke→hub lookup. Prefer hub-signed (works even if the hub link blips).
4. **VNC host-pinning** — the vncwebsocket must open on the VM's own PVE host
   (`routes/pxmx.py:1142`); the relay descriptor must point the proxy at the correct
   spoke/agent.
5. **Keepalive quirks** stay on the spoke↔Proxmox leg (Proxmox ignores WS pings) — unaffected by
   the proxy, but keep the existing per-leg keepalive tuning.
6. **`module_type "proxy"`** is new — audit every place module types are enumerated/gated so a
   proxy role doesn't trip RBAC or registry assumptions.

## 11. mTLS enforcement (post-proxy)

Once browsers reach the WebUI via the proxy (or via an enrolled workstation cert), the hub's
`:443` becomes spoke/agent-only and mTLS can be **enforced** (`CERT_REQUIRED`) instead of merely
requested.

### 11.1 Fresh-install default: OFF
- The mTLS master switch already defaults **OFF** (`mtls_enabled()`, `mtls.py:133`) and strict
  defaults to `CERT_OPTIONAL` (`server_verify_mode()`, `mtls.py:191`). **Keep it that way on a
  fresh install** — a new hub must be reachable by a plain browser with no cert.
- "Enforce mTLS" is a deliberate, explicit **admin action**, never automatic.

### 11.2 Two preconditions to make enforcement real (not theater)
1. **No cert-less browser may still hit the hub directly.** All WebUI access must go through a
   proxy **or** an enrolled workstation cert (§12). Verify no other legit cert-less client
   remains on the socket (agents, bugfixer mTLS client, same-box/loopback legs).
2. **Narrow the accepted client CA to the private hub CA only.** Today
   `server_client_ca_file()` (`mtls.py:242`) loads the hub CA **plus the entire system root
   store** (~100+ roots) — `CERT_REQUIRED` against that bundle would "verify" any cert chaining
   to any public root, i.e. no real gate. Strict mode MUST restrict trust to the hub mTLS CA.

### 11.3 Enable flow (UI) — with a hard "enroll first" gate
- **Global-Admin only, audited.**
- Enabling enforcement shows a **blocking warning**: *"You must enroll your workstation/browser
  (Setup → mTLS → Workstation Certificates) BEFORE enabling enforcement, or you will lock
  yourself out of the hub UI."*
- **Safety interlock (recommended):** only allow the flip if the enabling admin's **current
  connection already presents a valid hub-CA client cert** (detectable via the connection's
  verified peer cert, `peer_cert_ws.py`). If their own browser isn't enrolled, refuse the enable.
  This makes self-lockout structurally impossible.
- Two-step confirm (type-to-confirm), like the destructive-op pattern.

### 11.4 Break-glass — CLI on the hub
If enforcement locks everyone out (e.g. every workstation cert expired, or a misconfig), disable
mTLS from the hub shell using the built-in hard kill-switch **`LM_MTLS_DISABLE`** — it wins over
the runtime override AND the Fernet-encrypted hub state, so it works even when the WebUI knob is
unreachable (`mtls.py:141`).

```bash
# Break-glass: force mTLS fully OFF, then restart the hub (service = lm, env = /opt/lm/.env)
sudo sed -i '/^LM_MTLS_DISABLE=/d' /opt/lm/.env
echo 'LM_MTLS_DISABLE=1' | sudo tee -a /opt/lm/.env
sudo systemctl restart lm
```

Re-arm mTLS after fixing the cause:

```bash
sudo sed -i '/^LM_MTLS_DISABLE=/d' /opt/lm/.env
sudo systemctl restart lm
```

> A hub **restart is required** to change the listener's verify mode — the SSL context is built
> at server start (`build_server`, `api.py:1909`); the live trust hot-reload only refreshes the
> CA, not `verify_mode`. `LM_MTLS_DISABLE` takes effect on the next start.

## 12. Workstation cert enrollment (companion feature)

A UI to mint a **client cert for an operator's workstation** so an admin can reach the hub UI
**directly** (no proxy) once mTLS is enforced. The minting machinery already exists — the **Hub
Local mTLS CA** issues clientAuth certs (`security/mtls_ca.py`), with revocation in hub state and
DR escrow in the key vault. This feature wraps it in an admin page.

### 12.1 UI — Setup → mTLS → Workstation Certificates
- **Issue:** label + target user + validity → mints a clientAuth cert off the hub CA and returns
  a **PKCS#12 (`.p12`)** bundle for one-time download (passphrase shown once). Import into
  Keychain / the browser cert store.
- **List** issued certs (label, user, fingerprint, expiry, status).
- **Revoke** (lost laptop / offboarding).

### 12.2 Rules
- **Global-Admin only, audited** (matches the remote-console / command-runner pattern).
- **Private key delivered once, never stored** — the hub keeps only metadata.
- **Short-lived + revocable.** Revocation MUST be honored under strict mode (ties into the
  narrow-CA + revocation check in §11.2).
- **The cert is a transport gate, not a login.** A valid hub-CA client cert only passes the TLS
  handshake; the operator's normal `lm_session` cookie + RBAC still apply on top. (Cert-as-
  identity / auto-login is explicitly out of scope for v1.)

### 12.3 Avoiding lockout
- **Normal path:** enroll your workstation here **before** enabling enforcement (§11.3 refuses
  the enable otherwise).
- **If locked out anyway:** the CLI break-glass in §11.4.
- The issuing UI is reachable via the proxy (or before enforcement is on), so there is no
  bootstrap paradox — you never need a cert to mint your first cert.

### 12.4 Build order
Sequence **after** the proxy front door (Phase 1) and alongside the mTLS-enforcement work
(§11): enrollment UI + hub-CA minting/PKCS12 export + revoke → enforcement toggle with the
enroll-first interlock → break-glass documented. Only then flip enforcement on in production.
