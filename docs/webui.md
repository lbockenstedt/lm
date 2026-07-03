# WebUI (lm/WebUI)

The hub's browser UI. Repo: `lm/WebUI`. Served by the hub's FastAPI app (FileResponse for `index.html` + static assets).

## Role & module_type

Not a spoke — the hub's admin/operator UI. Talks to the hub over same-origin HTTP (cookie auth) + a couple of WebSocket routes; never talks to spokes/agents directly.

## Entrypoint

Served by `core/src/api.py` (mounted at `/`, catch-all `/{full_path:path}` → `index.html`). No separate process.

## Ports

Same as the hub: `https://<hub>` (443) or `http://<hub>:443` (no-cert). WS: `/ws/console/{session_id}?token=…` (VNC), `/sim/ws` (cs telemetry).

## Key files

- `index.html` (520 lines) — shell: login overlay (`#login-panel`), first-run `#setup-panel`, main nav (`#main-nav` `setView()`), top/secondary nav, viewport, cache status bar, footer status dots. Themes: `sw-theme` (HPE), `gl-theme` (Graylog), `cicada-theme`.
- `main.js` (~11k lines) — view router (`setView`/`setSubView`, `VIEW_LOADERS`, `VIEW_LABEL`, `VIEW_SUBMENUS`, `VIEW_CHILDREN`). Views: `dashboard`, `setup`, `settings`, `logs`, `ldap`, `cppm`, `cs`, `dhcp`, `dns`, `le`, `netbox`, `nw`, `opnsense`, `pxmx`. `AGENT_ROLES` map mirrors the agent-spoke `_ROLE_MAP`. HTTP via `fetch`/`setupFetch`/`csFetch` (cookie auth, same-origin). VNC WS: `wss://${hubHost}` (443 implicit) or `ws://${hubHost}:443` fallback (no-cert) → `/ws/console/${session_id}?token=…`.
- `sim-views.js` (~3.5k lines) — Client-Sim operator UI; `connectCSWebSocket()` → `new WebSocket(`${proto}//${location.host}/sim/ws`)` for telemetry; reconnect logic; VNC placeholders over `/sim/ws/console/{sessionId}`.
- `update_handler.js` — update UI wiring.
- `assets/html2canvas.min.js` — bundled.

## Notable behaviors & gotchas

- **Protocol-aware WS** — an `https:` page builds `wss://` (443 implicit); `http:` page falls back to `ws://<hub>:443` (no-cert).
- **No direct spoke access** — all data flows through hub REST routes (`/setup/*`, `/api/*`, `/admin/*`, `/auth/*`, `/sim/api/*`); the browser only opens WS to the hub for VNC + cs telemetry.
- **Per-route API bindings** are dispatched in `main.js` `VIEW_LOADERS`; adding a hub route usually means wiring a loader here.

## Related pages

[lm-hub.md](lm-hub.md), [architecture-topology.md](architecture-topology.md), [cs.md](cs.md), [pxmx.md](pxmx.md).