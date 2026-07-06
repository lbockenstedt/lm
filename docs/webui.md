# WebUI (lm/WebUI)

The hub's browser UI. Repo: `lm/WebUI`. Served by the hub's FastAPI app (FileResponse for `index.html` + static assets).

## Role & module_type

Not a spoke — the hub's admin/operator UI. Talks to the hub over same-origin HTTP (cookie auth) + a couple of WebSocket routes; never talks to spokes/agents directly.

## What it does

The WebUI is the browser app operators use to run the lab day to day: one view per module (opnsense, netbox, pxmx, dns, dhcp, cppm, ldap, cs, le, nw, generic agents), plus hub-wide Setup/Settings/Logs views. It's just the client — every page loads and saves data by calling the hub's own REST routes over the same origin (cookie session auth), and it never opens a connection to a spoke or agent directly.

It also carries the in-app documentation experience: a Help drawer that renders the canonical `lm/docs/*.md` files verbatim, and — when the bugfixer agent is connected — an "Ask AI" LLM assistant that answers questions from those same docs plus a couple of live-state lookups. See "In-app Help & the Ask AI assistant" below.

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
- **In-app Help drawer** — the WebUI ships a Help drawer (the "?" button / inline ⓘ icons, `help.js`) that renders these canonical `lm/docs/*.md` files **verbatim** as tooltips/panels. The docs in `lm/docs/` ARE the in-app help content — so keep them accurate; a docs edit is a UI-copy edit.

## How it works

**View routing.** `main.js` maintains a small router (`setView`/`setSubView`, backed by `VIEW_LOADERS`/`VIEW_LABEL`/`VIEW_SUBMENUS`/`VIEW_CHILDREN`) that maps each nav click to a loader function. Each loader knows exactly which hub route(s) to call — e.g. the Spokes & Agents loader fans out to `GET /setup/pending_spokes` + `GET /api/pxmx/agents` + `GET /setup/diagnostics` and merges the results into one table. Adding a new hub route to the UI is mostly a matter of wiring a new (or extended) loader here.

**Auth + data flow.** All fetches go through `fetch`/`setupFetch`/`csFetch` helpers, same-origin, carrying the `lm_session` cookie. The hub enforces tenant scoping server-side — a non-admin session only ever gets back data for tenants it's authorized for, regardless of what the browser asks for.

**Protocol-aware WebSockets.** The only two WS connections the browser itself opens are both to the hub, never to a spoke: `/ws/console/{session_id}?token=…` for a VM's VNC console, and `/sim/ws` for cs (Client-Simulation) telemetry. An `https:` page builds `wss://` (443 implicit); an `http:` (no-cert) page falls back to `ws://<hub>:443`.

**Help drawer rendering.** `help.js` fetches `GET /docs` (index) and `GET /docs/{name}` (one doc's raw markdown + title) and renders it client-side with a small hand-rolled markdown-to-HTML pass (headings become collapsible-anchored `<h2 id="sec-...">`, tables, fenced code, lists, and `[label](otherdoc.md#section)` links that open another doc in the same drawer instead of navigating the page). There's no server-side rendering and no separate WebUI-only copy of the docs — the same `lm/docs/*.md` files are the single source for the drawer, the doc index, and the Ask AI assistant's knowledge base.

## How to use it

- **Switch modules** — use the main nav (`#main-nav`); each module has its own view, and some have a secondary submenu for sub-sections.
- **Open Help for the current page** — click the header "Help" ("?") button, or click any inline (i) icon next to a specific field/card — the icon can jump straight to the relevant `##` section of the doc instead of just opening it at the top.
- **Ask a question instead of reading** — if the "✨ Ask AI" button is present next to Help, click it, type a natural-language question, and submit. See below for exactly how this works and what it can/can't answer.
- **Open a VM console** — from the pxmx view; this opens a dedicated `/ws/console/{session_id}` WebSocket that the hub relays to the target spoke/agent. Closing the tab or disconnecting tears down that relay.

## In-app Help & the Ask AI assistant

There are two distinct help affordances, and only one of them is an LLM:

- **Help drawer** — pure docs viewer, no LLM involved. It renders `lm/docs/*.md` verbatim. Always available.
- **"Ask AI"** — an LLM question-answering assistant layered on top of the same docs, plus two live-state tools.

**Ask AI is backed by the bugfixer module, not the hub.** The hub only orchestrates: it picks relevant docs, defines the tools, and relays each conversation turn to the connected bugfixer agent via a `HELP_ASK` command; bugfixer owns the actual multi-provider LLM call and hands back `{content, tool_calls}`. Because of this, the feature is **hidden entirely** when bugfixer isn't connected — on page load, `help.js` calls `GET /api/help/available`, and only injects the "✨ Ask AI" button next to Help when that returns `available: true`. If you do reach the ask flow while bugfixer is disconnected (e.g. it dropped after the page loaded), `POST /api/help/ask` returns **HTTP 409**.

**It answers from ONLY the docs + two live tools — never general knowledge.** `POST /api/help/ask` does lightweight RAG: it scores every canonical `lm/docs/*.md` file by keyword overlap with your question (a match on the doc's own filename counts extra), keeps the top ~4, and falls back to the overview docs (README / architecture-topology / lm-hub) if nothing scores. Those doc bodies are pasted into the model's system prompt with an explicit instruction to answer using only that material (plus any tool output) and to cite the docs it used inline as `[doc:<name>]` — the WebUI strips the raw `[doc:...]` markers from the rendered answer and shows them instead as clickable "Sources" chips that reopen that doc in the Help drawer.

**Two tools the model can call mid-answer:**
- `get_spokes_status` — every known spoke/agent with its connected/approved status and module type. This is what answers "what's connected right now" or "why is my X offline".
- `search_devices` — fans your query out to the ipam (NetBox), hypervisor (pxmx), nac (ClearPass/CPPM), directory (LDAP), and firewall (OPNsense) spokes to find a specific device, VM, DHCP lease, user, or session by name, IP, or MAC.

The agentic loop allows up to 5 turns (model calls a tool → hub executes it → result is fed back → model continues), then gives up with a "reached the tool-iteration limit" message if it still hasn't produced a final answer.

**This is why keeping `lm/docs/*.md` accurate matters beyond the Help drawer** — these files ARE the assistant's entire knowledge base. A stale or wrong doc doesn't just mislead a human reading the drawer; it becomes a stale or wrong answer from the AI assistant too.

## Troubleshooting / common questions

- **"The ✨ Ask AI button doesn't appear."** The bugfixer agent isn't connected to the hub right now — `GET /api/help/available` returned `available: false`. This isn't a WebUI bug; check whether the bugfixer module/spoke is up and connected.
- **"The assistant says it can't find the answer."** The RAG-lite step only feeds the model the ~4 docs that best match your question's keywords — if your phrasing doesn't overlap with the right doc's vocabulary (or the topic genuinely isn't documented anywhere), it won't be in context. Try rephrasing closer to a doc's own headings/filename, or open the Help drawer and browse the index directly.
- **"I get an HTTP 409 when I try to ask."** Bugfixer was connected when the page loaded (so the button appeared) but disconnected before the question was submitted. Wait for it to reconnect and try again.
- **"A module's data looks stale or won't load."** Check the relevant `VIEW_LOADERS` entry's route in `main.js` and confirm the underlying spoke is connected — the WebUI itself has no cache of its own beyond what a given view keeps in memory; a 503 from the hub route means the spoke isn't connected, a 502 means the spoke replied with an error.

## Related pages

[lm-hub.md](lm-hub.md), [architecture-topology.md](architecture-topology.md), [cs.md](cs.md), [pxmx.md](pxmx.md).