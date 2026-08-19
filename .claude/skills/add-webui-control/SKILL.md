---
name: add-webui-control
description: >-
  Use when adding a single new interactive control to LM's WebUI — a button,
  toggle, or small form that triggers a new backend action (e.g. "add a
  button to clear missing USB dongles", "add a toggle for X"). Touches a
  backend route module, a config default, the WebUI view that renders the
  control, its JS handler, and — only if the control lives in the
  Simulations (sim-views.js) module — a dual-copy twin in the cs repo. This
  skill is the small, self-contained recipe for a single bolt-on control; it
  is NOT for adding a new simulation (use add-simulation for that) or for
  architectural changes that touch auth, transport, encryption, or the
  self-update mechanism — those need a human, not this skill. Invoke it
  whenever asked to add a UI button/control/toggle to LM's WebUI.
---

# Add a WebUI Control

LM's WebUI (`WebUI/`) is a single-page, client-side app — one `index.html`
shell + `main.js` (the whole app, HTML strings rendered into `#viewport`) +
`sim-views.js` (the Simulations module only). There is no build step: files
are served static, versioned by a `?v=` query string. Adding one control is a
small, bounded change across a backend route, the view that renders it, and
its JS handler. Work through `reference.md` (same folder) for the exact
touch-points and code shapes; this file is the shape + the boundaries.

## The shape (in order)

1. **Backend route** — a new or extended file under `core/src/routes/`
   exporting `register(app, hub, ctx)`, wired into `core/src/api.py`'s
   existing route-registration block. Use `ctx`'s auth closures
   (`ctx._is_admin` / `ctx._is_tenant_admin` / `access.read_scope`/
   `write_scope`) for permission checks — never hand-roll a check. Any
   blocking call (subprocess, another service, a slow library) goes through
   `await asyncio.to_thread(...)` — LM's single FastAPI event loop stalls
   the ENTIRE app for the duration of a blocking call otherwise, the same
   class of bug documented in ab's own history ("TypeError: Load
   failed" from a stalled request).
2. **Config default** (only if the control needs a persisted setting) — a
   module-level `_DEFAULTS` dict + a `_cfg()` helper that merges it with
   `hub.state.get_global_config()` at READ time (see `hub_watchdog.py`'s
   shape). This means an existing install with no key at all just gets the
   default on its next read — no migration/backfill step needed. Never
   invent a second config-loading pattern.
3. **The view** — add the control's markup where the feature area's view is
   rendered in `main.js` (or `sim-views.js` — see step 5 for what that
   implies). Follow the existing button-shape convention: an inline
   `onclick="fnName(args)"` on a template-literal `<button>`, styled from
   `docs/webui-style.md`'s token set (HPE-green primary:
   `bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border
   border-[#01A982]`; destructive: `bg-red-100 hover:bg-red-200
   text-red-700`; neutral: `bg-slate-100 hover:bg-slate-200 text-slate-600
   border border-slate-200`). **A `title="…"` tooltip explaining exactly
   what the action does is mandatory** — every existing action button in
   this codebase carries one; a control without one is incomplete.
4. **JS handler** — a function beside the view, following the established
   shape: an optimistic `showToast(..., 'info')` (if the action takes a
   moment), `await` the fetch, branch on the response's `ok`, then a
   `success`/`error` toast, then (if the control changes something visible)
   re-render/refresh the view. Never a full page reload.
5. **State/status, if the control introduces one** — LM has no central
   status-enum registry (unlike ab's processed-issue counters). Add a
   local status→badge/class mapping function in the SAME view file, shaped
   like `statusBadge`/`spokeStatusMessage` — a small closure or function
   mapping the string/bool state to a Tailwind badge class, called inline
   per row. Store the state itself as a plain field on the relevant
   hub-state record (via the same config/state mechanism from step 2), not
   a new parallel data structure.
6. **Docs** — extend whichever `lm/docs/<module>.md` page already covers
   this feature area (not `webui.md`, unless the change alters the WebUI's
   overall architecture/routing, which a single control never does). The
   Help drawer renders these docs verbatim as in-app help / the Ask-AI
   knowledge base, so this is not a separate documentation-only step — it's
   how the feature becomes discoverable and explainable to users.
7. **Verify** — run the `dual-copy-guard` skill (mandatory if the control
   touched `sim-views.js`, harmless no-op otherwise), syntax-check what you
   can, and report exactly which of the 6 steps above you did and which you
   intentionally skipped (e.g. no config default needed because the control
   is stateless) — a silent skip reads as "done" when it isn't.

## Boundaries — the rules a control MUST obey

- **No new top-level nav item, view, or route category without a human.**
  This skill is for bolting a control onto an EXISTING view/feature area —
  if the request implies a wholly new section of the app, that's a design
  decision, not a bolt-on; stop and say so rather than improvising one.
- **Never hand-roll an auth check.** Use `ctx`'s closures / `access.py`'s
  `read_scope`/`write_scope`/`is_admin`/`is_tenant_admin`/
  `has_module_access` — these encode the RBAC model (system-admin vs
  tenant-admin vs per-module permission flags); a bespoke check is exactly
  how a permission gap gets introduced.
- **Never touch auth/transport/encryption/self-update code to add a
  control.** mTLS, the hub-spoke signing scheme, Fernet state encryption,
  and the watchdog/self-update mechanism are boundaries this skill's caller
  (AppBuilder's feature-classifier) should already have kept you away from —
  if you find yourself needing to touch one of those files to make a
  "simple button" work, stop; that is no longer a bolt-on.
- **Config always defaults via the `_cfg()`-merge shape**, never a one-time
  migration script, and never a raw `get_global_config()[key]` that KeyErrors
  on a fresh install.
- **Blocking calls in routes are always offloaded** (`asyncio.to_thread`) —
  LM is a single-event-loop app; an inline blocking call stalls every other
  request, not just the one that made it.
- **A `title=` tooltip is mandatory on every new action control.**
- **`sim-views.js` changes need the dual-copy-guard skill** — `cs/lm-spoke/
  static/sim-views.js` is a hand-maintained twin, not generated, and drifts
  silently otherwise. `main.js`/`index.html`/`help.js`/`update_handler.js`
  have no twin — a change there is single-copy and complete on its own.

## Scope

This skill is for **one bolt-on control on an existing view**, backend route
included. It is explicitly NOT for: adding a new client simulation (use
`add-simulation`), adding a new top-level module/nav section, or any change
to authentication, the hub-spoke transport/signing scheme, encryption, or
the self-update/watchdog mechanism — those need a human to design.
