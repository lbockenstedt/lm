# Add a WebUI Control — exhaustive touch-point map

Workspace root: `/Users/lbockenstedt/vscode`. Repo used: `lm/` (hub backend +
WebUI). Only touches `cs/lm-spoke/static/sim-views.js` if the control lives in
the Simulations module (see §5).

Read the *current* files to find exact insertion points — the constructs
below are stable; line numbers are not. Placeholder `<feature>` = the route
module / feature area name (e.g. `pxmx`, `firewall`, `nw`).

Legend: ☐ = a required edit. Skip a section only when the note says it's
optional and explain why in your final report.

---

## 1 — Backend route — REQUIRED

### ☐ `core/src/routes/<feature>.py`  (new file, or an addition to an existing one)
- Export `register(app, hub, ctx)` — the only contract the route-registration
  block in `api.py` requires. Follow `core/src/routes/exec.py`'s shape for a
  simple admin-triggered action:
  - A small `_require_admin(request)` (or the tenant-scoped
    `_authz_<feature>()` shape from `firewall.py`/`ldap.py`/`nw.py`/
    `truenas.py`/`client_debug.py` if the resource is tenant-owned) that
    raises `HTTPException(403)` via `ctx._is_admin` / `access.write_scope`.
  - A config-gate check (`_cfg().get("enabled")`, see §2) before doing
    anything, if the feature has an on/off toggle.
  - Audit-log the action (`logger.warning(...)` or similar) before AND
    after, matching the surrounding module's convention.
  - Any blocking call — subprocess, another service, a slow library —
    wrapped in `await asyncio.to_thread(fn, *args)`. Never call it inline.
- ☐ Import the new module and add its `.register(app, hub, ctx)` call in the
  route-registration block in `core/src/api.py` (alongside the existing
  `security_routes.register(...)`, `exec_routes.register(...)`, etc. calls).

### ☐ Auth/permission check — pick ONE, matching the resource's ownership
- System-wide admin only: `ctx._is_admin(sess)`.
- Tenant-admin (tenant-confined): `ctx._is_tenant_admin(sess)`.
- A specific tenant-owned resource (device, firewall rule, LDAP config,
  etc.): resolve the resource's `tenant_id`, then
  `access.write_scope(sess, tenant_id)` (mutating) or
  `access.read_scope(sess, tenant_id)` (read-only) — `403` on `"deny"`.
  Copy `firewall.py`'s `_authz_firewall()` shape exactly.
- A whole module's visibility (nav-level, not per-action): `access.
  has_module_access(sess, "<module>")`.
- Never write a bespoke `if user.role == ...` check outside these helpers.

## 2 — Config default (OPTIONAL — only if the control needs a persisted setting)

### ☐ Module-level `_DEFAULTS` + `_cfg()` in the SAME route file
- Follow `hub_watchdog.py`'s shape:
  ```python
  _DEFAULTS = {"enabled": False, ...}
  def _cfg() -> dict:
      c = dict(_DEFAULTS)
      c.update(hub.state.get_global_config().get("<feature>") or {})
      return c
  ```
- Read via `_cfg()` everywhere; write via
  `hub.state.update_global_config({"<feature>": {...}})` (merges + persists
  encrypted + marks dirty — never write `system_state["global_config"]`
  directly).
- A single boolean/simple flag can skip the dict and just do
  `(hub.state.get_global_config() or {}).get("<feature>", <default>)`
  inline (see `exec.py`'s `remote_exec` key) — use the dict shape only once
  there's more than one field.

## 3 — The view — REQUIRED

### ☐ The control's markup, in the view function that renders this feature area
- `main.js` for anything outside Simulations; `sim-views.js` for anything
  inside it (see §5 for the twin implication of choosing `sim-views.js`).
- Match the existing button convention: inline
  `onclick="fnName('${arg}')"` on a template-literal `<button>` — not
  `addEventListener` wiring, which is not how buttons are built elsewhere in
  this file.
- Class tokens (from `docs/webui-style.md`, confirm current values there
  before copying — it's the canonical source, this list is illustrative):
  - Primary/HPE-green: `bg-[#01A982]/10 hover:bg-[#01A982]/20
    text-[#01A982] border border-[#01A982]`
  - Destructive: `bg-red-100 hover:bg-red-200 text-red-700` (or solid
    `bg-red-600 text-white` for a high-emphasis destructive action)
  - Neutral/secondary: `bg-slate-100 hover:bg-slate-200 text-slate-600
    border border-slate-200`
  - Size tiers: large CTA `px-6 py-2 rounded-md text-sm font-bold`; toolbar
    `px-4 py-2 rounded-md text-xs font-bold` (or `px-3 py-1.5`); inline row
    `px-2 py-1 rounded text-xs font-bold`.
- ☐ `title="…"` on the button, stating what the action DOES (not a
  restatement of the label) — every existing HPE-green action button in
  this codebase carries one; this is not optional.

## 4 — JS handler — REQUIRED

### ☐ An `async function` beside the view, following the established shape
```js
async function <feature>DoThing(arg) {
    showToast('Doing the thing…', 'info');           // optimistic, if not instant
    try {
        const { ok, data, detail } = await _spokeFetch('/api/<feature>/thing', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ arg })
        });
        if (!ok) { showToast('Failed: ' + (detail || ''), 'error'); return; }
        showToast('Done.', 'success');
        // re-render/refresh the affected part of the view here — never a full page reload
    } catch (e) { showToast('Failed: ' + (e.message || e), 'error'); }
}
```
- Use whichever fetch helper the surrounding module already uses
  (`_spokeFetch`/`setupFetch`/`csFetch`/plain `fetch`) — don't introduce a
  fourth.
- `showToast(message, type)` — `type` is `'success'` / `'error'` / `'info'`.
  For a destructive action, use `showConfirmToast(message, opts)` first
  rather than acting immediately on click.

## 5 — State/status wiring (OPTIONAL — only if the control introduces a new state)

- ☐ Store the state as a plain field on the relevant hub-state record
  (via §2's config/state mechanism, or wherever the owning resource's
  record already lives) — not a new parallel data structure.
- ☐ A local status→badge/class mapping function in the SAME view file,
  shaped like `statusBadge` (CPPM device list) or `spokeStatusMessage`
  (spoke/agent connectivity) — a small function/closure mapping the
  string/bool state to a Tailwind badge class, called inline per row.
  There is no central status registry to extend — LM's pattern is
  per-view, not global.

## 6 — Docs — REQUIRED

### ☐ Extend the existing `lm/docs/<module>.md` page for this feature area
- NOT `docs/webui.md` — that page documents the WebUI's overall
  architecture/routing, which a single control never changes.
- The Help drawer renders these docs verbatim (in-app help + the Ask-AI's
  knowledge base) — this step is how the control becomes discoverable, not
  a documentation-only formality.

## 7 — Dual-copy check (REQUIRED only if you touched `sim-views.js`)

- ☐ If the control's view code landed in `sim-views.js`: run the
  `dual-copy-guard` skill and port the equivalent change to
  `cs/lm-spoke/static/sim-views.js` — this file is a hand-maintained twin,
  NOT generated, and drifts silently otherwise.
- ☐ If the control also needed backend support inside the Simulations
  quota/config system: check the `sim_quota.py` twin
  (`lm/core/src/simulations/sim_quota.py` ⇄ `cs/lm-spoke/src/sim_quota.py`)
  too.
- If the control lives anywhere else (`main.js`, `index.html`, `help.js`,
  `update_handler.js`), there is no twin — this section is a no-op, report
  it as such rather than silently skipping it.

## 8 — Verify

- ☐ `python3 -m py_compile` on any touched `.py`.
- ☐ Run the repo's own relevant self-tests if the feature area has them.
- ☐ Run `dual-copy-guard` (cheap even when §7 was a no-op — confirms it
  actually was).
- ☐ Report exactly which of sections 1-7 you touched and which you skipped,
  and WHY for each skip (e.g. "§2 skipped — control is stateless, no config
  needed" / "§5 skipped — no new state introduced" / "§7 no-op — control
  lives in main.js, no sim-views.js twin exists").
