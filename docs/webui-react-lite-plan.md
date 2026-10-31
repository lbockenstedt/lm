# WebUI "React-lite" plan (no rewrite, no build step)

Facts: main.js 36k lines + sim-views.js 14k, classic <script> tags, 647 inline
onclick=, ~267 window.* globals, 842 escapeHtml(), 615 innerHTML=.
~40 test files read WebUI/main.js as text (string asserts / JS engine).

Ordering principle: each phase builds the primitive the next one uses, so nothing
done earlier is redone later.

## Phase 0 - Safety net (prereq for all)
- [done] core/tests/webui_src.py: `main_js_source()` / `main_js_paths()` read
  every part listed in MAIN_JS_PARTS (load order). The ~40 tests that read
  main.js now use it, so code can move between files without breaking them.
  Phase 1 only appends to MAIN_JS_PARTS.
- [done] core/tests/test_webui_inline_handlers_defined.py: every function an
  inline handler (onclick=, onchange=, ...) calls must be defined as a global
  somewhere in the WebUI. Catches the main breakage of Phases 1, 4 and 5.
- [todo, before Phase 3] Browser smoke test (Playwright, CI only): real
  create_app + fake hub, admin session, visit every nav view, fail on uncaught
  page errors. Phase 3 changes rendering, which static checks can't see.

## Phase 1 - Split files (item 6, part A) - zero behavior change
- [done] main.js (37k lines) cut into main.js (core: routes, helpers, nav,
  ~4.9k lines) + 13 contiguous WebUI/js/<area>.js classic scripts, loaded in
  the same order from index.html. Pure cut, verified lossless.
- Classic scripts share global scope, so inline onclick keeps working.
- The only cross-file hazard is load-time code using a function declared in a
  later file (function hoisting no longer spans files). An acorn scan found
  two: VIEW_LOADERS and EXTERNAL_DNS_PROVIDERS stored function references at
  load time; both now call by name (`(subMenu) => loadX(subMenu)`).
- api.py _webui_asset_fingerprint now includes WebUI/js/*.js (cache-bust);
  index.html's error guard treats js/*.js as core assets; build-tailwind.sh
  scans js/**; verify_build.sh syntax-checks every part.
- Verified: full core suite; headless Chrome loads old and split UI with no
  errors and the same 1465 global functions.
- Later (optional): regroup functions by view inside js/ (moves only).

## Phase 2 - Safe templating (item 5)
- js/core/html.js: `html` tagged template auto-escapes values; `raw(str)` marks
  trusted HTML; nested `html` results not re-escaped.
- Convert view by view; delete escapeHtml() calls as you go.
- Name it `html` now; Phase 6 uses htm bound to `phtml` to avoid collision.

## Phase 3 - Views + DOM diffing (items 3 + 2 together)
- js/core/view.js: `createView({el, state, render})` -> `{state, setState, refresh}`.
  render returns `html` (Phase 2); update applies via vendored idiomorph
  (assets/idiomorph.min.js) instead of innerHTML.
- Diffing lives inside createView only, so it is written once.
- Migrate views one at a time (start: OS Updates, which already has
  _osuRender/_osuData and hand-rolled _osuOpen preservation -> delete that).

## Phase 4 - Event delegation (item 4)
- createView gets `actions: { name(ev, el) {...} }`; one listener on the view
  root dispatches `data-action="name"` (+ data-* args).
- Per migrated view: onclick="foo(1)" -> data-action="foo" data-id="1";
  remove the matching window.foo global. Track count of onclick= / window.* in a
  test that may only go down.

## Phase 5 - ES modules (item 6, part B)
- Then drop 'unsafe-inline' from script-src in the CSP (core/src/api.py)
  once index.html's inline <script> blocks are moved to files too.
- Only when a file has no inline handlers / window.* consumers left: switch it
  to import/export and <script type="module">.
- Remaining cross-file globals become explicit imports. Last file to flip: core.

## Phase 6 - Preact + htm (item 1)
- Vendor assets/preact+htm standalone (~5 KB), bind `phtml = htm.bind(h)`.
- Use for new views and the most interactive existing ones; createView's
  state/setState/actions maps 1:1 to useState/handlers, so a migration is a
  mechanical port, not a redesign. createView stays for simple views.

## Per-PR rules
- One view (or small group) per PR, Phase 0 tests green, promote dev->qa->main.
- Regenerate tailwind.css if class strings move into new files (update
  build-tailwind.sh content globs to WebUI/js/**).
- Cache-bust: new files use ?v=__WEBUI_VERSION__ like existing tags.
