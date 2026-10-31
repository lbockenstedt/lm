# WebUI "React-lite" plan (no rewrite, no build step)

Facts: main.js 36k lines + sim-views.js 14k, classic <script> tags, 647 inline
onclick=, ~267 window.* globals, 842 escapeHtml(), 615 innerHTML=.
~40 test files read WebUI/main.js as text (string asserts / JS engine).

Ordering principle: each phase builds the primitive the next one uses, so nothing
done earlier is redone later.

## Phase 0 - Safety net (prereq for all)
- [done] core/tests/webui_src.py: `main_js_source()` / `main_js_paths()` read
  every part, in the load order read from index.html. The ~40 tests that read
  main.js now use it, so code can move between files without breaking them.
  Adding a part only needs its <script> tag in index.html.
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
  build-tailwind.sh scans js/**; verify_build.sh syntax-checks every part.
- index.html's error guard: the last part sets window.lmCoreLoaded, and the
  guard uses that (not updateStatus, which main.js defines first) so a
  broken, missing (404) or stale part still gets the reload-once recovery.
  Verified in headless Chrome: ok / broken part / missing middle part /
  missing last part.
- Verified: full core suite; headless Chrome loads old and split UI with no
  errors and the same 1465 global functions.
- Later (optional): regroup functions by view inside js/ (moves only).

## Phase 2 - Safe templating (item 5)
One PR: helper + tests + OS Updates pilot. Other views convert later, when
Phase 3 touches them anyway (no separate mass rewrite).

Helper - new WebUI/js/safe-html.js, loaded BEFORE main.js (~30 lines):
- `safeHtml` tagged template: every `${value}` is HTML-escaped (same rules
  as escapeHtml) unless it is already a SafeHtml result.
- Arrays are flattened, so `${rows.map(r => safeHtml`...`)}` needs no .join('').
- null / undefined / false render as ''; 0 renders "0".
- `rawHtml(str)`: explicit opt-out for trusted markup (helpIcon(), _osuBadge()
  output, static strings). Grep-able, so every opt-out is reviewable.
- Result is a SafeHtml object with toString(), so `el.innerHTML = safeHtml`...``
  and old string templates keep working unchanged.
- Server JSON can't create a SafeHtml instance, so the marker can't be spoofed.
- Named safeHtml/rawHtml (not `html`): 16 functions already have local
  `html` variables.

Pitfalls handled in the pilot:
- `.join('')` on SafeHtml items gives a plain string, which would then be
  double-escaped -> drop .join('') inside safeHtml (arrays are flattened).
- escapeHtml(x) inside safeHtml double-escapes -> remove those calls.
- onclick="fn('${x}')" JS-string args: escJsAttr already HTML-escapes, so it
  is wrapped as rawHtml(escJsAttr(x)) via a tiny `jsArg(x)` helper. (Goes
  away in Phase 4 when inline handlers become data-action.)
- Shared helpers that return markup (helpIcon, _osuBadge) return rawHtml(...)
  so callers in both old and new templates work.

Pilot - OS Updates view (js/settings.js): _renderOsUpdatesView, _osuCveHtml,
_osuRender and their row helpers; delete their escapeHtml calls.

Tests:
- core/tests/test_webui_safe_html.py runs safe-html.js under node (skip if
  node missing): escapes <>&"', nesting not re-escaped, arrays, null/false/0,
  rawHtml passthrough, toString into a string template.
- Pilot regression: render _osuCveHtml with a hostile fixture
  (`<img onerror>` in package/description/reason) and assert no raw tag
  survives and the normal output is unchanged for benign data.
- Ratchet: total escapeHtml( count across WebUI JS may not go up, so new
  code uses safeHtml.
- Existing suite + inline-handler test + headless Chrome load check.

Done when: helper merged, OS Updates pilot looks identical, tests green,
docs/webui.md has a 5-line "how to write markup" note.
Risk: low (new code + one view). Rework later: none - Phase 3 render
functions return safeHtml, createView does String(result) before morphing.
Phase 6 htm is bound to `phtml`, so no name clash.

## Phase 3 - Views + DOM diffing (items 3 + 2 together)
- js/core/view.js: `createView({el, state, render})` -> `{state, setState, refresh}`.
  render returns `safeHtml` (Phase 2); update applies via vendored idiomorph
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
