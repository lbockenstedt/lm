# WebUI style guide (canonical UI tokens)

The LM WebUI (`WebUI/main.js`, `WebUI/sim-views.js`, `index.html`) has an implicit
design system. This is its canonical form — **match these when adding UI** so the
app stays consistent. Derived from the dominant patterns already in use (a scan
counted usage; these are the majority styles).

## Typography

| Role | Class | Notes |
|---|---|---|
| Page / card **title** | `text-lg font-bold text-[#263040]` | brand navy. NOT slate-800/700, NOT text-xl/base. |
| Modal title | `text-lg font-bold text-[#263040]` | same as page title |
| **Section sub-label** (small caps) | `text-sm font-bold text-slate-500 uppercase tracking-wider` | grey group header; add `mb-2` when it needs an explicit bottom margin (normalized — was mb-1/3/4) |
| Body text | `text-sm text-slate-600/700` | |
| Secondary / meta | `text-xs text-slate-500` | table cells, captions |
| Micro (badges, pills) | `text-[10px]` / `text-[11px]` uppercase | status pills, chips |
| **Left-nav item** | `text-xs font-medium` | forced uniform in JS (renderNav) regardless of cached index.html |
| Sub-nav tab | `px-1.5 py-1 text-xs uppercase tracking-normal` | uniform across every view |

Avoid: `text-slate-800`/`text-slate-700` on titles (use `#263040`), `text-xl` for
normal page titles, `tracking-widest` on tab strips (overflows many-tab views).

## Cards & spacing

- Card container: `hpe-card rounded-lg shadow-sm` (radius + shadow are uniform).
- Card padding: **`p-5`** for every primary content card (now normalized — was
  drifting p-3/p-4/p-6). Exceptions: `p-0` for a `<details>` collapsible (its
  header owns the padding), `p-8` for a centered empty/error-state card.
- Root view wrapper: `space-y-4` (page sections) — the dominant vertical rhythm.
- Inside a card: `space-y-2` (fields) or `space-y-3`.

## Tables

- Cell padding: **`px-4 py-2`** (standard density). `px-4 py-3` only for a roomy
  "primary" table; `px-3 py-2` for a dense/compact table. Pick one per table —
  don't mix within a view.
- Header row: `bg-slate-50 text-xs text-slate-500 uppercase` + `th px-4 py-2 font-medium`.
- Row: `border-b border-slate-100 hover:bg-slate-50`.

## Buttons

- **Primary (HPE green)**: `bg-[#01A982]/10 hover:bg-[#01A982]/20 text-[#01A982] border border-[#01A982]`.
- Sizes (pick by context, be consistent within a toolbar):
  - large (modal submit / primary CTA): `px-6 py-2 rounded-md text-sm font-bold`
  - medium (toolbar action): `px-4 py-2 rounded-md text-xs font-bold` OR `px-3 py-1.5`
  - small (inline row action): `px-2 py-1 rounded text-xs font-bold`
- Destructive: `bg-red-100 hover:bg-red-200 text-red-700` (light) or `bg-red-600 text-white` (solid CTA).
- Neutral: `bg-slate-100 hover:bg-slate-200 text-slate-600 border border-slate-200`.

## Normalized (2026-07 consistency pass)

- Titles → `text-lg font-bold text-[#263040]` (was slate-800/700, text-xl).
- hpe-card padding → `p-5` uniform (was p-3/p-4/p-6); p-0 collapsibles + p-8 empty
  states kept.
- Section-label explicit margins → `mb-2` (was mb-1/3/4).
- Nav font → `text-xs`, force-normalized in JS; sub-nav tabs uniform.

## Known remaining drift (per-instance — NOT safe for a blind find/replace)

- **Table / input density**: `px-4 py-2` vs `px-4 py-3` vs `px-3 py-2`. These
  classes are shared by table cells, form inputs, AND buttons, so a global
  replace would break inputs/buttons. Normalize per-table (default `px-4 py-2`)
  when touching a specific view.
- **Button size tiers**: `px-6 py-2` (large CTA) / `px-4 py-2` / `px-3 py-1.5`
  (toolbar) / `px-2 py-1` (inline) — contextual, keep consistent *within* a
  toolbar rather than globally.
- **Modal widths** (`max-w-md`…`max-w-4xl`): intentionally sized to content.
