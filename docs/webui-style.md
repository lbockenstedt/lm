---
summary: "The LM WebUI follows the HPE Design System (design-system.hpe.design): HPE color tokens, HPE Graphik, sentence case, pill buttons, WCAG 2.1 AA."
keywords: [a11y, accessibility, buttons, cards, color, consistency, contrast, css, design, font, graphik, hpe, layout, lm, style, styling, theme, tokens, webui]
---

# WebUI style guide (HPE Design System)

The LM WebUI (`WebUI/main.js`, `WebUI/js/*.js`, `WebUI/sim-views.js`, `index.html`)
follows the [HPE Design System](https://design-system.hpe.design). Match these
rules when adding UI. Tokens come from the `hpe-design-tokens` package (light
theme) and live in `scripts/build-tailwind.sh` (rebuild `WebUI/assets/tailwind.css`
after any class change).

## Color tokens

| Tailwind class | Value | Use |
|---|---|---|
| `bg-primary` / `hover:bg-primary-hover` | `#068667` / `#006750` | Filled primary button, toast, selected state. White text = 4.55:1. |
| `text-primary-text` | `#006750` | Green text and links on light surfaces (6.9:1). On dark surfaces CSS renders it `#05CC93`. |
| `brand` (`bg-brand/10`, `border-brand`, `ring-brand`) | `#01A982` | **Decorative only**: tints, borders, focus rings, accents. Never as text or behind white text (3.0:1). |
| `navy` (`text-navy`, `bg-navy`) | `#263040` | Titles, topbar, footer, login panel. |
| `focus` | `#292D3A` | Keyboard focus outline (white on dark surfaces). |
| red / amber / green / blue `-500`, `-50` | HPE critical / warning / ok / info | Status colors. `red-500`/`600` = `#CC1F1A`. |

Muted text is **`text-slate-500`** (4.76:1). `text-slate-400`/`300` fail AA on
white; don't use them on light surfaces. On dark surfaces (navy, slate-800+,
topbar, footer, login) CSS renders `text-slate-500` as slate-400 automatically.

## Typography

- Font: **HPE Graphik** (`'HPE Graphik', Arial, sans-serif`). Loaded from a local
  install first, then the HPE CDN; offline hubs fall back to Arial. The font is
  licensed, so it is never committed to this repo.
- **Sentence case everywhere.** No `uppercase` class or wide letter-spacing
  (`tracking-wider`/`widest`). The novelty themes (sw, cicada) are exempt.
- **12px minimum**: use `text-xs`, never `text-[9px]`/`[10px]`/`[11px]`.

| Role | Class |
|---|---|
| Page / card title | `text-lg font-bold text-navy` |
| Section label | `text-sm font-bold text-slate-500` (+ `mb-2`) |
| Body | `text-sm text-slate-600/700` |
| Secondary / meta, badges | `text-xs text-slate-500` |
| Left-nav item | `text-xs font-medium` (forced in `renderNav`) |
| Sub-nav tab | `px-1.5 py-1 text-xs` |

## Buttons

HPE buttons are **pills** (`rounded-full`).

- Primary: `bg-primary hover:bg-primary-hover text-white px-4 py-2 rounded-full text-sm font-bold`.
- Primary (tinted, toolbar): `bg-brand/10 hover:bg-brand/20 text-primary-text border border-brand rounded-full`.
- Secondary / neutral: `bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-full`.
- Destructive: `bg-red-600 hover:bg-red-700 text-white rounded-full` (or `bg-red-50 text-red-700`).
- Sizes: large `px-6 py-2 text-sm`, toolbar `px-4 py-2`/`px-3 py-1.5 text-xs`, inline `px-2 py-1 text-xs`.
- Tabs, icon-only squares, full-width and grouped (segmented) buttons keep
  their own shape.
- Save / action buttons are right-pinned in a `flex justify-end` row, except an
  inline field+Save row, a `w-full` action, or a Save with adjacent helper text.

## Accessibility (WCAG 2.1 AA)

`WebUI/js/a11y.js` patches the live DOM, so existing markup works with the
keyboard and screen readers:

- clickable `<div>`/`<span>`/`<tr>` with `onclick` get `tabindex=0` (+ `role=button`)
  and respond to Enter/Space;
- icon-only buttons get `aria-label` from `title` (or "Close" for ×/✕);
- the active nav item gets `aria-current="page"`.

For new UI, prefer a real `<button>`, and give icon-only buttons a `title` or
`aria-label`. Don't remove the `:focus-visible` outline.

## Time

Timestamps show the time zone. `Date#toLocaleString()`/`toLocaleTimeString()`
with no arguments add it automatically (see the top of `main.js`); if you pass
options, include `timeZoneName: 'short'`.

## Cards, spacing and tables

- Card: `hpe-card rounded-lg shadow-sm`, padding **`p-5`** (`p-0` for a
  `<details>` collapsible, `p-8` for an empty/error-state card).
- View wrapper `space-y-4`; inside a card `space-y-2` or `space-y-3`.
- Table cells `px-4 py-2` (roomy `px-4 py-3`, dense `px-3 py-2` — one per table).
- Header row `bg-slate-50 text-xs text-slate-500` + `th px-4 py-2 font-medium`.
- Row `border-b border-slate-100 hover:bg-slate-50`.
- Modal widths (`max-w-md`…`max-w-4xl`) are sized to content.

## Backing out

The HPE pass landed as one merge of branch `hpe-design-compliance` (one commit
per area: tokens, contrast, a11y, typography, buttons, time). The tag
`pre-hpe-design` marks the commit before it. `git revert -m 1 <merge>` undoes
all of it; reverting a single area commit undoes just that area.

The report emails (`core/src/simulations/email_report.py`, alert emails in
`core/src/alert_engine.py`) use the same tokens. They landed as a separate merge
of branch `hpe-design-reports`; revert that merge to restore the old email look.
