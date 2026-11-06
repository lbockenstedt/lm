#!/usr/bin/env bash
# Regenerates WebUI/assets/tailwind.css — a precompiled, vendored Tailwind
# build that replaces the cdn.tailwindcss.com runtime JIT compiler. The WebUI
# has no npm build step for anything else (vanilla JS/HTML by design — see
# lm/AGENTS.md); this script is a one-time/occasional local tool whose OUTPUT
# gets committed, same as assets/html2canvas.min.js. It is NOT part of any
# deploy/CI path and nothing at runtime depends on Node/npm being present.
#
# Run this (and commit the result) whenever a Tailwind utility class is
# added, renamed, or removed anywhere in WebUI/*.html or WebUI/*.js — the
# compiled CSS only contains classes it found by scanning those files; a
# class that exists only in a string nothing here can see (e.g. built
# dynamically from concatenated fragments: `'bg-' + color + '-100'`) will
# silently have no styles. Requires Node/npm locally; installs tailwindcss
# into a throwaway temp dir so it never touches this repo's (nonexistent)
# node_modules.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WEBUI_DIR="$(cd "${SCRIPT_DIR}/../WebUI" && pwd)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT

echo "Installing tailwindcss (scratch dir: ${WORK_DIR})..."
(cd "${WORK_DIR}" && npm init -y >/dev/null 2>&1 && npm install -D tailwindcss@3 >/dev/null 2>&1)

cat > "${WORK_DIR}/tailwind.config.js" <<CONFIG
module.exports = {
  content: ["${WEBUI_DIR}/*.html", "${WEBUI_DIR}/*.js", "${WEBUI_DIR}/js/**/*.js"],
  // HPE Design System tokens (design-system.hpe.design, hpe-design-tokens).
  // See docs/webui-style.md. brand = decorative only (accents, borders, tints);
  // anything behind or as text uses primary / primary.text for AA contrast.
  theme: { extend: {
    colors: {
      brand: '#01A982',                                                // decorative.brand
      primary: { DEFAULT: '#068667', hover: '#006750', text: '#006750' }, // background.primary.strong / text.primary
      navy: '#263040',
      focus: '#292D3A',                                                // focus
      // HPE status colors on the Tailwind palette (icon.* / background.*).
      red:     { 50: '#FFECEC', 500: '#CC1F1A', 600: '#CC1F1A' },      // critical
      amber:   { 50: '#FFF3DD', 500: '#D36D00' },                      // warning
      green:   { 50: '#E3FDF4', 500: '#009A71' },                      // ok
      emerald: { 50: '#E3FDF4', 500: '#009A71' },                      // ok
      blue:    { 50: '#E0F8FF', 500: '#0055DA' },                      // info
      sky:     { 50: '#E0F8FF', 500: '#0055DA' },                      // info
    },
  } },
  plugins: [],
};
CONFIG

cat > "${WORK_DIR}/input.css" <<'CSS'
@tailwind base;
@tailwind components;
@tailwind utilities;
CSS

echo "Building ${WEBUI_DIR}/assets/tailwind.css..."
(cd "${WORK_DIR}" && npx tailwindcss -c tailwind.config.js -i input.css \
    -o "${WEBUI_DIR}/assets/tailwind.css" --minify)

echo "Done. Review the diff and commit WebUI/assets/tailwind.css."
