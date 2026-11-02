// Safe HTML templates (docs/webui.md, "How to write markup"). ES module:
//   import { safeHtml, rawHtml } from '../core/safe-html.js';
//
//   el.innerHTML = safeHtml`<b>${user.name}</b>`;
//
// Every ${value} is HTML-escaped unless it is already safeHtml (nested
// templates) or wrapped in rawHtml() for trusted markup. Arrays are flattened,
// so ${rows.map(r => safeHtml`<li>${r}</li>`)} needs no .join(''). null,
// undefined and false render as nothing; 0 renders "0". The result is a
// SafeHtml object whose toString() is the markup, so it drops into innerHTML
// and old string templates unchanged. Server data can't create a SafeHtml,
// so it can't bypass escaping.

export class SafeHtml {
    constructor(markup) { this.markup = markup; }
    toString() { return this.markup; }
}

function _safeHtmlEscape(text) {
    return String(text)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function _safeHtmlPart(value) {
    if (value === null || value === undefined || value === false) return '';
    if (value instanceof SafeHtml) return value.markup;
    if (Array.isArray(value)) return value.map(_safeHtmlPart).join('');
    return _safeHtmlEscape(value);
}

export function safeHtml(strings, ...values) {
    let out = strings[0];
    values.forEach((value, i) => { out += _safeHtmlPart(value) + strings[i + 1]; });
    return new SafeHtml(out);
}

// Trusted markup only (static strings, helpIcon() output). Grep for rawHtml
// to review every place escaping is skipped.
export function rawHtml(markup) {
    return new SafeHtml(markup === null || markup === undefined ? '' : String(markup));
}
