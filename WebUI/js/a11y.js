// HPE Design System / WCAG 2.1 AA keyboard + screen-reader support.
//
// The WebUI renders many clickable <div>/<span>/<tr> elements with inline
// onclick handlers and icon-only buttons. Rather than touch every call site,
// this file patches the live DOM:
//   - clickable non-focusable elements get tabindex=0 (+ role=button), and
//     Enter/Space activates them like a button;
//   - icon-only buttons get an aria-label from their title (or "Close");
//   - the active nav item gets aria-current="page".
// Remove the <script src="js/a11y.js"> tag in index.html to disable it.
(function () {
    'use strict';

    const NATIVE = new Set(['A', 'BUTTON', 'INPUT', 'SELECT', 'TEXTAREA', 'SUMMARY', 'OPTION', 'LABEL']);
    const NO_ROLE = new Set(['TR', 'TD', 'TH', 'LI']);
    const CLOSE_GLYPHS = /^[×✕✖xX]$/;

    function fixClickable(el) {
        if (NATIVE.has(el.tagName) || el.hasAttribute('tabindex')) return;
        el.setAttribute('tabindex', '0');
        if (!el.hasAttribute('role') && !NO_ROLE.has(el.tagName)) el.setAttribute('role', 'button');
    }

    function fixIconButton(btn) {
        if (btn.hasAttribute('aria-label') || btn.hasAttribute('aria-labelledby')) return;
        const text = (btn.textContent || '').trim();
        if (/[A-Za-z0-9]/.test(text)) return;
        const label = btn.getAttribute('title') || (CLOSE_GLYPHS.test(text) ? 'Close' : '');
        if (label) btn.setAttribute('aria-label', label);
    }

    function fixNav() {
        document.querySelectorAll('.nav-item, .sub-nav-item').forEach((el) => {
            if (el.classList.contains('active')) el.setAttribute('aria-current', 'page');
            else if (el.hasAttribute('aria-current')) el.removeAttribute('aria-current');
        });
    }

    function scan() {
        document.querySelectorAll('[onclick]:not([tabindex])').forEach(fixClickable);
        document.querySelectorAll('button:not([aria-label])').forEach(fixIconButton);
        fixNav();
    }

    let queued = false;
    function queueScan() {
        if (queued) return;
        queued = true;
        requestAnimationFrame(() => { queued = false; scan(); });
    }

    // Enter/Space on a focused clickable element behaves like a button press.
    document.addEventListener('keydown', (e) => {
        if (e.key !== 'Enter' && e.key !== ' ') return;
        const el = e.target;
        if (!(el instanceof HTMLElement) || NATIVE.has(el.tagName) || el.isContentEditable) return;
        if (!el.hasAttribute('onclick') || el.getAttribute('tabindex') !== '0') return;
        e.preventDefault();
        el.click();
    });

    function start() {
        scan();
        new MutationObserver(queueScan).observe(document.body, {
            childList: true, subtree: true,
            attributes: true, attributeFilter: ['class', 'onclick', 'tabindex', 'aria-label', 'title'],
        });
    }

    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
    else start();
})();
