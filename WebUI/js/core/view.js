// ES module: import { createView, delegate } from '../core/view.js';
//
// createView: a piece of the page drawn from state. render(state) returns
// markup (normally safeHtml); every refresh morphs the element to it with
// idiomorph instead of replacing innerHTML, so focus, scroll, and the user's
// open/closed <details> survive a re-render. See docs/webui.md.
//
//   const v = createView({ el: 'osu-body', state: { data: {} }, render: s => safeHtml`...` });
//   v.setState({ data });   // merge + redraw
//   v.refresh();            // redraw after changing something render reads
//
// `el` is an element id (looked up on every refresh, since a view's container
// is re-created when its page is re-opened) or an element.

export function morphHtml(el, markup) {
    if (!window.Idiomorph) { el.innerHTML = markup; return; }
    Idiomorph.morph(el, markup, {
        morphStyle: 'innerHTML',
        callbacks: {
            // A <details> stays open/closed as the user left it.
            beforeAttributeUpdated(name, node) {
                return !(name === 'open' && node.tagName === 'DETAILS');
            },
        },
    });
}

export function createView({ el, state = {}, render }) {
    const view = {
        state,
        setState(patch) {
            Object.assign(view.state, patch);
            view.refresh();
        },
        refresh() {
            const root = typeof el === 'string' ? document.getElementById(el) : el;
            if (root) morphHtml(root, String(render(view.state)));
        },
    };
    return view;
}

// delegate: one set of listeners on a page root instead of inline on*=
// handlers and window.* globals. Markup names the action; data-* carry args:
//   <button data-action="reboot" data-node="${key}">       click
//   <input type="checkbox" data-action="toggleNode" ...>    change (form fields)
//   <input data-input="picked">                             every keystroke
//   <form data-submit="search">                             submit (Enter)
// Each action is called as actions[name](el, event). Calling delegate again on
// the same root just swaps the actions (a page re-render keeps one listener).
const _FORM_FIELDS = new Set(['INPUT', 'SELECT', 'TEXTAREA']);

export function delegate(root, actions) {
    const bound = !!root._lmActions;
    root._lmActions = actions;
    if (bound) return;
    const on = (type, attr, accept) => root.addEventListener(type, ev => {
        const el = ev.target.closest(`[${attr}]`);
        if (!el || !root.contains(el) || !accept(el)) return;
        const name = el.getAttribute(attr);
        const fn = root._lmActions[name];
        if (!fn) { console.error(`delegate: no action "${name}"`); return; }
        if (type === 'submit') ev.preventDefault();
        fn(el, ev);
    });
    on('click', 'data-action', el => !_FORM_FIELDS.has(el.tagName));
    on('change', 'data-action', el => _FORM_FIELDS.has(el.tagName));
    on('input', 'data-input', () => true);
    on('submit', 'data-submit', () => true);
}
