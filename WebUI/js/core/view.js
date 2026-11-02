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

function morphHtml(el, markup) {
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

function createView({ el, state = {}, render }) {
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

if (typeof module !== 'undefined') module.exports = { createView, morphHtml };
