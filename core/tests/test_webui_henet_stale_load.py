"""HE.NET page (DNS -> External DNS): a load that was overtaken never paints, and
a button never acts on a page the tenant was switched away from.

lm #2028 item 1. ``loadHenet`` in ``WebUI/js/external-dns-dhcp.js`` starts four
reads, awaits them, then writes ``#dns-content`` and the ``_henet*`` state the
page's buttons read. A load that finished after a tenant switch, after the
operator moved to another DNS tab, or after "<- External DNS" used to write the
old tenant's records, credential, schedule and conflict over the current page.
A failed records read also left the previous tenant's records where the error
page's bulk buttons would act on them; the page now holds null records, and the
bulk buttons report that the records could not be loaded instead of taking the
failure for an empty list.

``setTenant()`` switches ``currentTenant`` before it reloads the view, and a
confirm toast leaves the tenant picker and the DNS tabs usable, so tenant A's
page (or a dialog or confirm opened on it) stayed clickable under tenant B, or
after the operator moved to another tab: "Sync all" sent A's records tagged as
B's. Every button that acts on a tenant's records or credential now checks that
its page is still the one on screen for the selected tenant, when clicked and
after each confirm, dialog or read it waits on.

Other DNS renderers can also draw over ``#dns-content`` while the view, tab and
tenant stay the same (the Records tab's reload when an internal DNS record's
Delete finishes). So a load draws into an element of its own, and its page
counts as on screen only while that element is still in ``#dns-content``.

These tests run the real file under node in a ``vm`` context with stubbed
globals. Every ``_spokeFetch`` waits until the test answers it, so each race
plays out in a fixed order with no timers.
"""
import json
import os
import shutil
import subprocess

import pytest
from webui_src import WEBUI

HENET_JS = WEBUI / "js" / "external-dns-dhcp.js"

pytestmark = pytest.mark.skipif(shutil.which("node") is None,
                                reason="node is required to execute the WebUI page")

# The page script with fake DOM/globals, plus helpers the scenarios use:
# start() runs loadHenet() for the tenant now selected, finish() answers that
# load's fetches and waits for it, state() reports the screen and page state,
# call([fn, ...args]) clicks a button, and tick() lets a click run until it
# ends or waits on a fetch.
_HARNESS = r"""
const fs = require('fs');
const vm = require('vm');
const P = JSON.parse(process.env.HENET_PARAMS);

// An element holds markup or one child element (#dns-content holds the one an
// HE.NET load draws into); setting either replaces what it held, as in a browser.
function element() {
    const el = {
        dataset: {}, child: null, markup: '',
        get innerHTML() { return el.child ? el.child.innerHTML : el.markup; },
        set innerHTML(html) { el.child = null; el.markup = html; drawn(el); },
        replaceChildren(child) { el.child = child; el.markup = ''; drawn(el); },
        contains(node) { return node === el || !!el.child?.contains(node); },
    };
    return el;
}
const container = element();  // #dns-content
// What the operator sees: #dns-content's markup (a load's own element adds
// none) and the conflict span's text. New markup on screen brings a new, empty
// span, as in a browser.
const screen = { get html() { return container.innerHTML; }, conflict: '' };
const drawn = el => { if (container.contains(el)) screen.conflict = ''; };
const conflictSpan = { set textContent(text) { screen.conflict = text; } };
const modals = {};   // the open dialogs by id
const fields = {     // what the operator entered in each dialog input
    'henet-moveall-target': 'tenant-c', 'henet-assign-cred': 'he-bucket|he-login-a',
    'henet-r-name': 'new.example.com', 'henet-r-type': 'A', 'henet-r-value': 'addr-new',
    'henet-r-ttl': '300', 'henet-r-tenant': 'tenant-a',
};
const parked = [];   // every _spokeFetch call, unanswered until finish()
const paints = [];   // _henetCredConflict at each _henetShowCredConflict() call
const toasts = [];   // every showToast(msg, type)
const confirms = []; // every showConfirmToast(msg); the operator always confirms
// At the moment P.when names, switch to tenant B as setTenant() does first.
// With P.how 'leave', move to the DNS Records tab instead, as setSubView()
// does. With 'repaint', another DNS renderer draws over #dns-content and
// leaves the view, tab and tenant as they are, as the Records tab's reload
// after an internal DNS record's Delete does (certificates.js:3417).
const flip = when => {
    if (P.when !== when) return;
    if (P.how === 'leave') ctx.currentSubView = 'Records';
    else if (P.how === 'repaint') container.innerHTML = '<p>Records tab</p>';
    else ctx.currentTenant = 'tenant-b';
};
const ctx = {
    console, __paints: paints,
    currentView: 'dns', currentSubView: 'External DNS', currentTenant: 'default',
    activeProducts: new Set(['henet']),
    document: {
        createElement: () => element(),
        // A dialog input exists only while its dialog is open.
        getElementById: id => id === 'dns-content' ? container
            : modals[id] ? modals[id]
            : (id in fields && Object.values(modals).some(m => m.html.includes(`id="${id}"`)))
                ? { value: fields[id] }
            : (id === 'henet-cred-conflict' && screen.html.includes('id="henet-cred-conflict"'))
                ? conflictSpan : null,
    },
    escapeHtml: s => String(s),
    isAdmin: () => true,
    isTenantAdmin: () => false,
    tableHead: cols => '<thead>' + cols.join('|') + '</thead>',
    tableWrap: html => '<table>' + html + '</table>',
    _isSpokeUpdating: () => false,
    _spokeErrorBanner: (detail, fallback) => '<p>Error: ' + (detail || fallback) + '</p>',
    _spokeFetch: (url, opts = {}) => new Promise((resolve, reject) => parked.push({
        url, method: opts.method || 'GET', body: opts.body ? JSON.parse(opts.body) : null,
        resolve, reject })),
    showToast: (msg, type) => toasts.push({ msg, type }),
    showConfirmToast: async msg => { confirms.push(msg); flip('confirm'); return true; },
    // The reads a dialog's button waits on before it opens the dialog.
    ensureTenants: async () => { flip('wait'); },
    apiJson: async () => { flip('wait'); return { secrets: [{ type: 'henet', bucket: 'he-bucket', name: 'he-login-a' }] }; },
    openModal: (id, html) => (modals[id] = { id, html, dataset: {}, remove() { delete modals[id]; } }),
    viewAsTenant: async () => {},
};
ctx.window = ctx;
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(process.env.HENET_JS, 'utf8'), ctx);
vm.runInContext(`{
    const show = _henetShowCredConflict;
    _henetShowCredConflict = function () { __paints.push(_henetCredConflict); return show(); };
}`, ctx);
const call = ([fn, ...args]) => ctx[fn](...args);
const tick = () => new Promise(resolve => setImmediate(resolve));

// Each tenant's answers. A Global Admin's record list holds every tenant's;
// tenant-c has none.
const TENANTS = {
    'default': { cred: 'he-login-admin', time: '03:00', conflict: 'Two slots name the Admin slot' },
    'tenant-a': { cred: 'he-login-a', time: '01:00', conflict: 'Two slots name tenant-a' },
    'tenant-b': { cred: 'he-login-b', time: '02:00', conflict: 'Two slots name tenant-b' },
    'tenant-c': { cred: 'he-login-c', time: '04:00', conflict: 'Two slots name tenant-c' },
};
const RECORDS = [
    { name: 'shared.example.com', type: 'A', value: 'addr-s', ttl: 300, tenant_id: '' },
    { name: 'a.example.com', type: 'A', value: 'addr-a', ttl: 300, tenant_id: 'tenant-a' },
    { name: 'b.example.com', type: 'AAAA', value: 'addr-b', ttl: 600, tenant_id: 'tenant-b' },
];

// Start loadHenet() for the selected tenant; its fetches are keyed by path tail.
function start() {
    const from = parked.length;
    const done = ctx.loadHenet();
    const reqs = {};
    for (const p of parked.slice(from)) reqs[p.url.split('?')[0].split('/').pop()] = p;
    return { tenant: ctx.currentTenant, done, reqs };
}

// Answer one load's fetches with its tenant's data and wait for it to end.
// cred: 'ok' | 'conflict' (409); records: 'ok' | 'error' (502) | 'reject'.
async function finish(load, { cred = 'ok', records = 'ok' } = {}) {
    const t = TENANTS[load.tenant];
    const ok = data => ({ ok: true, status: 200, data, detail: null });
    const r = load.reqs;
    r.status?.resolve(ok({ status: 'SUCCESS', reachable: true, record_count: RECORDS.length }));
    r['sync-config']?.resolve(ok({ config: { enabled: true, mode: 'daily', daily_time: t.time } }));
    r.credential?.resolve(cred === 'ok'
        ? ok({ credential: { bucket: 'he-bucket', name: t.cred }, tenants: {} })
        : { ok: false, status: 409, data: null, detail: t.conflict });
    if (records === 'reject') r.records?.reject(new Error('network down'));
    else r.records?.resolve(records === 'ok' ? ok({ records: RECORDS })
        : { ok: false, status: 502, data: null, detail: 'HE.NET spoke offline' });
    await load.done;
}

// The screen plus every piece of page state a stale load could overwrite.
// records: 'unset' when no load published a page, null when the read failed.
function state() {
    const page = vm.runInContext('_henetPage', ctx);
    return {
        html: screen.html, conflictText: screen.conflict, paints: paints.slice(),
        records: page === null ? 'unset' : page.records && page.records.map(r => r.name),
        cred: ctx._henetAssignedCred === undefined ? 'unset' : ctx._henetAssignedCred,
        schedule: ctx._henetScheduleCfg ? ctx._henetScheduleCfg.daily_time : null,
        tab: ctx._henetActiveTab === undefined ? 'unset' : ctx._henetActiveTab,
        conflict: vm.runInContext('_henetCredConflict', ctx),
    };
}
let out;
"""

# Load A (tenant A) is still out when the operator switches to tenant B, whose
# load finishes first; then A's answers arrive.
_TENANT_SWITCH = """
ctx.currentTenant = 'tenant-a';
const a = start();
ctx.currentTenant = 'tenant-b';
const b = start();
await finish(b, { cred: P.current || 'ok' });
const current = state();
await finish(a, { cred: P.stale || 'ok' });
out = { current, final: state(), credUrls: [a.reqs.credential.url, b.reqs.credential.url] };
"""

# setTenant() sets currentTenant, then awaits two hub calls before it reloads
# the view, so A's answers can land while no newer load exists yet.
_SWITCH_BEFORE_RELOAD = """
ctx.currentTenant = 'tenant-a';
const a = start();
const loading = screen.html;
ctx.currentTenant = 'tenant-b';
await finish(a);
out = { loading, final: state() };
"""

# Tenant A's page is up; after a switch to tenant B, B's records read fails.
_FAILED_READ_AFTER_SWITCH = """
ctx.currentTenant = 'tenant-a';
await finish(start());
const before = state();
ctx.currentTenant = 'tenant-b';
await finish(start(), { records: P.records });
out = { before, after: state() };
"""

# The operator opens DNS -> Records (which draws itself) before the load ends.
# With P.how 'repaint', only the Records tab's paint lands: another DNS renderer
# draws over #dns-content and leaves the view, tab and tenant as they are.
_NAVIGATE_AWAY = """
ctx.currentTenant = 'tenant-a';
const a = start();
if (P.how !== 'repaint') ctx.currentSubView = 'Records';
container.innerHTML = '<p>Records tab</p>';
await finish(a, { records: P.records });
out = state();
"""

# Two providers: the HE.NET tile was opened, then "<- External DNS" clicked.
_BACK_TO_TILES = """
vm.runInContext("EXTERNAL_DNS_PROVIDERS.push({ id: 'other', product: 'other', "
    + "name: 'Other DNS', desc: 'A second provider', load() {} })", ctx);
ctx.activeProducts = new Set(['henet', 'other']);
ctx.currentTenant = 'tenant-a';
const a = start();
await ctx.loadExternalDNS();
const tiles = screen.html;
await finish(a);
out = { tiles, final: state() };
"""

# An action's reload (say after Save) that runs once the operator has left.
_RELOAD_AFTER_LEAVING = """
ctx.currentTenant = 'tenant-a';
ctx.currentSubView = 'Records';
container.innerHTML = '<p>Records tab</p>';
await finish(start());
out = state();
"""

# One load, nothing racing it.
_SINGLE_LOAD = """
ctx.currentTenant = 'tenant-b';
const b = start();
const loading = screen.html;
await finish(b, { cred: P.cred });
out = { loading, final: state() };
"""

# The page for P.tenant is up (its records read answered P.records), then the
# operator clicks the bulk button that runs P.action.
_BULK_ACTION = """
ctx.currentTenant = P.tenant;
await finish(start(), { records: P.records });
const before = parked.length;
await ctx[P.action]();
out = { toasts, confirms: confirms.length, fetches: parked.length - before };
"""

# Tenant A's page is up; the operator opens the dialog P.open (if any), then
# clicks P.click. flip() switches to tenant B (or, with P.how 'leave', moves to
# the DNS Records tab, or with 'repaint', has another DNS renderer draw over the
# page) at P.when: 'click' (just before the click, while setTenant() has not
# reloaded the view yet), 'wait' (during a read the button waits on), 'confirm'
# (while its confirm toast is open), or 'never'. 'reload' instead starts a
# reload of A's page just before the click.
# sent lists each request as [method, url, body].
_BUTTON = """
ctx.currentTenant = 'tenant-a';
await finish(start());
if (P.open) { call(P.open); await tick(); }
const opened = Object.keys(modals);
flip('click');
if (P.when === 'reload') start();
const from = parked.length;
call(P.click);
await tick();
out = { opened, open: Object.keys(modals), toasts, confirms: confirms.length,
        sent: parked.slice(from).map(p => [p.method, p.url, p.body]) };
"""

_LEFT_ALONE = {"records": "unset", "cred": "unset", "schedule": None, "tab": "unset",
               "conflict": "", "paints": []}

# Each button on tenant A's page that acts on its records or credential: the
# dialog button that opens it (None for the page's own buttons), the click, and
# the first request it sends. a.example.com is tenant A's only record (A,
# addr-a, TTL 300); the dialogs' inputs hold the values in the harness's fields.
_A_REC = {"name": "a.example.com", "type": "A"}
_BUTTONS = {
    "Deconfigure": (None, ["deconfigureHenetScope"], ["DELETE", "/api/henet/record", _A_REC]),
    "Remove row": (None, ["deleteHenetRecord", "a.example.com", "A"],
                   ["DELETE", "/api/henet/record", _A_REC]),
    "Import existing": (None, ["importHenet"],
                        ["POST", "/api/henet/import", {"tenant": "tenant-a"}]),
    "Sync all": (None, ["syncHenet"], ["POST", "/api/henet/sync", {
        "records": [{**_A_REC, "value": "addr-a", "ttl": 300}], "tenant": "tenant-a"}]),
    "Move all": (["showHenetMoveAllModal"], ["_henetMoveAll"],
                 ["POST", "/api/henet/record/tenant", {**_A_REC, "tenant": "tenant-c"}]),
    "Save credential": (["showHenetCredModal"], ["_henetSaveCred"], [
        "POST", "/api/henet/credential",
        {"bucket": "he-bucket", "name": "he-login-a", "tenant": "tenant-a"}]),
    "Clear credential": (["showHenetCredModal"], ["_henetClearCred"],
                         ["DELETE", "/api/henet/credential?tenant=tenant-a", None]),
    "Add record": (["showHenetRecordModal"], ["saveHenetRecord"], [
        "POST", "/api/henet/record",
        {"name": "new.example.com", "type": "A", "value": "addr-new", "ttl": 300,
         "tenant": "tenant-a"}]),
    "Edit record": (["editHenetRecord", "a.example.com", "A"], ["saveHenetRecord"], [
        "PUT", "/api/henet/record",
        {**_A_REC, "value": "addr-new", "ttl": 300, "tenant": "tenant-a"}]),
}
_GONE = ("The HE.NET page was left, reloaded or switched to another tenant, "
         "so nothing was changed.")


def _run(scenario, **params):
    """Run one scenario against the real page script; return what it reports."""
    js = (_HARNESS + "(async () => {\n" + scenario
          + "\n})().then(() => console.log(JSON.stringify(out)));\n")
    env = dict(os.environ, HENET_JS=str(HENET_JS), HENET_PARAMS=json.dumps(params))
    proc = subprocess.run([shutil.which("node"), "-e", js], capture_output=True, text=True,
                          encoding="utf-8", env=env, timeout=60)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout.strip().splitlines()[-1])


def _untouched(page):
    """The state fields of ``page`` that a load writes (none should be written)."""
    return {k: page[k] for k in _LEFT_ALONE}


def _button(name, when, how=None):
    """Click tenant A's button ``name`` (see _BUTTONS) with the switch, or with
    a move to another tab when ``how`` is 'leave', at ``when``."""
    opener, click, _ = _BUTTONS[name]
    return _run(_BUTTON, open=opener, click=click, when=when, how=how)


def _refused(out):
    """True when the click showed only the page-gone error toast."""
    return [t["type"] for t in out["toasts"]] == ["error"] and _GONE in out["toasts"][0]["msg"]


def test_tenant_switch_keeps_the_new_tenants_page():
    """A's late answers leave B's markup, records, credential, schedule and tab."""
    out = _run(_TENANT_SWITCH)
    assert out["credUrls"] == ["/api/henet/credential?tenant=tenant-a",
                               "/api/henet/credential?tenant=tenant-b"]
    page = out["current"]
    assert "b.example.com" in page["html"] and "he-login-b" in page["html"]
    assert "a.example.com" not in page["html"] and "he-login-a" not in page["html"]
    assert page["records"] == ["b.example.com"]
    assert page["cred"] == {"bucket": "he-bucket", "name": "he-login-b"}
    assert page["schedule"] == "02:00"
    assert page["tab"] == "tenant-b"
    assert page["conflict"] == "" and page["paints"] == [""]
    # Nothing changed when A finished, and A did not repaint the conflict.
    assert out["final"] == page


def test_answers_between_the_switch_and_the_reload_draw_nothing():
    """A's answers that beat setTenant()'s reload leave "Loading…" and the state alone."""
    out = _run(_SWITCH_BEFORE_RELOAD)
    assert out["final"]["html"] == out["loading"]
    assert _untouched(out["final"]) == _LEFT_ALONE


@pytest.mark.parametrize("records, error", [
    ("error", "Error: HE.NET spoke offline"),  # the hub answered with an error
    ("reject", "Error: network down"),         # the request itself failed
])
def test_a_failed_read_keeps_no_records_from_the_tenant_before(records, error):
    """The error page's bulk buttons must not act on tenant A's record list."""
    out = _run(_FAILED_READ_AFTER_SWITCH, records=records)
    assert out["before"]["records"] == ["a.example.com"]
    assert out["before"]["tab"] == "tenant-a"
    page = out["after"]
    assert error in page["html"] and "Deconfigure" in page["html"]
    assert page["records"] is None and page["tab"] == "tenant-b"


@pytest.mark.parametrize("action", [
    "deconfigureHenetScope", "showHenetMoveAllModal", "syncHenet"])
def test_bulk_buttons_on_an_error_page_say_the_records_were_not_loaded(action):
    """A failed read is not an empty list: no "nothing to remove", no request sent."""
    out = _run(_BULK_ACTION, tenant="tenant-b", records="error", action=action)
    assert [t["type"] for t in out["toasts"]] == ["error"]
    assert "could not be loaded" in out["toasts"][0]["msg"]
    assert out["confirms"] == 0 and out["fetches"] == 0


def test_deconfigure_on_an_empty_scope_still_says_there_is_nothing_to_remove():
    """A read that succeeded with no records in scope is still reported as empty."""
    out = _run(_BULK_ACTION, tenant="tenant-c", records="ok", action="deconfigureHenetScope")
    assert out["toasts"] == [{"msg": "No HE.NET records under management for tenant-c.",
                              "type": "success"}]
    assert out["confirms"] == 0 and out["fetches"] == 0


@pytest.mark.parametrize("stale, current", [
    ("conflict", "ok"),        # a stale 409 must not show on a page that has none
    ("conflict", "conflict"),  # ...nor replace the current page's own conflict
    ("ok", "conflict"),        # and a stale success must not clear that conflict
])
def test_stale_credential_conflict_never_reaches_the_current_page(stale, current):
    """Only the current load sets (or clears) _henetCredConflict and its text."""
    out = _run(_TENANT_SWITCH, stale=stale, current=current)
    want = "Two slots name tenant-b" if current == "conflict" else ""
    page = out["current"]
    assert page["conflict"] == want and page["conflictText"] == want
    assert page["paints"] == [want]
    assert out["final"] == page


@pytest.mark.parametrize("records", ["ok", "error", "reject"])
def test_leaving_the_tab_keeps_the_tab_the_operator_opened(records):
    """Whether the records come back, fail or throw, the Records tab stays."""
    out = _run(_NAVIGATE_AWAY, records=records)
    assert out["html"] == "<p>Records tab</p>"
    assert _untouched(out) == _LEFT_ALONE


@pytest.mark.parametrize("records", ["ok", "error", "reject"])
def test_a_load_whose_content_another_renderer_replaced_draws_nothing(records):
    """Another DNS renderer drew over #dns-content (the Records tab's reload
    after an internal DNS Delete) with the view, tab and tenant unchanged: the
    load paints nothing into what replaced it and publishes no page."""
    out = _run(_NAVIGATE_AWAY, records=records, how="repaint")
    assert out["html"] == "<p>Records tab</p>"
    assert _untouched(out) == _LEFT_ALONE


def test_back_to_the_provider_tiles_keeps_the_tiles():
    """loadExternalDNS() drops the HE.NET load it replaced."""
    out = _run(_BACK_TO_TILES)
    assert "HE.NET" in out["tiles"] and "Other DNS" in out["tiles"]
    assert out["final"]["html"] == out["tiles"]
    assert _untouched(out["final"]) == _LEFT_ALONE


def test_a_reload_after_leaving_the_tab_draws_nothing():
    """Not even "Loading…" is drawn over the tab the operator moved to."""
    out = _run(_RELOAD_AFTER_LEAVING)
    assert out["html"] == "<p>Records tab</p>"
    assert _untouched(out) == _LEFT_ALONE


@pytest.mark.parametrize("cred, want_cred, want_conflict", [
    ("ok", {"bucket": "he-bucket", "name": "he-login-b"}, ""),
    ("conflict", None, "Two slots name tenant-b"),
])
def test_a_single_load_still_draws_the_page(cred, want_cred, want_conflict):
    """With nothing racing it, a load draws and sets everything as before."""
    out = _run(_SINGLE_LOAD, cred=cred)
    assert out["loading"] == '<p class="text-sm text-slate-500 italic p-4">Loading…</p>'
    page = out["final"]
    assert "● HE DNS reachable" in page["html"]
    assert "auto-sync daily at 02:00" in page["html"]
    assert "b.example.com" in page["html"] and "a.example.com" not in page["html"]
    assert ("🔐 he-login-b" in page["html"]) == (want_cred is not None)
    assert page["records"] == ["b.example.com"]
    assert page["cred"] == want_cred
    assert page["schedule"] == "02:00"
    assert page["tab"] == "tenant-b"
    assert page["conflict"] == page["conflictText"] == want_conflict
    assert page["paints"] == [want_conflict]


@pytest.mark.parametrize("name", _BUTTONS)
def test_each_button_still_sends_its_request_for_the_page_on_screen(name):
    """With nothing switched, each button sends tenant A's request, as before."""
    out = _button(name, "never")
    assert out["sent"] == [_BUTTONS[name][2]]
    assert out["toasts"] == []
    # A dialog closes only once its request succeeds, and these never answer.
    assert len(out["opened"]) == (_BUTTONS[name][0] is not None)
    assert out["open"] == out["opened"]


@pytest.mark.parametrize("when, how", [
    ("click", None), ("reload", None), ("click", "leave"), ("click", "repaint")])
@pytest.mark.parametrize("name", _BUTTONS)
def test_a_button_on_a_page_no_longer_on_screen_sends_nothing(name, when, how):
    """After a switch (before setTenant() reloads the view), once a reload
    started, after a move to another tab, or after another DNS renderer drew
    over the page with the view, tab and tenant unchanged, a button says so and
    sends nothing; its dialog is closed."""
    out = _button(name, when, how)
    assert out["sent"] == [] and out["confirms"] == 0
    assert out["open"] == []
    assert _refused(out)


@pytest.mark.parametrize("how", [None, "leave", "repaint"])
@pytest.mark.parametrize("when", ["click", "wait"])
@pytest.mark.parametrize("opener", [
    ["showHenetMoveAllModal"], ["showHenetCredModal"], ["showHenetRecordModal"],
    ["editHenetRecord", "a.example.com", "A"]])
def test_a_dialog_does_not_open_for_a_page_no_longer_on_screen(opener, when, how):
    """Switched, moved to another tab, or drawn over by another DNS renderer,
    before the click or during the read the dialog waits on."""
    out = _run(_BUTTON, open=None, click=opener, when=when, how=how)
    assert out["open"] == [] and out["sent"] == []
    assert _refused(out)


_SAME_TENANT_OTHER_CASE = """
ctx.currentTenant = 'tenant-a';
await finish(start());
ctx.currentTenant = ' Tenant-A ';
const from = parked.length;
ctx.deleteHenetRecord('a.example.com', 'A');
await tick();
out = { toasts, confirms: confirms.length,
        sent: parked.slice(from).map(p => [p.method, p.url, p.body]) };
"""


def test_an_equivalent_tenant_id_in_another_case_keeps_the_page_live():
    """Tenant ids compare trimmed and case-folded, as the hub's tenant checks do."""
    out = _run(_SAME_TENANT_OTHER_CASE)
    assert out["toasts"] == []
    assert out["confirms"] == 1
    assert out["sent"] == [["DELETE", "/api/henet/record", _A_REC]]


@pytest.mark.parametrize("how", [None, "leave", "repaint"])
@pytest.mark.parametrize("name", ["Deconfigure", "Remove row", "Import existing", "Sync all"])
def test_a_switch_or_move_while_the_confirm_is_open_sends_nothing(name, how):
    """The confirm toast stays up while the operator switches tenant or moves to
    another tab, and while another DNS renderer draws over the page: confirming
    after any of these sends nothing, so tenant A's records are never sent as
    tenant B's, nor acted on from a page no longer shown."""
    out = _button(name, "confirm", how)
    assert out["confirms"] == 1 and out["sent"] == []
    assert _refused(out)
