"""Network → Scan tab: the credential sets that Save config and a scan send.

While several Credential Vault buckets name the tenant (``vault_error`` from
GET /setup/nw-scan-credentials), the list offers no vault login, so the tab
renders no checkbox for one. Save config and Scan & add must still send the
tenant's saved ``vault:`` ids back rather than drop them (#2028 item 2), and
the hint must say what a scan then does (#2028 item 3).

Runs the real tab code from the WebUI bundle under node: the render, Save
config, Scan & add and every ``_nwt*`` helper, so a new helper is picked up
without naming it here. The page is a fake ``document`` built from the
markup the render writes."""
import json
import re
import shutil
import subprocess

import pytest
from webui_src import main_js_source

pytestmark = pytest.mark.skipif(shutil.which("node") is None,
                                reason="node is required to execute the WebUI helpers")

_SRC = main_js_source()
_WHY = "Credential Vault: several buckets name tenant 'acme' (ACME, acme)"


def _fn(name):
    """The source of the top-level (async) function ``name``; it ends at the
    first column-0 closing brace."""
    m = re.search(r"^(async )?function %s\(" % re.escape(name), _SRC, re.M)
    assert m, f"function {name} not found in the WebUI bundle"
    return _SRC[m.start():_SRC.index("\n}\n", m.start()) + 3]


def _code():
    """The Scan tab's code: escapeHtml, the render, Save config, the scan
    and every ``_nwt*`` helper."""
    helpers = [m.group(2) for m in re.finditer(r"^(async )?function (_nwt\w*)\(", _SRC, re.M)]
    names = ["escapeHtml", "_renderNwScanTab", "saveNwTenantScanConfig",
             "runNwTenantScan", *helpers]
    return "\n".join(_fn(n) for n in names)


_HARNESS = """
const OUT = { posts: [], toasts: [] };
const CFG = %(cfg)s, CREDS = %(creds)s;
let currentTenant = 'acme';
function isAdmin() { return false; }
const _NW_SCHED_INTERVALS = [['0', 'Off']];
const _NW_JITTER_OPTS = [['', 'Inherit global']];
globalThis.window = {};
// The sweep card loads itself later; nothing here needs it.
globalThis.setTimeout = () => 0;
function _loadNwScanSchedules() {}
function _renderNwScanResults2() {}
function showToast(m, t) { OUT.toasts.push([m, t]); }
// The page: the tab's container and the elements its markup holds. Writing
// the markup again replaces them, as the browser does.
const page = { html: '', els: {}, inputs: null };
const container = {
    get innerHTML() { return page.html; },
    set innerHTML(v) { page.html = v; page.els = {}; page.inputs = null; },
};
globalThis.document = {
    getElementById(id) {
        if (id === 'nw-table-container') return container;
        if (!page.html.includes(`id="${id}"`)) return null;
        page.els[id] = page.els[id] || { id, dataset: {}, textContent: '', value: '', innerHTML: '' };
        return page.els[id];
    },
    // The credential checkboxes, read from the markup once per render.
    querySelectorAll(sel) {
        if (sel !== '.nwt-cred') return [];
        page.inputs = page.inputs || [...page.html.matchAll(/<input[^>]*class="nwt-cred[^>]*>/g)]
            .map(m => ({ value: m[0].match(/value="([^"]*)"/)[1], checked: /\\schecked[\\s>]/.test(m[0]) }));
        return page.inputs;
    },
};
// The hub: GETs return the tenant's config and credential list; POSTs are recorded.
async function setupFetch(url, opts = {}) {
    if (opts.method === 'POST') {
        OUT.posts.push({ url, body: JSON.parse(opts.body) });
        return { ok: true, json: async () => ({ status: 'ok' }) };
    }
    const body = url.startsWith('/api/nw/tenant-config') ? CFG
        : url.startsWith('/setup/nw-scan-credentials') ? CREDS : {};
    return { ok: true, json: async () => body };
}
%(code)s
(async () => {
    await _renderNwScanTab();
    OUT.html = page.html;
    OUT.vaultError = (page.els['nwt-vault-error'] || {}).textContent;
    %(script)s
    await saveNwTenantScanConfig(null);
    await runNwTenantScan(null, false);
})().then(() => console.log(JSON.stringify(OUT)));
"""


def _run(saved_ids, listed_ids, vault_error="", script=""):
    """Render the tab for tenant acme with ``saved_ids`` saved and
    ``listed_ids`` listed, run ``script``, then Save config and Scan & add.
    Returns the page markup, the vault error text and the two POSTs."""
    creds = {"instances": [{"id": i, "name": i, "tenant_id": "acme"} for i in listed_ids]}
    if vault_error:
        creds["vault_error"] = vault_error
    harness = _HARNESS % {
        "cfg": json.dumps({"scan": {"credential_ids": saved_ids}, "spokes": []}),
        "creds": json.dumps(creds), "code": _code(), "script": script}
    out = subprocess.run(["node", "-e", harness], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    result = json.loads(out.stdout.strip().splitlines()[-1])
    assert [p["url"] for p in result["posts"]] == ["/api/nw/tenant-config", "/setup/nw-scan/run"]
    return result


def _sent(out):
    """The credential ids Save config and then Scan & add sent."""
    save, scan = out["posts"]
    return save["body"]["scan"]["credential_ids"], scan["body"]["credential_ids"]


def test_a_vault_conflict_keeps_the_saved_vault_logins():
    """With a vault conflict no vault login is listed, yet Save config and
    Scan & add send the saved one back. They used to send only the ticked
    sets, which dropped it (#2028 item 2)."""
    out = _run(["c-acme", "vault:acme:lower"], ["c-acme"], vault_error=_WHY)
    # No checkbox offers the vault login; the reason is shown as text.
    assert 'value="vault:acme:lower"' not in out["html"]
    assert out["vaultError"] == _WHY
    # Save config and Scan & add both send it back with the ticked set.
    assert _sent(out) == (["c-acme", "vault:acme:lower"], ["c-acme", "vault:acme:lower"])


def test_unticking_every_set_still_keeps_the_hidden_vault_login():
    """Unticking every listed set still sends the hidden vault login, which
    no checkbox can untick."""
    out = _run(["c-acme", "vault:acme:lower"], ["c-acme"], vault_error=_WHY,
               script="document.querySelectorAll('.nwt-cred')[0].checked = false;")
    assert _sent(out) == (["vault:acme:lower"], ["vault:acme:lower"])


def test_without_a_conflict_an_unlisted_vault_login_is_dropped_as_before():
    """With no conflict only the ticked sets are sent, as before the fix."""
    # A listed vault login is a checkbox like any set; an unlisted one was
    # deleted from the vault, so a save drops it.
    out = _run(["c-acme", "vault:acme:kept", "vault:acme:gone"], ["c-acme", "vault:acme:kept"])
    assert _sent(out) == (["c-acme", "vault:acme:kept"], ["c-acme", "vault:acme:kept"])


def test_the_hint_says_what_a_scan_with_no_set_ticked_does():
    """The tab's hints say that a scan with no set ticked uses the saved
    selection, and when a scan is refused during a vault conflict. They said
    a scan with no set ticked was refused (#2028 item 3)."""
    out = _run(["c-acme"], ["c-acme"], vault_error=_WHY)
    html = out["html"]
    # With no set ticked a scan uses the saved selection; it is not refused outright.
    assert "with no credential set ticked, a scan uses the saved selection" in html
    assert "a scan with no set ticked or a vault login ticked is refused" not in html
    assert ("A scan is refused while a vault login is saved, or when no set is ticked "
            "and none is saved") in html
