"""DNS → Overrides: an applied override can be edited and carries a comment.

These tests EXECUTE the real WebUI functions out of ``WebUI/main.js`` under
node with stubbed globals: the Edit button opens the assign modal pre-filled
from the assignment, and Save posts the new values plus ``old_target`` so the
spoke replaces the old IP/subnet in one change.
"""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

MAIN_JS = Path(__file__).resolve().parents[2] / "WebUI" / "main.js"

pytestmark = pytest.mark.skipif(shutil.which("node") is None,
                                reason="node is required to execute the WebUI helpers")

FUNCTIONS = ["_dnsOverrideQS", "_dnsOverrideFor", "_dnsOverridesView", "_dnsOverrideExact",
             "editDnsOverrideAssignment", "showDnsOverrideAssignModal",
             "saveDnsOverrideAssignment"]

OVERRIDES = {
    "profiles": [{"name": "PAVO-DEVICE"}, {"name": "STAGING"}],
    "assignments": [{"target": "10.0.0.0/24", "profile": "PAVO-DEVICE",
                     "label": "bench", "comment": "vendor needs staging API"}],
}


def _extract(name: str) -> str:
    js = MAIN_JS.read_text(encoding="utf-8")
    start = re.search(r"(async )?function %s\(" % re.escape(name), js).start()
    end = js.index("\n}\n", start) + len("\n}\n")
    return js[start:end]


def _run(script: str):
    harness = "\n".join(_extract(n) for n in FUNCTIONS) + """
const OUT = { fetches: [], toasts: [], html: '' };
const fields = {};
const modal = { dataset: {}, remove() { OUT.removed = true; } };
globalThis.window = { _dnsOverrides: %s };
globalThis.escapeHtml = s => String(s ?? '');
globalThis.isAdmin = () => true;
globalThis.isTenantAdmin = () => false;
globalThis._tenantQS = () => '';
globalThis._taTenantQuery = () => '';
globalThis._isIPInCIDR = () => false;
globalThis.tableWrap = s => s;
globalThis.tableHead = cols => cols.join('|');
globalThis.showToast = (m, t) => OUT.toasts.push([m, t]);
globalThis.loadDNSData = () => {};
globalThis.openModal = (id, html) => {
    OUT.html = html;
    for (const m of html.matchAll(/id="(dns-ova-[a-z]+)"[^>]*?value="([^"]*)"/g)) fields[m[1]] = { value: m[2] };
    const sel = html.match(/<select id="dns-ova-profile"[\\s\\S]*?<\\/select>/)[0];
    const chosen = sel.match(/<option value="([^"]*)" selected/);
    fields['dns-ova-profile'] = { value: chosen ? chosen[1] : '' };
};
globalThis.document = { getElementById: id => id === 'dns-override-assign-modal' ? modal : fields[id] };
globalThis._spokeFetch = async (url, opts) => {
    OUT.fetches.push({ url, method: opts.method, body: JSON.parse(opts.body) });
    return { ok: true, data: { status: 'SUCCESS' } };
};
(async () => { %s })().then(() => console.log(JSON.stringify({ ...OUT, fields })));
""" % (json.dumps(OVERRIDES), script)
    out = subprocess.run(["node", "-e", harness], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout.strip().splitlines()[-1])


def test_assigned_override_rows_show_comment_and_edit_button():
    out = _run("OUT.html = _dnsOverridesView(window._dnsOverrides, 'E', 'D');")
    assert "Comment" in out["html"]
    assert "vendor needs staging API" in out["html"]
    assert "editDnsOverrideAssignment('10.0.0.0/24')" in out["html"]


def test_edit_prefills_the_modal_from_the_assignment():
    out = _run("editDnsOverrideAssignment('10.0.0.0/24');")
    assert "Edit DNS Override" in out["html"]
    assert out["fields"]["dns-ova-target"]["value"] == "10.0.0.0/24"
    assert out["fields"]["dns-ova-profile"]["value"] == "PAVO-DEVICE"
    assert out["fields"]["dns-ova-label"]["value"] == "bench"
    assert out["fields"]["dns-ova-comment"]["value"] == "vendor needs staging API"


def test_save_after_edit_posts_new_values_with_old_target():
    out = _run("""
        editDnsOverrideAssignment('10.0.0.0/24');
        fields['dns-ova-target'].value = '10.0.1.0/24';
        fields['dns-ova-profile'].value = 'STAGING';
        fields['dns-ova-comment'].value = 'moved to the new bench';
        await saveDnsOverrideAssignment();
    """)
    assert out["fetches"] == [{
        "url": "/api/dns/override-assignment", "method": "POST",
        "body": {"target": "10.0.1.0/24", "profile": "STAGING", "label": "bench",
                 "comment": "moved to the new bench", "old_target": "10.0.0.0/24"},
    }]
    assert out["removed"] is True


def test_new_assignment_sends_comment_but_no_old_target():
    out = _run("""
        showDnsOverrideAssignModal();
        fields['dns-ova-target'].value = '10.0.5.9';
        fields['dns-ova-profile'].value = 'STAGING';
        fields['dns-ova-comment'].value = 'testing captive portal';
        await saveDnsOverrideAssignment();
    """)
    body = out["fetches"][0]["body"]
    assert body["comment"] == "testing captive portal"
    assert "old_target" not in body
