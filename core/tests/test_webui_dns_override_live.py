"""DNS → Overrides → Live check: proof that an override actually answers.

Executes the real ``_dnsOverrideLiveView``/``loadDnsOverrideLiveCheck`` out of
``WebUI/main.js`` under node: each DNS server shows whether the profile is
loaded in its running Unbound, each assigned client shows how many override
answers it got, and the recent answers are listed.
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

FUNCTIONS = ["_ipToInt", "_isIPInCIDR", "_dnsOverrideFor", "_dnsOverrideLiveView",
             "loadDnsOverrideLiveCheck"]

ASSIGNMENTS = [{"target": "10.21.0.11/32", "profile": "PAVO-DEVICE", "label": "u36-6200"},
               {"target": "10.21.48.0/24", "profile": "PAVO-DEVICE", "label": "bench"}]

VERIFY = {
    "status": "SUCCESS", "minutes": 60, "assignments": ASSIGNMENTS,
    "members": [
        {"display_name": "svcs01", "ok": True, "log_local_actions": True,
         "views": [{"profile": "PAVO-DEVICE", "loaded": True, "answers": 12}]},
        {"display_name": "svcs02", "ok": True, "log_local_actions": False,
         "views": [{"profile": "PAVO-DEVICE", "loaded": False, "error": "no view"}]},
        {"display_name": "svcs03", "ok": False, "error": "unsupported worker operation"},
    ],
    "hits": [
        {"time": 1800000100, "member": "svcs01", "client": "10.21.0.11",
         "name": "devices-v2.arubanetworks.com", "type": "A", "action": "answered",
         "profile": "PAVO-DEVICE"},
        {"time": 1800000000, "member": "svcs01", "client": "10.21.0.11",
         "name": "activate.arubanetworks.com", "type": "A", "action": "answered",
         "profile": "PAVO-DEVICE"},
    ],
}


def _extract(name: str) -> str:
    js = MAIN_JS.read_text(encoding="utf-8")
    start = re.search(r"(async )?function %s\(" % re.escape(name), js).start()
    end = js.index("\n}\n", start) + len("\n}\n")
    return js[start:end]


def _run(reply):
    harness = "\n".join(_extract(n) for n in FUNCTIONS) + """
const box = { dataset: {}, innerHTML: '' };
const urls = [];
globalThis.window = { _dnsOverrides: { assignments: %s } };
globalThis.escapeHtml = s => String(s ?? '');
globalThis._tenantQS = () => '';
globalThis.tableWrap = s => s;
globalThis.tableHead = cols => cols.join('|');
globalThis.document = { getElementById: id => id === 'dns-override-live' ? box : null };
globalThis._spokeFetch = async url => { urls.push(url); return %s; };
loadDnsOverrideLiveCheck(1440).then(() => console.log(JSON.stringify({ html: box.innerHTML, urls })));
""" % (json.dumps(ASSIGNMENTS), json.dumps(reply))
    out = subprocess.run(["node", "-e", harness], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout.strip().splitlines()[-1])


def test_live_check_shows_servers_clients_and_answers():
    out = _run({"ok": True, "data": VERIFY})
    html = out["html"]
    assert out["urls"] == ["/api/dns/overrides/verify?minutes=1440"]
    assert "PAVO-DEVICE ✓ loaded" in html and "12 answer line(s)" in html
    assert "PAVO-DEVICE ✗ not loaded" in html
    assert "no answer: unsupported worker operation" in html
    assert "2 override answer(s)" in html          # 10.21.0.11 got both answers
    assert "no overridden queries" in html         # the /24 had none
    assert "devices-v2.arubanetworks.com" in html and "Override answer" in html
    assert '<option value="1440" selected>' in html


def test_live_check_reports_an_unavailable_spoke():
    out = _run({"ok": False, "data": None, "detail": "DNS spoke offline"})
    assert "DNS spoke offline" in out["html"]
    assert "Re-check" in out["html"]
