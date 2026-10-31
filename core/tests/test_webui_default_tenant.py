"""Tenant picker ★: the user picks the tenant LM opens on.

Executes the real ``_tenantDefaultStar``/``setDefaultTenant`` out of
``WebUI/main.js`` under node with stubbed globals.
"""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from webui_src import main_js_source

MAIN_JS = Path(__file__).resolve().parents[2] / "WebUI" / "main.js"

pytestmark = pytest.mark.skipif(shutil.which("node") is None,
                                reason="node is required to execute the WebUI helpers")


def _extract(name: str) -> str:
    js = main_js_source()
    start = re.search(r"(async )?function %s\(" % re.escape(name), js).start()
    end = js.index("\n}\n", start) + len("\n}\n")
    return js[start:end]


def _run(script: str, default=None, reply=None):
    reply = reply or {"ok": True, "body": {"status": "ok", "default_tenant": "acme"}}
    harness = _extract("_tenantDefaultStar") + _extract("setDefaultTenant") + """
const OUT = { fetches: [], toasts: [], stopped: false };
let currentUser = { default_tenant: %s };
globalThis.window = { _lmTenantPicker: [{ id: 'acme', name: 'Acme' }] };
globalThis.escapeHtml = s => String(s ?? '');
globalThis.showToast = (m, t) => OUT.toasts.push([m, t]);
globalThis.document = { querySelectorAll: () => [] };
const REPLY = %s;
globalThis.fetch = async (url, opts) => {
    OUT.fetches.push({ url, method: opts.method, body: JSON.parse(opts.body) });
    return { ok: REPLY.ok, statusText: 'err', json: async () => REPLY.body };
};
(async () => { %s })().then(() => console.log(JSON.stringify({ ...OUT, user: currentUser })));
""" % (json.dumps(default), json.dumps(reply), script)
    out = subprocess.run(["node", "-e", harness], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout.strip().splitlines()[-1])


def test_star_marks_only_the_default_tenant():
    out = _run("OUT.on = _tenantDefaultStar('acme'); OUT.off = _tenantDefaultStar('globex');",
               default="acme")
    assert "★" in out["on"] and "click to clear" in out["on"]
    assert "☆" in out["off"] and "setDefaultTenant('globex', event)" in out["off"]


def test_starring_saves_the_default_without_switching_tenant():
    out = _run("await setDefaultTenant('acme', { stopPropagation() { OUT.stopped = true; } });")
    assert out["stopped"] is True
    assert out["fetches"] == [{"url": "/auth/default-tenant", "method": "PUT",
                               "body": {"tenant_id": "acme"}}]
    assert out["user"]["default_tenant"] == "acme"
    assert out["toasts"] == [["Acme is now your default tenant", "success"]]


def test_starring_the_current_default_clears_it():
    out = _run("await setDefaultTenant('acme');", default="acme",
               reply={"ok": True, "body": {"status": "ok", "default_tenant": None}})
    assert out["fetches"][0]["body"] == {"tenant_id": None}
    assert out["user"]["default_tenant"] is None


def test_a_refused_save_is_reported():
    out = _run("await setDefaultTenant('acme');",
               reply={"ok": False, "body": {"detail": "You do not have access to that tenant"}})
    assert out["user"]["default_tenant"] is None
    assert out["toasts"][0][1] == "error" and "do not have access" in out["toasts"][0][0]
