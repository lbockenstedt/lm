"""Regression (lm#488): the Credential Vault edit dialog must be able to show
the stored values.

Clicking Edit on a secret opened the add-secret form with the name, type and
mode filled in but every value field blank, and no way to see or reveal the
current values -- while the separate Reveal button on the same row showed them
fine. To change one field of a multi-field secret you had to cancel, Reveal,
copy each value by hand, re-open Edit and retype the lot.

That is worse than an inconvenience: ``_cvDoAddSecret`` upserts by name, so
saving after a partial re-entry overwrote the fields you did not retype with
blanks.

The fix adds a "Reveal current values" button to the edit dialog that calls the
same ``/tenant/cred-vault/reveal`` endpoint (same pass-phrase requirement) and
loads the result into the form via ``_cvFillAddFields`` -- the exact inverse of
``_cvCollectAddValue``.

The mapping tests execute the real function under JavaScriptCore against a DOM
shim, so they check behaviour rather than the presence of source text. They skip
where no JS engine is available; the wiring tests are static and always run.
"""

import json
import os
import re
import shutil
import subprocess

import pytest

WEBUI = os.path.join(os.path.dirname(__file__), "..", "..", "WebUI")
MAIN_JS = os.path.abspath(os.path.join(WEBUI, "main.js"))

JSC = ("/System/Library/Frameworks/JavaScriptCore.framework/Versions/A/"
       "Helpers/jsc")


def _src():
    with open(MAIN_JS, encoding="utf-8") as fh:
        return fh.read()


def _extract(name, src):
    """Return the source of a top-level `function <name>(...) {...}` by
    brace-matching, so the test runs the real implementation."""
    start = src.index("function %s(" % name)
    depth, i = 0, src.index("{", start)
    for k in range(i, len(src)):
        if src[k] == "{":
            depth += 1
        elif src[k] == "}":
            depth -= 1
            if depth == 0:
                return src[start:k + 1]
    raise AssertionError("unbalanced braces in " + name)


def _js_engine():
    if os.path.exists(JSC):
        return [JSC]
    node = shutil.which("node")
    return [node] if node else None


# ── wiring (static, always runs) ────────────────────────────────────────────

def test_edit_dialog_offers_a_reveal_button():
    src = _src()
    assert 'id="cv-add-reveal-btn"' in src, (
        "the edit dialog must offer a control to reveal the stored values")
    assert "_cvRevealIntoEdit(" in src


def test_reveal_button_only_appears_when_editing():
    """An add form has nothing to reveal; the button belongs to the edit path."""
    src = _src()
    i = src.index('id="cv-add-reveal-btn"')
    # The button lives inside the `${editing ? ... : ''}` arm of the template.
    window = src[max(0, i - 600):i]
    assert "editing ?" in window, (
        "the reveal button must be inside the editing-only branch")


def test_reveal_uses_the_same_endpoint_and_passphrase_as_the_reveal_dialog():
    src = _src()
    fn = _extract("_cvRevealIntoEdit", src)
    assert "'/tenant/cred-vault/reveal'" in fn
    assert "cv-add-psk" in fn, "must require the bucket pass-phrase"
    assert "_cvFillAddFields" in fn


def test_reveal_refuses_without_a_passphrase():
    """No pass-phrase must short-circuit before any network call."""
    fn = _extract("_cvRevealIntoEdit", _src())
    guard = fn.index("if (!psk)")
    call = fn.index("cred-vault/reveal")
    assert guard < call, "the pass-phrase check must precede the reveal call"


def test_dialog_blanks_revealed_plaintext_on_close():
    """Revealed secrets sit in inputs; clear them rather than orphaning a node."""
    src = _src()
    fn = _extract("_cvClearAddSecret", src)
    assert "el.value = ''" in fn
    assert "cv-add-modal" in fn
    assert '<button onclick="_cvClearAddSecret()"' in src, (
        "Cancel must clear before removing the dialog")
    assert "if (e.target === m) _cvClearAddSecret();" in src, (
        "a backdrop dismissal must clear too")


def test_secret_name_is_escaped_into_the_inline_handler():
    """Names are free text; a bare apostrophe would break out of the JS string."""
    src = _src()
    assert "encodeURIComponent(preset.name).replace(/'/g, '%27')" in src


# ── behaviour (executed) ────────────────────────────────────────────────────

_CASES = [
    ("login username/password", "login",
     {"username": "alice", "password": "s3cret"},
     {"cv-f-username": "alice", "cv-f-password": "s3cret"}),
    ("login oauth pair", "login",
     {"client_id": "cid", "client_secret": "csec"},
     {"cv-f-client-id": "cid", "cv-f-client-secret": "csec"}),
    ("apikey", "apikey", {"apikey": "AK"}, {"cv-f-apikey": "AK"}),
    ("legacy token spelling", "token", {"token": "legacy"},
     {"cv-f-apikey": "legacy"}),
    ("henet ddns key", "henet", {"ddns_key": "DK"}, {"cv-f-henet-key": "DK"}),
    ("dns he-login", "dns",
     {"provider": "he-login", "he_username": "me@x.com", "he_password": "pw"},
     {"cv-f-dns-username": "me@x.com", "cv-f-dns-password": "pw"}),
    ("dns INI round-trip (value contains '=')", "dns",
     {"provider": "rfc2136",
      "dns_creds": ("dns_rfc2136_server = 192.0.2.53\n"
                    "dns_rfc2136_name = tsigkey\n"
                    "dns_rfc2136_secret = abc==\n"
                    "dns_rfc2136_algorithm = HMAC-SHA512")},
     {"cv-f-dns-server": "192.0.2.53", "cv-f-dns-name": "tsigkey",
      "cv-f-dns-secret": "abc==", "cv-f-dns-algorithm": "HMAC-SHA512"}),
    ("generic key/value", "generic", {"mykey": "myval"},
     {"cv-f-key": "mykey", "cv-f-value": "myval"}),
    ("empty reveal writes nothing", "apikey", {}, {"cv-f-apikey": ""}),
]

_HARNESS = """
// jsc exposes print(); node exposes console.log. The harness must run on both,
// since CI has node and developer machines here have JavaScriptCore.
var __emit = (typeof print === 'function')
    ? print : function (s) { console.log(s); };
%(fn)s
var DNS_CRED_PROVIDERS = {
  'he-login': { login: true, fields: [{k:'username'},{k:'password'}] },
  'rfc2136': { fields: [
      {k:'server', ini:'dns_rfc2136_server'}, {k:'name', ini:'dns_rfc2136_name'},
      {k:'secret', ini:'dns_rfc2136_secret'},
      {k:'algorithm', ini:'dns_rfc2136_algorithm'}] }
};
var els = {};
%(ids)s.forEach(function (i) { els[i] = { value: '', checked: false }; });
els['cv-add-type'].value = %(type)s;
var document = {
  getElementById: function (id) { return els[id] || null; },
  querySelectorAll: function () { return []; }
};
function _cvLoginToggleOauth(c) { els['__oauth'] = { value: String(c) }; }
function _cvDnsRenderFields() { els['__dns'] = { value: '1' }; }
_cvFillAddFields(%(value)s);
var out = {};
Object.keys(els).forEach(function (k) { out[k] = els[k].value; });
__emit(JSON.stringify(out));
"""


@pytest.mark.parametrize("label,vtype,value,expect", _CASES,
                         ids=[c[0] for c in _CASES])
def test_reveal_populates_the_right_fields(label, vtype, value, expect, tmp_path):
    engine = _js_engine()
    if not engine:
        pytest.skip("no JavaScript engine available to execute main.js")

    ids = sorted(set(list(expect) + [
        "cv-add-type", "cv-f-login-oauth", "cv-f-dns-provider"]))
    script = _HARNESS % {
        "fn": _extract("_cvFillAddFields", _src()),
        "ids": json.dumps(ids),
        "type": json.dumps(vtype),
        "value": json.dumps(value),
    }
    path = tmp_path / "case.js"
    path.write_text(script, encoding="utf-8")

    proc = subprocess.run(engine + [str(path)], capture_output=True, text=True,
                          timeout=60)
    assert proc.returncode == 0, f"JS failed: {proc.stderr or proc.stdout}"
    got = json.loads(proc.stdout.strip().splitlines()[-1])

    for field, want in expect.items():
        assert got.get(field) == want, (
            f"{label}: {field} was {got.get(field)!r}, expected {want!r}")


def test_oauth_toggle_follows_the_revealed_shape(tmp_path):
    """A ClearPass client must flip the form to the client_id pair, not leave it
    on username/password where the values would land in the wrong inputs."""
    engine = _js_engine()
    if not engine:
        pytest.skip("no JavaScript engine available to execute main.js")

    script = _HARNESS % {
        "fn": _extract("_cvFillAddFields", _src()),
        "ids": json.dumps(["cv-add-type", "cv-f-login-oauth",
                           "cv-f-client-id", "cv-f-client-secret"]),
        "type": json.dumps("login"),
        "value": json.dumps({"client_id": "cid", "client_secret": "csec"}),
    }
    path = tmp_path / "oauth.js"
    path.write_text(script, encoding="utf-8")
    proc = subprocess.run(engine + [str(path)], capture_output=True, text=True,
                          timeout=60)
    assert proc.returncode == 0, proc.stderr
    got = json.loads(proc.stdout.strip().splitlines()[-1])
    assert got.get("__oauth") == "true", (
        "revealing an OAuth pair must re-render the login inputs as the "
        "client_id/client_secret pair")


def test_main_js_still_parses():
    """The edit above is a large template-literal splice -- prove the file is
    still syntactically valid rather than trusting a regex."""
    engine = _js_engine()
    if not engine:
        pytest.skip("no JavaScript engine available to parse main.js")
    check = ("try { new Function(readFile(%s)); print('OK'); } "
             "catch (e) { print('ERR ' + e); throw e; }" % json.dumps(MAIN_JS))
    if engine[0] != JSC:  # node has no readFile()
        check = ("const fs=require('fs');new Function(fs.readFileSync(%s,'utf8'));"
                 "console.log('OK');" % json.dumps(MAIN_JS))
    proc = subprocess.run(engine + ["-e", check], capture_output=True,
                          text=True, timeout=120)
    assert proc.returncode == 0 and "OK" in proc.stdout, (
        proc.stderr or proc.stdout)
