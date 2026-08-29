"""WebUI regressions for two bugs that both looked like "the page didn't refresh".

1. lm#486 -- switching tenants left "My Devices" showing the PREVIOUS tenant.
   The page did refetch. ``window._mdFilter`` (the Managed Devices tenant tab
   filter) lives on window so the tab handlers survive re-renders -- which also
   means it survived a TENANT switch. For a Global Admin ``_devEndpoint()``
   returns the bare ``/setup/*`` path with no ``?tenant=``, so the fetch carries
   EVERY tenant's devices; the self-heal in ``loadAllDevices`` only clears a
   filter whose tenant owns no device, so it could never fire -- the old tenant
   still owned devices. Fresh data, re-filtered straight back to the old tenant.

2. lm#487 -- with a Credential Vault dialog open, the footer "Bug/Feature
   Request" button did nothing. ``openModal()`` builds a full-viewport
   ``fixed inset-0 ... z-50`` layer and the footer was an unpositioned block in
   normal flow, so the overlay covered the button; the click hit the backdrop,
   and for modals opened with ``{ backdropClose: true }`` (which the vault uses)
   it silently dismissed that dialog instead.

These are asserted against the real WebUI sources -- there is no JS runtime in
CI, and the z-index checks compare PARSED NUMBERS rather than matching literal
strings, so bumping any one layer without re-checking the others fails here.
"""
import os
import re

import pytest


def _repo_root():
    d = os.path.dirname(os.path.abspath(__file__))
    while d != "/":
        if os.path.isdir(os.path.join(d, "WebUI")):
            return d
        d = os.path.dirname(d)
    raise AssertionError("could not locate the repo root (no WebUI/ above this test)")


@pytest.fixture(scope="module")
def main_js():
    with open(os.path.join(_repo_root(), "WebUI", "main.js"), encoding="utf-8") as fh:
        return fh.read()


@pytest.fixture(scope="module")
def index_html():
    with open(os.path.join(_repo_root(), "WebUI", "index.html"), encoding="utf-8") as fh:
        return fh.read()


def _fn_body(src, header):
    """Return the source of the function starting at `header`, by brace balance."""
    start = src.index(header)
    i = src.index("{", start)
    depth, j = 0, i
    while j < len(src):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[start:j + 1]
        j += 1
    raise AssertionError(f"unbalanced braces after {header!r}")


def _z(class_attr):
    """Parse a Tailwind z-index (`z-50` or `z-[60]`) out of a class string."""
    m = re.search(r"\bz-\[(\d+)\]", class_attr) or re.search(r"\bz-(\d+)\b", class_attr)
    assert m, f"no z-index found in {class_attr!r}"
    return int(m.group(1))


# ── lm#486 ────────────────────────────────────────────────────────────────────

def test_set_tenant_repoints_managed_devices_tenant_filter(main_js):
    """The fix must live INSIDE setTenant -- that is the only place that knows
    the tenant changed. Asserting on the whole file would pass on a stray
    mention anywhere in 30k lines."""
    body = _fn_body(main_js, "async function setTenant(tenant)")
    assert "_mdFilter" in body, (
        "setTenant no longer re-points window._mdFilter.tenant -- lm#486 regressed: "
        "My Devices will stay filtered to the tenant you switched AWAY from."
    )
    m = re.search(r"_mdFilter\.tenant\s*=\s*(\w+)", body)
    assert m, "expected an assignment to _mdFilter.tenant inside setTenant"
    assert m.group(1) == "tenant", (
        f"_mdFilter.tenant is set to {m.group(1)!r}; it must be the `tenant` argument "
        "setTenant was called with, otherwise the list follows the wrong tenant."
    )


def test_set_tenant_repoint_happens_before_the_rerender(main_js):
    """Ordering matters: the re-render triggers loadAllDevices(), which reads the
    filter. Setting it afterwards would leave the first paint showing the old
    tenant."""
    body = _fn_body(main_js, "async function setTenant(tenant)")
    assert body.index("_mdFilter.tenant") < body.index("setSubView(currentSubView)"), (
        "the _mdFilter re-point must precede the sub-view/view re-render"
    )


def test_load_all_devices_keeps_the_empty_tenant_self_heal(main_js):
    """The re-point relies on this fallback: if the newly selected tenant owns no
    devices, the filter must drop back to 'all' rather than showing an empty list."""
    assert re.search(
        r"f\.tenant\s*!==\s*'all'\s*&&\s*!all\.some\(.*?_tenant.*?\)\s*\)\s*f\.tenant\s*=\s*'all'",
        main_js, re.S,
    ), "the loadAllDevices tenant self-heal is gone; the re-point can strand an empty list"


def test_filter_semantics_model_reproduces_the_stale_tenant_bug():
    """Executable model of the real filter semantics, proving WHY the self-heal
    could not save us: for a Global Admin the fetch is unscoped, so the old
    tenant still owns devices and the filter is never cleared."""
    def self_heal(f, devices):
        if f["tenant"] != "all" and not any(d["_tenant"] == f["tenant"] for d in devices):
            f["tenant"] = "all"

    def visible(f, devices):
        return [d["n"] for d in devices if f["tenant"] == "all" or d["_tenant"] == f["tenant"]]

    all_devices = [{"n": "lrb-fw", "_tenant": "lrb"}, {"n": "dxp-fw", "_tenant": "dxp"}]

    stale = {"tenant": "lrb"}          # user was on lrb, switches to dxp
    self_heal(stale, all_devices)
    assert stale["tenant"] == "lrb", "self-heal must NOT fire -- lrb still owns a device"
    assert visible(stale, all_devices) == ["lrb-fw"], "this is the bug users reported"

    fixed = {"tenant": "lrb"}
    fixed["tenant"] = "dxp"            # the fix
    self_heal(fixed, all_devices)
    assert visible(fixed, all_devices) == ["dxp-fw"]

    empty = {"tenant": "lrb"}
    empty["tenant"] = "newtenant"      # a tenant that owns nothing
    self_heal(empty, all_devices)
    assert empty["tenant"] == "all", "self-heal must rescue a tenant with no devices"
    assert visible(empty, all_devices) == ["lrb-fw", "dxp-fw"]


# ── lm#487 ────────────────────────────────────────────────────────────────────

def test_footer_sits_above_modal_overlays(index_html, main_js):
    """The footer must out-stack openModal()'s overlay, or the Bug/Feature
    Request button is unclickable whenever any dialog is open."""
    m = re.search(r"<footer[^>]*class=\"([^\"]+)\"", index_html)
    assert m, "could not find the <footer> element"
    footer_z = _z(m.group(1))

    om = re.search(r"modal\.className\s*=\s*'fixed inset-0 bg-black/50[^']*'", main_js)
    assert om, "could not find openModal()'s overlay className"
    overlay_z = _z(om.group(0))

    assert footer_z > overlay_z, (
        f"footer z-index ({footer_z}) must exceed the modal overlay ({overlay_z}); "
        "otherwise the overlay swallows the Bug/Feature Request click (lm#487)"
    )


def test_footer_is_positioned_so_z_index_applies(index_html):
    """z-index is inert on a `position: static` box. Without `relative` the class
    would look right and do nothing."""
    m = re.search(r"<footer[^>]*class=\"([^\"]+)\"", index_html)
    classes = m.group(1).split()
    assert any(c in ("relative", "absolute", "fixed", "sticky") for c in classes), (
        "the footer needs a positioning class for its z-index to take effect"
    )


def test_bug_modal_opens_above_the_dialog_being_reported(main_js, index_html):
    """The report window must out-stack both the dialog under it and the footer."""
    body = _fn_body(main_js, "async function fileBug(prefill = '')")
    m = re.search(r"modal\.className\s*=\s*'([^']+)'", body)
    assert m, "could not find the file-bug modal className"
    bug_z = _z(m.group(1))

    om = re.search(r"modal\.className\s*=\s*'fixed inset-0 bg-black/50[^']*'", main_js)
    overlay_z = _z(om.group(0))
    footer_z = _z(re.search(r"<footer[^>]*class=\"([^\"]+)\"", index_html).group(1))

    assert bug_z > overlay_z, (
        f"the bug modal ({bug_z}) must render above an open dialog ({overlay_z}), "
        "or the report window opens behind whatever the user is reporting"
    )
    assert bug_z > footer_z, (
        f"the bug modal ({bug_z}) must render above the footer ({footer_z}), "
        "or the raised footer draws on top of the report window"
    )


def test_footer_bug_button_still_calls_file_bug(index_html):
    """Guard the entry point itself -- the stacking fix is pointless if the
    handler is renamed or dropped."""
    assert 'onclick="fileBug()"' in index_html, "the footer Bug/Feature Request button is gone"
