"""Console port listing must follow the tenant model.

Regression + model guard for ``/api/console/ports``:

  * DEDICATED agent → all its ports are that tenant's; they must NOT appear
    under another tenant (the reported leak: an "LRB" console server showing
    devices under every tenant).
  * SHARED agent (tenant flagged ``shared: True``) → its ports are the shared
    tenant's: shown under ADMIN, the shared tenant and groups containing it,
    never routed to another tenant by the device IP.
  * UNASSIGNED → admin-only holding state, only in the global ("All") view.
  * A per-port override pins one shared device to a tenant → behaves dedicated.

``_console_port_disposition`` is the single pure predicate the route uses to
pick show / hide; it's extracted via AST (like the other route-logic tests) so
we don't import the whole hub app.
"""
import ast
import os
import types

_CONSOLE = os.path.join(os.path.dirname(__file__), "..", "src", "routes", "console.py")


def _load():
    src = open(_CONSOLE).read()
    mod = ast.parse(src)
    fns = [n for n in mod.body if isinstance(n, ast.FunctionDef)
           and n.name in ("_console_port_disposition", "_console_tenant_in")]
    # Stub the access attributes the predicates read rather than importing the
    # whole access module (which pulls in the hub).
    ns = {"access": types.SimpleNamespace(
        ADMIN_TENANT_ID="default",
        _norm_tenant_id=lambda t: "" if t is None else str(t).strip().casefold(),
        _GROUP_MEMBERS={"group:ssplm": {"default", "shared"}})}
    exec(compile(ast.Module(body=fns, type_ignores=[]), "<console>", "exec"), ns)
    return ns["_console_port_disposition"], ns["_console_tenant_in"]


_disp, tenant_in = _load()


def disp(admin, visible, eff, sel, shared):
    return _disp(admin, visible, eff, sel, shared, tenant_in(eff, sel))


# ── Admin ────────────────────────────────────────────────────────────────────
def test_admin_global_view_shows_every_kind():
    # sel None == a genuinely unscoped (programmatic) call, not the picker.
    assert disp(True, True, "lrb", None, False) == "show"   # dedicated
    assert disp(True, True, "shared", None, True) == "show"  # shared, unmasked
    assert disp(True, True, "", None, False) == "show"       # unassigned


# ── ADMIN/Default scope ("default" is the ADMIN tenant, not "All") ───────────
def test_admin_default_hides_other_tenants_dedicated():
    # THE reported bug: with ADMIN/Default picked, the Console listed EVERY
    # tenant's ports. Dedicated data belongs wholly to its own tenant.
    assert disp(True, True, "lrb", "default", False) == "hide"
    assert disp(True, True, "acme", "default", False) == "hide"


def test_admin_default_shows_unassigned_and_default_bound():
    # Unassigned is the ADMIN holding state; a port explicitly bound to the
    # ADMIN tenant obviously belongs to it.
    assert disp(True, True, "", "default", False) == "show"
    assert disp(True, True, "default", "default", False) == "show"


def test_admin_default_shows_shared_unmasked():
    # The ADMIN tenant owns no NetBox prefixes, so masking there fails closed
    # and would hide every shared console server from the admin.
    assert disp(True, True, "shared", "default", True) == "show"


def test_admin_selected_tenant_hides_other_dedicated():
    # THE bug: an LRB-bound port must not show while viewing ACME.
    assert disp(True, True, "lrb", "acme", False) == "hide"
    assert disp(True, True, "acme", "acme", False) == "show"


def test_shared_port_never_routed_to_another_tenant():
    # The reported leak: an SSPLM (shared) console port whose device IP lies in
    # a DXP prefix of another VRF showed under DXP. The tenant decides, not the IP.
    assert disp(True, True, "shared", "dxp", True) == "hide"
    assert disp(False, True, "shared", "dxp", True) == "hide"


def test_shared_port_shows_under_shared_and_its_group():
    assert disp(True, True, "shared", "shared", True) == "show"
    assert disp(True, True, "shared", "group:ssplm", True) == "show"
    assert disp(True, True, "default", "group:SSPLM", False) == "show"
    assert disp(True, True, "dxp", "group:ssplm", False) == "hide"


def test_admin_selected_tenant_hides_unassigned():
    # Unassigned belongs to no tenant → not under a specific tenant.
    assert disp(True, True, "", "acme", False) == "hide"


# ── Non-admin (``visible`` = access.spoke_visible_to_session) ─────────────────
def test_nonadmin_sees_own_dedicated_only():
    assert disp(False, True, "lrb", "lrb", False) == "show"
    assert disp(False, True, "lrb", None, False) == "show"


def test_nonadmin_other_dedicated_hidden():
    # spoke_visible_to_session already returned False for a foreign tenant.
    assert disp(False, False, "acme", "lrb", False) == "hide"


def test_nonadmin_shared_hidden_outside_shared_tenant():
    assert disp(False, True, "shared", None, True) == "hide"
    assert disp(False, True, "shared", "lrb", True) == "hide"


def test_nonadmin_never_sees_unassigned():
    assert disp(False, False, "", "lrb", False) == "hide"
    assert disp(False, False, "", None, False) == "hide"


# ── Per-port override pins a shared device to a tenant (dedicated behaviour) ──
def test_override_pins_shared_device_to_tenant():
    # eff is the OVERRIDE tenant (not shared) → dedicated exact-match.
    assert disp(True, True, "lrb", "lrb", False) == "show"
    assert disp(True, True, "lrb", "acme", False) == "hide"
    assert disp(False, True, "lrb", "lrb", False) == "show"
