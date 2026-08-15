"""Console port listing must follow the tenant model.

Regression + model guard for ``/api/console/ports``:

  * DEDICATED agent → all its ports are that tenant's; they must NOT appear
    under another tenant (the reported leak: an "LRB" console server showing
    devices under every tenant).
  * SHARED agent (tenant flagged ``shared: True``) → visible to every tenant but
    each port is subnet-masked by its device IP → disposition ``"mask"``.
  * UNASSIGNED → admin-only holding state, only in the global ("All") view.
  * A per-port override pins one shared device to a tenant → behaves dedicated.

``_console_port_disposition`` is the single pure predicate the route uses to
pick show / mask / hide; it's extracted via AST (like the other route-logic
tests) so we don't import the whole hub app. The subnet mask itself
(``filter_record_by_prefixes``) is covered by the tenant-filter tests.
"""
import ast
import os

_CONSOLE = os.path.join(os.path.dirname(__file__), "..", "src", "routes", "console.py")


def _load_disposition():
    src = open(_CONSOLE).read()
    mod = ast.parse(src)
    fn = next(n for n in mod.body
             if isinstance(n, ast.FunctionDef) and n.name == "_console_port_disposition")
    ns = {}
    exec(compile(ast.Module(body=[fn], type_ignores=[]), "<console>", "exec"), ns)
    return ns["_console_port_disposition"]


disp = _load_disposition()


# ── Admin ────────────────────────────────────────────────────────────────────
def test_admin_global_view_shows_every_kind():
    # sel None == picker on default/global. Admin is visible to everything.
    assert disp(True, True, "lrb", None, False) == "show"   # dedicated
    assert disp(True, True, "shared", None, True) == "show"  # shared, unmasked
    assert disp(True, True, "", None, False) == "show"       # unassigned


def test_admin_selected_tenant_hides_other_dedicated():
    # THE bug: an LRB-bound port must not show while viewing ACME.
    assert disp(True, True, "lrb", "acme", False) == "hide"
    assert disp(True, True, "acme", "acme", False) == "show"


def test_admin_selected_tenant_masks_shared():
    # Shared infra shows under the selected tenant, but subnet-masked.
    assert disp(True, True, "shared", "acme", True) == "mask"


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


def test_nonadmin_shared_is_masked_not_shown_wholesale():
    # Shared is visible to everyone but must be subnet-masked, never full.
    assert disp(False, True, "shared", None, True) == "mask"
    assert disp(False, True, "shared", "lrb", True) == "mask"


def test_nonadmin_never_sees_unassigned():
    assert disp(False, False, "", "lrb", False) == "hide"
    assert disp(False, False, "", None, False) == "hide"


# ── Per-port override pins a shared device to a tenant (dedicated behaviour) ──
def test_override_pins_shared_device_to_tenant():
    # eff is the OVERRIDE tenant (not shared) → dedicated exact-match, no mask.
    assert disp(True, True, "lrb", "lrb", False) == "show"
    assert disp(True, True, "lrb", "acme", False) == "hide"
    assert disp(False, True, "lrb", "lrb", False) == "show"
