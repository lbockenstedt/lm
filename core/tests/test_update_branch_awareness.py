"""Dev/QA instances must track the branch they are DEPLOYED from.

The hub can be pointed at a non-main branch via ``global_config.global_branch``
(that is what makes a dev or qa instance possible), and the deploy/update path
already honours it. The GitHub VERSION lookup did not: it called
``_fetch_github_version(repo)`` with the ``branch="main"`` default, so a dev
instance compared its own VERSION against *main's* VERSION and reported
bogus "up to date" / "behind" status.

These tests pin the branch actually used, and -- importantly -- that
``_configured_branch`` reads the real state API. An earlier version of the fix
called a state accessor that does not exist; the broad ``except`` swallowed the
AttributeError and returned "main", so the bug looked fixed while the code still
always read main.
"""
import ast
import os
import sys

_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "src", "update_pipeline.py")


def _pipeline_class():
    """Extract _configured_branch + the VERSION URL helpers without importing
    update_pipeline (it drags in the whole hub). Keeps this test fast and free
    of the sys.path mutation that breaks sibling test modules."""
    tree = ast.parse(open(_SRC).read())
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "_configured_branch")
    url = next(n for n in ast.walk(tree)
               if isinstance(n, ast.FunctionDef) and n.name == "_github_version_url")
    ns = {"_GITHUB_OWNER": "lbockenstedt"}
    mod = ast.Module(body=[url], type_ignores=[])
    exec(compile(ast.fix_missing_locations(mod), "<x>", "exec"), ns)
    cls = ast.ClassDef(name="P", bases=[], keywords=[], body=[fn],
                       decorator_list=[])
    mod2 = ast.Module(body=[cls], type_ignores=[])
    exec(compile(ast.fix_missing_locations(mod2), "<x>", "exec"), ns)
    return ns["P"], ns["_github_version_url"]


class _State:
    def __init__(self, cfg):
        self._cfg = cfg

    def get_global_config(self):
        return self._cfg


def test_configured_branch_uses_real_state_api():
    """Guards the silent-fallback trap: a wrong accessor would still return
    'main' via the except branch, so assert the configured value comes back."""
    P, _ = _pipeline_class()
    p = P()
    p.state = _State({"global_branch": "dev"})
    assert p._configured_branch() == "dev"


def test_qa_branch_is_honoured():
    P, _ = _pipeline_class()
    p = P()
    p.state = _State({"global_branch": "qa"})
    assert p._configured_branch() == "qa"


def test_defaults_to_main_when_unset_or_blank():
    P, _ = _pipeline_class()
    for cfg in ({}, {"global_branch": ""}, {"global_branch": None}):
        p = P()
        p.state = _State(cfg)
        assert p._configured_branch() == "main"


def test_never_raises_when_state_is_broken():
    """Version refresh is best-effort; a broken state must degrade to main."""
    P, _ = _pipeline_class()

    class Boom:
        def get_global_config(self):
            raise RuntimeError("state unavailable")

    p = P()
    p.state = Boom()
    assert p._configured_branch() == "main"


def test_version_url_points_at_the_requested_branch():
    _, url = _pipeline_class()
    assert url("lm", "lbockenstedt", "qa").endswith("/lbockenstedt/lm/qa/VERSION")
    assert url("lm", "lbockenstedt", "main").endswith("/lbockenstedt/lm/main/VERSION")


def test_refresh_passes_branch_to_fetch():
    """The regression itself: the call site must forward a branch argument."""
    src = open(_SRC).read()
    tree = ast.parse(src)
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
              and n.name == "_refresh_github_version")
    calls = [n for n in ast.walk(fn)
             if isinstance(n, ast.Call) and any(
                 isinstance(a, ast.Name) and a.id == "_fetch_github_version"
                 for a in ast.walk(n))]
    assert calls, "_refresh_github_version no longer calls _fetch_github_version"
    # to_thread(_fetch_github_version, repo, owner, branch) -> 4 args
    assert any(len(c.args) >= 4 for c in calls), (
        "_fetch_github_version is called without an explicit branch; a dev/qa "
        "instance would read main's VERSION")
