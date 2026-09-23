"""The Credential Vault audit lines must name the acting user.

``_actor`` read ``user.username`` / ``user.id``, but a login session stores the
id as ``user_id`` (routes/auth.py), so every move / delete / reveal was logged
``by ?``. The other route tests stub ``_actor`` out, which hid it — this lifts
the real closure with ``ast`` and runs it against the real session shape.
"""
import ast
import os

_CV_ROUTES = os.path.join(os.path.dirname(__file__), "..", "src", "routes", "cred_vault.py")


def _actor():
    tree = ast.parse(open(_CV_ROUTES).read())
    ns = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_actor":
            exec(compile(ast.Module(body=[node], type_ignores=[]), _CV_ROUTES, "exec"), ns)
            return ns["_actor"]
    raise AssertionError("_actor not found in routes/cred_vault.py")


def test_actor_reads_login_session_user_id():
    # Shape written by the login route: user_data = {"user_id": ..., ...}
    sess = {"user": {"user_id": "gadmin", "tenants": [], "protected": True}}
    assert _actor()(sess) == "gadmin"


def test_actor_falls_back_to_top_level_user_id():
    assert _actor()({"user_id": "gadmin", "user": {}}) == "gadmin"


def test_actor_keeps_legacy_keys():
    assert _actor()({"user": {"username": "legacy"}}) == "legacy"


def test_actor_unknown_session_is_question_mark():
    assert _actor()({}) == "?"
    assert _actor()(None) == "?"
