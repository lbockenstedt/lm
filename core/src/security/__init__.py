"""Hub security package (encryption, key manager, mTLS, OIDC, threat monitor).

A REGULAR package (this file) — not an implicit namespace package — so
``import security.*`` resolves here deterministically. Without it, the
namespace-package fallback loses to any plain ``security.py`` module found
later on ``sys.path`` (e.g. ``core/src/routes/security.py`` when the test
suite appends ``core/src/routes`` for direct route-module imports), which
broke ``from security.key_manager import ...`` with "'security' is not a
package" depending on import order.
"""
