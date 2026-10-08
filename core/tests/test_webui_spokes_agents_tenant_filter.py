"""Setup -> Spokes & Agents tenant-filter dropdown (WebUI/main.js,
``loadSpokesAndAgents`` / ``_saMatch``).

The reported bug: a Proxmox node agent deliberately assigned to a tenant (most
visibly the built-in ADMIN/``default`` tenant) did not always show up when that
tenant was selected in the picker. Root cause: the client-side filter matched a
pxmx node agent's EFFECTIVE tenant using only its owning SPOKE's raw binding
(``_spokeTenantById.get(a.spoke_id)``) and ignored the agent's own pinned
``client_simulation.tenant_id`` — the same per-agent override that the table's
DISPLAY label (``_tenantOf``) already honors. An agent pinned to a tenant other
than its (possibly shared/unassigned/differently-bound) spoke therefore showed
the right tenant label in the unfiltered table, yet vanished the moment that
tenant was selected in the filter.

These are lightweight source-presence checks (this repo's existing convention
for WebUI/main.js logic, see test_webui_loading_feedback.py / the drive-health
route's submenu test) plus a Node syntax check, since there's no JS execution
harness in this suite.
"""
import shutil
import subprocess
from pathlib import Path

WEBUI_JS = Path(__file__).resolve().parents[2] / "WebUI" / "main.js"


def _content():
    assert WEBUI_JS.exists(), f"WebUI/main.js not found at {WEBUI_JS}"
    return WEBUI_JS.read_text(encoding="utf-8")


def test_pxmx_agent_tenant_filter_prefers_the_agents_own_effective_tenant():
    """``pxmxAgentsF`` must match on the agent's own effective tenant (pin
    first, same precedence as the display label ``_tenantOf``), falling back
    to the owning spoke's binding only when the agent carries none."""
    content = _content()
    assert "const pxmxAgentsF    = pxmxAgents.filter(a => _saMatch(_tenantOf(a) || _spokeTenantById.get(a.spoke_id)));" in content
    # The old (buggy) pattern — spoke binding checked FIRST, ignoring the
    # per-agent pin entirely — must be gone.
    assert "_saMatch(_spokeTenantById.get(a.spoke_id) ?? a.tenant_id)" not in content


def test_js_syntax_valid():
    if not shutil.which("node"):
        import pytest
        pytest.skip("node not available")
    res = subprocess.run(["node", "--check", str(WEBUI_JS)], capture_output=True, text=True)
    assert res.returncode == 0, f"Node syntax error: {res.stderr}"
