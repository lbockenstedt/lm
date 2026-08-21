"""HTTPS-port scanner / invalid-connection detection.

The hub serves a FastAPI API + a static JS SPA on :443 and never serves
PHP/ASP/CGI, dotfiles, or DB-admin panels. A request for any of those is an
automated vulnerability scan; the SPA catch-all would otherwise answer 200
index.html and hide it. ``api._looks_like_probe`` classifies such paths, and the
access-control middleware records them as ``http_probe`` failures so the threat
monitor tallies + auto-blocks the source past threshold (trusted IPs exempt).

Part 1 tests the classifier (pure function). Part 2 tests that ``http_probe``
failures drive the SAME block + lifetime-tally machinery as every other kind.
"""
import importlib.util
import os
import sys

_SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

os.environ.setdefault("LM_FERNET_KEY", __import__("cryptography.fernet",
                      fromlist=["Fernet"]).Fernet.generate_key().decode())

import api  # noqa: E402


def _load_from_src(modname, relpath):
    target = os.path.join(_SRC, relpath)
    spec = importlib.util.spec_from_file_location(modname, target)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[modname] = mod
    spec.loader.exec_module(mod)
    return mod


_load_from_src("azure_nsg", "azure_nsg.py")
_tm = _load_from_src("security.threat_monitor", os.path.join("security", "threat_monitor.py"))
ThreatMonitor = _tm.ThreatMonitor


# ── Part 1: the classifier ──────────────────────────────────────────────────
def test_scanner_paths_are_flagged():
    for p in ["/wp-login.php", "/wordpress/wp-admin/", "/.env", "/.git/config",
              "/phpMyAdmin/index.php", "/xmlrpc.php", "/actuator/health",
              "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
              "/cgi-bin/test.cgi", "/.aws/credentials", "/adminer.php",
              "/solr/admin/", "/boaform/admin/formLogin", "/config.bak"]:
        assert api._looks_like_probe(p), p


def test_legitimate_paths_are_not_flagged():
    for p in ["/", "/index.html", "/assets/main.js?v=123", "/status",
              "/api/security/overview", "/vm/abc-123/details", "/setup/general",
              "/auth/login", "/tenant/x/dashboard", "/le/style.css",
              "/console/vm", "/.well-known/acme-challenge/tok"]:
        assert not api._looks_like_probe(p), p


def test_classifier_is_case_insensitive_and_null_safe():
    assert api._looks_like_probe("/WP-LOGIN.PHP")
    assert api._looks_like_probe("/PhpMyAdmin/")
    assert not api._looks_like_probe("")
    assert not api._looks_like_probe(None)


# ── Part 2: http_probe drives block + lifetime tally ────────────────────────
class _State:
    def __init__(self, data_dir, gc=None):
        self.data_dir = data_dir
        self.system_state = {"global_config": gc or {}}

    def _mark_dirty(self):
        pass


class _Hub:
    def __init__(self, state):
        self.state = state


def _tm_for(tmp_path, entries=None):
    return ThreatMonitor(_Hub(_State(str(tmp_path), {"azure_nsg": {"entries": entries or []}})))


def test_repeated_probes_block_the_scanner_and_tally():
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        tm = _tm_for(d)
        tm.set_config({"threshold": 5, "window_s": 600})
        for _ in range(6):                              # > threshold
            tm.record_failure("203.0.113.44", "http_probe", detail="GET /wp-login.php")
        assert "203.0.113.44" in tm._blocks
        rec = tm._blocks["203.0.113.44"]
        assert rec["kind"] == "http_probe"
        assert "scan probes" in rec["reason"]
        t = tm.snapshot()["totals"]
        assert t["by_kind"]["http_probe"] == 6
        assert t["blocks_placed"] == 1


def test_probe_from_trusted_ip_is_not_blocked():
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        tm = _tm_for(d, entries=[{"ip": "198.51.100.5/32", "description": "admin"}])
        tm.set_config({"threshold": 2, "window_s": 600})
        for _ in range(10):
            tm.record_failure("198.51.100.5", "http_probe", detail="GET /.env")
        assert "198.51.100.5" not in tm._blocks          # trusted → exempt
        assert tm.snapshot()["totals"]["by_kind"]["http_probe"] == 10  # still counted
