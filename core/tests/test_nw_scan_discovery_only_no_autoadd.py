"""A credential-free ("discovery-only") scan must never auto-add devices.

Scan credentials became optional: with none selected the nw spoke still runs a
discovery pass and turns nmap service detection ON, because nmap is then the
only way left to classify a host. nmap CAN assign a manageable ``object_type``
(``nw_scanner._fingerprint`` sets ``method="nmap"``), so the auto-add loop in
``routes/nw.py`` would happily write fleet devices with an empty username and no
``vault_credential`` — entries the fleet can never actually manage, and a direct
contradiction of the documented "a credential-free scan is preview-only"
guarantee. Those devices belong in ``preview``, exactly like a dry run.

The route body lives inline inside ``register()`` and cannot be imported, so
this extracts the real decision region from the source and executes it against
fakes — the same pattern the automerge tests use.
"""
import re
import textwrap
import uuid
from pathlib import Path

NW_ROUTES = Path(__file__).resolve().parents[1] / "src" / "routes" / "nw.py"

_SCAN_OBJECT_TYPES = {"switch", "router", "firewall"}


def _decision_source() -> str:
    src = NW_ROUTES.read_text(encoding="utf-8")
    start = src.index('        dry_run = bool(data.get("dry_run", True))')
    end = src.index("        if added:", start)
    return textwrap.dedent(src[start:end])


def _run(identified, *, push_creds, dry_run_req=True, auto_add=False):
    """Execute the real dry-run/auto-add decision. Returns (added, preview)."""
    ns = {
        "data": {"dry_run": dry_run_req, "auto_add": auto_add},
        "saved": {},
        "identified": identified,
        "push_creds": push_creds,
        "chosen": push_creds,
        "by_cred": {c.get("id"): c for c in push_creds},
        "known": set(),
        "devices": [],
        "tenant_id": "tenant-lrb",
        "spoke_id": "nw-lrb",
        "uuid": uuid,
        "_SCAN_OBJECT_TYPES": _SCAN_OBJECT_TYPES,
    }
    exec(_decision_source(), ns)
    return ns["added"], ns["preview"], ns["dry_run"]


_NMAP_HIT = {"address": "10.1.1.5", "hostname": "sw1", "object_type": "switch",
             "os": "", "method": "nmap", "credential_id": None}
_SSH_HIT = {"address": "10.1.1.6", "hostname": "sw2", "object_type": "switch",
            "os": "", "method": "ssh", "credential_id": "cred-1"}
_CRED = {"id": "cred-1", "username": "admin", "vault_credential": "kv://nw/sw"}


def test_credential_free_scan_never_auto_adds():
    added, preview, dry_run = _run([_NMAP_HIT], push_creds=[],
                                   dry_run_req=False, auto_add=True)
    assert dry_run is True, "no credentials must force preview-only"
    assert added == []
    assert [d["address"] for d in preview] == ["10.1.1.5"]


def test_credentialed_scan_still_auto_adds():
    added, preview, dry_run = _run([_SSH_HIT], push_creds=[_CRED],
                                   dry_run_req=False, auto_add=True)
    assert dry_run is False
    assert [d["address"] for d in added] == ["10.1.1.6"]
    assert preview == []
    # The winning credential set's vault reference rides along, which is exactly
    # what a credential-free add could never supply.
    assert added[0]["vault_credential"] == "kv://nw/sw"
    assert added[0]["username"] == "admin"


def test_credentialed_scan_still_honours_an_explicit_dry_run():
    added, preview, _ = _run([_SSH_HIT], push_creds=[_CRED],
                             dry_run_req=True, auto_add=True)
    assert added == []
    assert [d["address"] for d in preview] == ["10.1.1.6"]


def test_credentialed_scan_still_honours_auto_add_off():
    added, preview, _ = _run([_SSH_HIT], push_creds=[_CRED],
                             dry_run_req=False, auto_add=False)
    assert added == []
    assert [d["address"] for d in preview] == ["10.1.1.6"]


def test_unmanageable_object_types_are_never_offered():
    unknown = dict(_NMAP_HIT, address="10.1.1.7", object_type="server")
    added, preview, _ = _run([unknown], push_creds=[_CRED],
                             dry_run_req=False, auto_add=True)
    assert added == [] and preview == []


def test_docs_no_longer_claim_preview_only_by_construction():
    """The guarantee is enforced by the gate above, not by the object_type
    filter — nmap can set object_type, so the old wording was false."""
    doc = (Path(__file__).resolve().parents[2] / "docs" / "nw.md")
    if not doc.exists():                      # canonical copy lives in the nw repo
        return
    text = doc.read_text(encoding="utf-8")
    assert not re.search(r"inherently preview-only", text)
