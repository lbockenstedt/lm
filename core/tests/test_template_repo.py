"""Tests for TemplateRepo — the hub-local Proxmox template-backup store."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from template_repo import TemplateRepo  # noqa: E402


def test_create_pending_returns_token_and_lists_public(tmp_path):
    r = TemplateRepo(str(tmp_path))
    rec = r.create_pending(name="sim-t2", source_vmid=9001, source_node="pxmx",
                           source_agent="a1", source_spoke="cs-1", created_by="admin")
    assert rec["status"] == "pending" and rec["_upload_token"]
    # public view (list/get) never exposes the token
    pub = r.list()
    assert len(pub) == 1 and "_upload_token" not in pub[0]
    assert "_upload_token" not in r.get(rec["id"])


def test_token_verify_and_consume_on_finalize(tmp_path):
    r = TemplateRepo(str(tmp_path))
    rec = r.create_pending(name="t", source_vmid=1, source_node="n", source_agent="a",
                           source_spoke="s", created_by="admin")
    tid, tok = rec["id"], rec["_upload_token"]
    assert r.verify_token(tid, tok)
    assert not r.verify_token(tid, "wrong")
    assert not r.verify_token(tid, "")
    r.finalize(tid, size=100, sha256="abc")
    assert not r.verify_token(tid, tok)  # one-time token consumed
    g = r.get(tid)
    assert g["status"] == "complete" and g["size"] == 100 and g["sha256"] == "abc" and g["progress"] == 100


def test_update_meta_only_allows_editable_fields(tmp_path):
    r = TemplateRepo(str(tmp_path))
    tid = r.create_pending(name="t", source_vmid=1, source_node="n", source_agent="a",
                           source_spoke="s", created_by="admin")["id"]
    r.update_meta(tid, {"version": "v3", "os": "Debian 12", "purpose": "golden",
                        "tenant": "acme", "status": "HACK", "sha256": "HACK", "id": "HACK"})
    g = r.get(tid)
    assert g["version"] == "v3" and g["os"] == "Debian 12" and g["purpose"] == "golden" and g["tenant"] == "acme"
    assert g["status"] == "pending" and g["sha256"] == "" and g["id"] == tid  # protected fields untouched


def test_reload_from_disk_and_delete(tmp_path):
    r = TemplateRepo(str(tmp_path))
    tid = r.create_pending(name="t", source_vmid=1, source_node="n", source_agent="a",
                           source_spoke="s", created_by="admin")["id"]
    r.update_meta(tid, {"version": "v9"})
    # a fresh instance recovers the record from meta.json on disk
    r2 = TemplateRepo(str(tmp_path))
    assert r2.get(tid)["version"] == "v9"
    assert r2.delete(tid) is True
    assert r2.get(tid) is None
    assert not os.path.isdir(os.path.join(str(tmp_path), "template-repo", tid))
    assert r2.delete("nonexistent") is False


def test_set_status_progress_clamped(tmp_path):
    r = TemplateRepo(str(tmp_path))
    tid = r.create_pending(name="t", source_vmid=1, source_node="n", source_agent="a",
                           source_spoke="s", created_by="admin")["id"]
    r.set_status(tid, "uploading", progress=150)
    assert r.get(tid)["progress"] == 100
    r.set_status(tid, "failed", error="boom", progress=-5)
    g = r.get(tid)
    assert g["status"] == "failed" and g["progress"] == 0 and g["error"] == "boom"
