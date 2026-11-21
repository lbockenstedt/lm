"""Verify offline serving bundle provisioning without touching a host runtime."""

import hashlib
import io
import json
import os
import stat
import tarfile
from pathlib import Path

import pytest

from agent.src import llm_install
from agent.src import llm_activation
from agent.src.llm_install import stage_bundle


def _bundle(path, extra=None):
    """Create a small stand-in for an approved archive, with an optional invalid entry."""
    with tarfile.open(path, "w") as archive:
        for name, content in (
            ("bin/ollama", b"fixture binary"),
            ("llm-models.json", b'{"test:cpu":"' + b"a" * 64 + b'"}'),
            ("models/manifests/test", b"manifest"),
            ("models/blobs/test", b"model"),
        ):
            entry = tarfile.TarInfo(name)
            entry.size = len(content)
            entry.mode = 0o755 if name == "bin/ollama" else 0o644
            archive.addfile(entry, io.BytesIO(content))
        if extra is not None:
            archive.addfile(extra)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_offline_bundle_stages_only_once(tmp_path):
    """A repeated install preserves the existing runtime; another digest cannot replace it."""
    source, destination = tmp_path / "bundle.tar", tmp_path / "worker"
    digest = _bundle(source)
    previous_umask = os.umask(0o077)
    try:
        stage_bundle(source, digest, destination)
    finally:
        os.umask(previous_umask)
    assert (destination / "bin/ollama").read_bytes() == b"fixture binary"
    assert stat.S_IMODE((destination / "models/blobs").stat().st_mode) == 0o755
    assert (destination / "bundle.env").read_text() == f"OLLAMA_MODELS={destination}/models\n"
    stage_bundle(source, digest, destination)
    with pytest.raises(ValueError, match="does not upgrade"):
        stage_bundle(source, "b" * 64, destination)
    assert (destination / "models/blobs/test").read_bytes() == b"model"


@pytest.mark.parametrize("bad_bundle", ["digest", "outside path", "link", "environment"])
def test_rejected_offline_bundle_is_not_installed(tmp_path, bad_bundle):
    """Reject altered inputs and unsupported entries before publishing a runtime."""
    source, destination = tmp_path / "bundle.tar", tmp_path / "worker"
    extra = {
        "outside path": tarfile.TarInfo("../outside"),
        "link": tarfile.TarInfo("lib/link"),
        "environment": tarfile.TarInfo("bundle.env"),
    }.get(bad_bundle)
    if bad_bundle == "link":
        extra.type = tarfile.SYMTYPE
        extra.linkname = "/outside"
    digest = _bundle(source, extra)
    with pytest.raises(ValueError):
        stage_bundle(source, "0" * 64 if bad_bundle == "digest" else digest, destination)
    assert not destination.exists()
    assert not (tmp_path / "outside").exists()


def test_serving_unit_never_prunes_read_only_store():
    """Ollama 0.40.16 exits at startup when pruning cannot write the staged bundle store."""
    unit = (Path(__file__).resolve().parents[1] / "lm-llm-ollama.service").read_text(encoding="utf-8")
    assert "Environment=OLLAMA_NOPRUNE=1" in unit.splitlines()
    assert "ProtectSystem=strict" in unit.splitlines()


def test_units_listen_on_the_ports_the_role_calls():
    """The role and qualification reach each runtime only on its unit's loopback port."""
    from agent.src import llm_qualification, llm_spoke

    units = Path(__file__).resolve().parents[1]
    for name, port in (("lm-llm-ollama.service", llm_spoke.SERVING_PORT),
                       ("lm-llm-candidate.service", llm_qualification.PORT)):
        lines = (units / name).read_text(encoding="utf-8").splitlines()
        assert f"Environment=OLLAMA_HOST=127.0.0.1:{port}" in lines, name
    assert llm_qualification.BASELINE_PORT == llm_spoke.SERVING_PORT != llm_qualification.PORT


def test_candidate_bundle_is_runtime_only(tmp_path):
    """A candidate stages only its runtime; a bundled model store is refused."""
    source, destination = tmp_path / "candidate.tar", tmp_path / "candidate"
    with tarfile.open(source, "w") as archive:
        entry = tarfile.TarInfo("bin/ollama")
        entry.size, entry.mode = 7, 0o755
        archive.addfile(entry, io.BytesIO(b"trial-1"))
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    stage_bundle(source, digest, destination, serving=False)
    assert (destination / "bin/ollama").read_bytes() == b"trial-1"
    assert not (destination / "bundle.env").exists()
    with pytest.raises(ValueError, match="does not upgrade"):
        stage_bundle(source, "b" * 64, destination, serving=False)

    serving_source = tmp_path / "serving.tar"
    with pytest.raises(ValueError, match="Unexpected entry"):
        stage_bundle(serving_source, _bundle(serving_source), tmp_path / "other", serving=False)
    assert not (tmp_path / "other").exists()


def _public_release(entries):
    """Create an in-memory stand-in for a decompressed upstream release."""
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w") as archive:
        for name, kind, value in entries:
            entry = tarfile.TarInfo(name)
            if kind == "link":
                entry.type, entry.linkname = tarfile.SYMTYPE, value
                archive.addfile(entry)
            else:
                entry.mode = 0o755
                entry.size = len(value)
                archive.addfile(entry, io.BytesIO(value))
    data.seek(0)
    return data


def test_public_release_extracts_cpu_libraries_and_safe_links_only(tmp_path):
    """Preserve required flat CPU libraries without publishing GPU payloads."""
    archive = _public_release([
        ("bin/ollama", "file", b"binary"),
        ("lib/ollama/libggml.so.0", "file", b"library"),
        ("lib/ollama/libggml.so", "link", "libggml.so.0"),
        ("lib/ollama/cuda_v12/libcuda.so", "file", b"gpu"),
    ])
    llm_install._extract_public_cpu(archive, tmp_path)
    assert (tmp_path / "bin/ollama").read_bytes() == b"binary"
    assert (tmp_path / "lib/ollama/libggml.so").read_bytes() == b"library"
    assert not (tmp_path / "lib/ollama/cuda_v12").exists()


@pytest.mark.parametrize(("name", "target"), [
    ("lib/ollama/link", "../../outside"), ("lib/ollama/link", "/etc/passwd"),
    ("lib/ollama/link", "missing"), ("../outside", "libggml.so"),
])
def test_public_release_refuses_unsafe_archive_paths_and_links(tmp_path, name, target):
    """An archive cannot redirect the runtime or escape its private staging tree."""
    archive = _public_release([("bin/ollama", "file", b"binary"), (name, "link", target)])
    with pytest.raises((ValueError, FileNotFoundError)):
        llm_install._extract_public_cpu(archive, tmp_path)


def test_public_release_rejects_bad_digest_before_extraction(tmp_path, monkeypatch):
    """Unverified downloads cannot be unpacked or published."""
    monkeypatch.setattr(llm_install.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(llm_install.urllib.request, "build_opener",
                        lambda *_: type("Opener", (), {"open": lambda *_args, **_kw: io.BytesIO(b"bad")})())
    monkeypatch.setattr(llm_install.subprocess, "Popen", lambda *a, **k: pytest.fail("unverified extraction"))
    destination = tmp_path / "candidate"
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        llm_install.stage_public_runtime(destination)
    assert not destination.exists()


def _activation_fixture(tmp_path, monkeypatch, model="test:cpu", content=b"model data"):
    """Create one digest-pinned local candidate and an isolated runtime tree."""
    runtime = tmp_path / "candidate-runtime"
    runtime.mkdir()
    (runtime / "bundle.json").write_text(json.dumps({"sha256": "a" * 64}))
    store = tmp_path / "candidate-models"
    blobs = store / "blobs"
    blobs.mkdir(parents=True)
    blob = hashlib.sha256(content).hexdigest()
    (blobs / f"sha256-{blob}").write_bytes(content)
    manifest = json.dumps({"config": {"digest": f"sha256:{blob}"}, "layers": []}).encode()
    name, tag = model.split(":")
    manifest_path = store / "manifests" / "registry.ollama.ai" / "library" / name / tag
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_bytes(manifest)
    monkeypatch.setattr(llm_activation, "CANDIDATE_RUNTIME", runtime)
    monkeypatch.setattr(llm_activation, "CANDIDATE_STORE", store)
    monkeypatch.setattr(llm_activation, "SERVING_RUNTIME", tmp_path / "serving")
    monkeypatch.setattr(llm_activation, "EXTERNAL_CATALOG", tmp_path / "operator-catalog.json")
    return {"model": model, "digest": hashlib.sha256(manifest).hexdigest()}


def test_activation_approves_only_after_serving_probe_and_can_rollback(tmp_path, monkeypatch):
    """A staged artifact remains unroutable until its exact digest is verified."""
    candidate = _activation_fixture(tmp_path, monkeypatch)
    record = llm_activation.publish(candidate, "a" * 64)
    catalog = llm_activation.SERVING_RUNTIME / "llm-models.json"
    assert json.loads(catalog.read_text()) == {}
    llm_activation.finalize(record)
    assert json.loads(catalog.read_text()) == {candidate["model"]: candidate["digest"]}
    llm_activation.rollback(record)
    assert not llm_activation.SERVING_RUNTIME.exists()


def test_activation_rejects_corrupt_blob_and_operator_catalog(tmp_path, monkeypatch):
    """Neither altered weights nor an overriding operator catalog can be activated."""
    candidate = _activation_fixture(tmp_path, monkeypatch)
    blob = next((llm_activation.CANDIDATE_STORE / "blobs").iterdir())
    blob.write_bytes(b"corrupt")
    with pytest.raises(ValueError, match="blob digest mismatch"):
        llm_activation.publish(candidate, "a" * 64)
    assert not llm_activation.SERVING_RUNTIME.exists()
    llm_activation.EXTERNAL_CATALOG.write_text("{}")
    with pytest.raises(ValueError, match="operator-managed"):
        llm_activation.publish(candidate, "a" * 64)


def test_activation_rejects_symlinked_manifest_directory(tmp_path, monkeypatch):
    """A candidate store cannot redirect publication outside its own tree."""
    candidate = _activation_fixture(tmp_path, monkeypatch)
    library = llm_activation.CANDIDATE_STORE / "manifests" / "registry.ollama.ai" / "library"
    moved = tmp_path / "moved"
    library.rename(moved)
    library.symlink_to(moved)
    with pytest.raises(ValueError, match="model store directory"):
        llm_activation.publish(candidate, "a" * 64)
    assert not llm_activation.SERVING_RUNTIME.exists()


def test_additive_activation_rollback_preserves_existing_catalog(tmp_path, monkeypatch):
    """Rolling back a second model must retain the first approved model."""
    first = _activation_fixture(tmp_path, monkeypatch)
    record = llm_activation.publish(first, "a" * 64)
    llm_activation.finalize(record)
    store = llm_activation.CANDIDATE_STORE
    data = b"second model"
    digest = hashlib.sha256(data).hexdigest()
    (store / "blobs" / f"sha256-{digest}").write_bytes(data)
    manifest = json.dumps({"config": {"digest": f"sha256:{digest}"}, "layers": []}).encode()
    manifest_path = store / "manifests" / "registry.ollama.ai" / "library" / "second" / "cpu"
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_bytes(manifest)
    second = {"model": "second:cpu", "digest": hashlib.sha256(manifest).hexdigest()}
    record = llm_activation.publish(second, "a" * 64)
    llm_activation.finalize(record)
    llm_activation.rollback(record)
    catalog = llm_activation.SERVING_RUNTIME / "llm-models.json"
    assert json.loads(catalog.read_text()) == {first["model"]: first["digest"]}
    assert not (llm_activation.SERVING_RUNTIME / "models" / "blobs" / f"sha256-{digest}").exists()
    assert len(list((llm_activation.SERVING_RUNTIME / "models" / "blobs").iterdir())) == 1
    assert not (llm_activation.SERVING_RUNTIME / "models" / "manifests" /
                "registry.ollama.ai" / "library" / "second" / "cpu").exists()


def test_additive_activation_cleans_blobs_when_publication_fails(tmp_path, monkeypatch):
    """A failed manifest link must not strand the model blob."""
    first = _activation_fixture(tmp_path, monkeypatch)
    record = llm_activation.publish(first, "a" * 64)
    llm_activation.finalize(record)
    store = llm_activation.CANDIDATE_STORE
    data = b"second model"
    digest = hashlib.sha256(data).hexdigest()
    (store / "blobs" / f"sha256-{digest}").write_bytes(data)
    manifest = json.dumps({"config": {"digest": f"sha256:{digest}"}, "layers": []}).encode()
    path = store / "manifests" / "registry.ollama.ai" / "library" / "second" / "cpu"
    path.parent.mkdir(parents=True)
    path.write_bytes(manifest)
    second = {"model": "second:cpu", "digest": hashlib.sha256(manifest).hexdigest()}
    real_link = llm_activation.os.link

    def fail_manifest_link(source, destination, **kwargs):
        """Simulate a filesystem error after the new blob was linked."""
        if Path(destination).name == "cpu":
            raise OSError("synthetic link failure")
        return real_link(source, destination, **kwargs)

    monkeypatch.setattr(llm_activation.os, "link", fail_manifest_link)
    with pytest.raises(OSError, match="synthetic link failure"):
        llm_activation.publish(second, "a" * 64)
    blobs = llm_activation.SERVING_RUNTIME / "models" / "blobs"
    assert not (blobs / f"sha256-{digest}").exists()
    assert len(list(blobs.iterdir())) == 1
