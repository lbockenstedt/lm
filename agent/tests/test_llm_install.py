"""Verify offline serving bundle provisioning without touching a host runtime."""

import hashlib
import io
import os
import stat
import tarfile
from pathlib import Path

import pytest

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
