"""Stage an explicitly approved offline serving bundle on a fresh worker."""

import hashlib
import json
import re
import sys
import tarfile
import tempfile
from pathlib import Path


def stage_bundle(source, digest, destination):
    """Verify the archive before unpacking it, and never replace a runtime."""
    if not re.fullmatch(r"[a-f0-9]{64}", digest):
        raise ValueError("Supply the trusted SHA-256 of the entire serving bundle")
    if destination.is_symlink():
        raise ValueError("The serving runtime path must not be a symlink")
    if destination.exists():
        marker = destination / "bundle.json"
        if marker.is_file() and json.loads(marker.read_text(encoding="utf-8")) == {"sha256": digest}:
            return
        raise ValueError("A serving runtime already exists; the installer does not upgrade it")

    # Verify a private snapshot so the bytes extracted are exactly the bytes hashed.
    with tempfile.TemporaryDirectory(dir=destination.parent) as temp:
        root = Path(temp)
        snapshot = root / "bundle.tar"
        tree = root / "runtime"
        tree.mkdir(mode=0o755)
        checksum = hashlib.sha256()
        with source.open("rb") as incoming, snapshot.open("wb") as saved:
            while chunk := incoming.read(1024 * 1024):
                checksum.update(chunk)
                saved.write(chunk)
        if checksum.hexdigest() != digest:
            raise ValueError("Serving bundle SHA-256 mismatch")

        # An offline package needs only directories and plain files, never links or devices.
        with tarfile.open(snapshot) as archive:
            for entry in archive:
                path = Path(entry.name)
                if path.is_absolute() or ".." in path.parts or not (entry.isfile() or entry.isdir()):
                    raise ValueError("Bundle must contain only regular files and directories within its root")
                if path.parts and path.parts[0] not in {"bin", "lib", "models", "llm-models.json"}:
                    raise ValueError("Unexpected entry at the root of the serving bundle")
                if entry.isdir():
                    (tree / path).mkdir(parents=True, exist_ok=True)
                    continue
                target = tree / path
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(entry) as data, target.open("xb") as output:
                    while chunk := data.read(1024 * 1024):
                        output.write(chunk)
                target.chmod(0o755 if entry.mode & 0o111 else 0o644)

        # Require a catalog and a preloaded store; the worker rechecks exact model digests.
        binary, catalog = tree / "bin/ollama", tree / "llm-models.json"
        if not binary.is_file() or not binary.stat().st_mode & 0o111 or not catalog.is_file():
            raise ValueError("Bundle must contain executable bin/ollama and llm-models.json")
        allowed = json.loads(catalog.read_text(encoding="utf-8"))
        if not isinstance(allowed, dict) or not allowed or any(
                not name or not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value)
                for name, value in allowed.items()):
            raise ValueError("Bundle catalog must map model names to exact SHA-256 digests")
        if not all((tree / "models" / part).is_dir() for part in ("manifests", "blobs")):
            raise ValueError("Bundle must include the preloaded Ollama model store")
        # Override only the store path; do not load environment from the archive.
        with (tree / "bundle.env").open("x", encoding="utf-8") as settings:
            settings.write(f"OLLAMA_MODELS={destination / 'models'}\n")
        (tree / "bundle.json").write_text(json.dumps({"sha256": digest}) + "\n", encoding="utf-8")
        # The DynamicUser service must be able to traverse the tree even with a restrictive installer umask.
        tree.chmod(0o755)
        for directory in tree.rglob("*"):
            if directory.is_dir():
                directory.chmod(0o755)
        tree.rename(destination)


if __name__ == "__main__":
    try:
        source, digest = sys.argv[1:]
        stage_bundle(Path(source), digest, Path("/opt/lm-llm"))
    except (OSError, ValueError, tarfile.TarError) as exc:
        sys.exit(f"LLM provisioning failed: {exc}")
