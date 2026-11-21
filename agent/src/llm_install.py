"""Stage explicitly approved offline Ollama bundles on a fresh worker."""

import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from pathlib import Path, PurePosixPath

# The owner approved this tested release as the starting Linux CPU runtime.
PUBLIC_RUNTIME = {
    "x86_64": {
        "url": "https://github.com/ollama/ollama/releases/download/v0.40.16/ollama-linux-amd64.tar.zst",
        "sha256": "87bfafb2acbc89b2e6a1be0a9043de6aa75fb450696f86bc426e65fc448f788d",
        "max_bytes": 1_600_000_000,
    },
}
_RELEASE_HOSTS = {"github.com", "release-assets.githubusercontent.com"}
PUBLIC_RUNTIME_VERSION = "0.40.16"


class _ReleaseRedirect(urllib.request.HTTPRedirectHandler):
    """Keep release downloads on the approved HTTPS distribution hosts."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """Reject a redirect that leaves the trusted release delivery hosts."""
        from urllib.parse import urlsplit

        parsed = urlsplit(newurl)
        if parsed.scheme != "https" or parsed.hostname not in _RELEASE_HOSTS or parsed.port not in (None, 443):
            raise ValueError("Untrusted Ollama release redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _extract_public_cpu(stream, tree):
    """Extract only pinned release CPU files, with bounded entries and safe links."""
    links = []
    total = 0
    with tarfile.open(fileobj=stream, mode="r|") as archive:
        for count, entry in enumerate(archive, 1):
            if count > 10000 or entry.size < 0:
                raise ValueError("Invalid Ollama release archive")
            path = PurePosixPath(entry.name)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError("Unsafe path in Ollama release")
            selected = path.parts == ("bin", "ollama") or (
                len(path.parts) == 3 and path.parts[:2] == ("lib", "ollama"))
            if not selected:
                continue
            target = tree.joinpath(*path.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            if entry.issym():
                if "/" in entry.linkname or entry.linkname in ("", ".", ".."):
                    raise ValueError("Unsafe Ollama library link")
                links.append((target, entry.linkname))
            elif entry.isfile():
                total += entry.size
                if total > 512 * 1024 * 1024:
                    raise ValueError("Ollama CPU runtime exceeds the size limit")
                with archive.extractfile(entry) as incoming, target.open("xb") as output:
                    shutil.copyfileobj(incoming, output, length=1024 * 1024)
                target.chmod(0o755 if entry.mode & 0o111 else 0o644)
            else:
                raise ValueError("Unsupported Ollama CPU archive entry")
    for target, link in links:
        target.symlink_to(link)
    libraries = tree / "lib" / "ollama"
    for target, _ in links:
        try:
            resolved = target.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ValueError("Invalid Ollama library target") from exc
        if resolved.parent != libraries or not resolved.is_file():
            raise ValueError("Invalid Ollama library target")
    binary = tree / "bin" / "ollama"
    if not binary.is_file() or not binary.stat().st_mode & 0o111:
        raise ValueError("Ollama release has no executable CPU runtime")


def _ensure_zstd():
    """Install the archive decompressor only when it is absent on the worker."""
    if shutil.which("zstd"):
        return
    try:
        subprocess.run(["apt-get", "-o", "DPkg::Lock::Timeout=600", "install", "-y", "-qq", "zstd"],
                       check=True, timeout=1200, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                       env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"})
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError("Could not install the zstd prerequisite") from exc
    if not shutil.which("zstd"):
        raise ValueError("The installed zstd executable is unavailable")


def stage_public_runtime(destination):
    """Download and verify the owner-pinned Linux release without replacing a runtime."""
    spec = PUBLIC_RUNTIME.get(platform.machine())
    if spec is None:
        raise ValueError("No approved Ollama release for this CPU architecture")
    if destination.is_symlink() or destination.exists():
        marker = destination / "bundle.json"
        if (not destination.is_symlink() and marker.is_file()
                and json.loads(marker.read_text(encoding="utf-8")) == {"sha256": spec["sha256"]}):
            return
        raise ValueError("An Ollama runtime already exists; provisioning will not replace it")
    _ensure_zstd()
    with tempfile.TemporaryDirectory(dir=destination.parent) as temp:
        root = Path(temp)
        archive, tree = root / "release.tar.zst", root / "runtime"
        tree.mkdir(mode=0o755)
        digest, size = hashlib.sha256(), 0
        deadline = time.monotonic() + 3600
        opener = urllib.request.build_opener(_ReleaseRedirect())
        with opener.open(spec["url"], timeout=120) as incoming, archive.open("xb") as output:
            while chunk := incoming.read(1024 * 1024):
                size += len(chunk)
                if size > spec["max_bytes"]:
                    raise ValueError("Ollama release exceeds the size limit")
                if time.monotonic() > deadline:
                    raise TimeoutError("Ollama release download timed out")
                digest.update(chunk)
                output.write(chunk)
        if digest.hexdigest() != spec["sha256"]:
            raise ValueError("Ollama release SHA-256 mismatch")
        # The digest is checked before invoking the decompressor or parsing the archive.
        with subprocess.Popen(["zstd", "-dc", str(archive)], stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL) as process:
            try:
                _extract_public_cpu(process.stdout, tree)
                while process.stdout.read(1024 * 1024):
                    pass
                if process.wait(timeout=60):
                    raise ValueError("Could not decompress the Ollama release")
            except BaseException:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=10)
                raise
        (tree / "bundle.json").write_text(json.dumps({"sha256": spec["sha256"]}) + "\n", encoding="utf-8")
        tree.chmod(0o755)
        for directory in tree.rglob("*"):
            if directory.is_dir():
                directory.chmod(0o755)
        # Rename cannot replace a non-empty existing runtime; refuse all existing paths.
        if destination.exists() or destination.is_symlink():
            raise ValueError("An Ollama runtime appeared while provisioning")
        tree.rename(destination)


def stage_bundle(source, digest, destination, *, serving=True):
    """Verify the archive before unpacking it, and never replace a runtime.

    A serving bundle carries its approved model store; a qualification
    candidate carries only the runtime, because its unit pulls into a
    separate state store during the job.
    """
    if not re.fullmatch(r"[a-f0-9]{64}", digest):
        raise ValueError("Supply the trusted SHA-256 of the entire Ollama bundle")
    if destination.is_symlink():
        raise ValueError("The serving runtime path must not be a symlink")
    if destination.exists():
        marker = destination / "bundle.json"
        if marker.is_file() and json.loads(marker.read_text(encoding="utf-8")) == {"sha256": digest}:
            return
        raise ValueError("An Ollama runtime already exists; the installer does not upgrade it")

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
            raise ValueError("Ollama bundle SHA-256 mismatch")

        # An offline package needs only directories and plain files, never links or devices.
        roots = {"bin", "lib", "models", "llm-models.json"} if serving else {"bin", "lib"}
        with tarfile.open(snapshot) as archive:
            for entry in archive:
                path = Path(entry.name)
                if path.is_absolute() or ".." in path.parts or not (entry.isfile() or entry.isdir()):
                    raise ValueError("Bundle must contain only regular files and directories within its root")
                if path.parts and path.parts[0] not in roots:
                    raise ValueError("Unexpected entry at the root of the Ollama bundle")
                if entry.isdir():
                    (tree / path).mkdir(parents=True, exist_ok=True)
                    continue
                target = tree / path
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(entry) as data, target.open("xb") as output:
                    while chunk := data.read(1024 * 1024):
                        output.write(chunk)
                target.chmod(0o755 if entry.mode & 0o111 else 0o644)

        binary = tree / "bin/ollama"
        if not binary.is_file() or not binary.stat().st_mode & 0o111:
            raise ValueError("Bundle must contain executable bin/ollama")
        if serving:
            _check_serving_store(tree, destination)
        (tree / "bundle.json").write_text(json.dumps({"sha256": digest}) + "\n", encoding="utf-8")
        # The DynamicUser service must be able to traverse the tree even with a restrictive installer umask.
        tree.chmod(0o755)
        for directory in tree.rglob("*"):
            if directory.is_dir():
                directory.chmod(0o755)
        tree.rename(destination)


def _check_serving_store(tree, destination):
    """Require a catalog and a preloaded store; the worker rechecks exact model digests."""
    catalog = tree / "llm-models.json"
    if not catalog.is_file():
        raise ValueError("Serving bundle must contain llm-models.json")
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


if __name__ == "__main__":
    try:
        candidate = sys.argv[1:2] == ["--candidate"]
        source, digest = sys.argv[1 + candidate:]
        stage_bundle(Path(source), digest, Path("/opt/lm-llm-candidate" if candidate else "/opt/lm-llm"),
                     serving=not candidate)
    except (OSError, ValueError, tarfile.TarError) as exc:
        sys.exit(f"LLM provisioning failed: {exc}")
