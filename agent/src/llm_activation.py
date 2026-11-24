"""Publish one verified candidate to the isolated, read-only serving store."""

import hashlib
import json
import logging
import os
import re
import shutil
import stat
import tempfile
import uuid
from pathlib import Path

logger = logging.getLogger(__name__)

CANDIDATE_RUNTIME = Path("/opt/lm-llm-candidate")
CANDIDATE_STORE = Path("/var/lib/lm-llm-candidate/models")
SERVING_RUNTIME = Path("/opt/lm-llm")
EXTERNAL_CATALOG = Path("/etc/lm/llm-models.json")
MAX_MANIFEST = 4 * 1024 * 1024
REFERENCE_TYPES = ("application/vnd.docker.distribution.manifest.v2+json",
                   "application/vnd.ollama.manifest.list.v2+json")


def _read_regular(path, maximum=None):
    """Read a regular, non-symlink file with an optional size bound."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ValueError("Model store contains a non-regular file")
        data = source.read() if maximum is None else source.read(maximum + 1)
    if maximum is not None and len(data) > maximum:
        raise ValueError("Model manifest exceeds the size limit")
    return data


def _store_path(root, *parts):
    """Refuse symlinks in model-store paths below the systemd state directory."""
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Invalid model store root")
    current = root
    for part in parts[:-1]:
        current = current / part
        if current.is_symlink() or not current.is_dir():
            raise ValueError("Invalid model store directory")
    return current / parts[-1]


def _mkdirs(root, parts):
    """Create store directories without traversing existing symlinks."""
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Invalid model store root")
    current = root
    for part in parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("Invalid model store directory")
        created = not current.exists()
        current.mkdir(exist_ok=True, mode=0o755)
        if not current.is_dir():
            raise ValueError("Invalid model store directory")
        if created:
            current.chmod(0o755)


def _descriptor(record):
    """Return the identifying (mediaType, digest, size) of one manifest descriptor."""
    if not isinstance(record, dict):
        raise ValueError("Invalid candidate manifest")
    return (record.get("mediaType"), record.get("digest"), record.get("size"))


def _check_manifest_list(row, pinned):
    """Require the referenced manifest list to be genuine and to name the pinned manifest."""
    digest = row.get("digest")
    if not isinstance(digest, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
        raise ValueError("Candidate manifest digest mismatch")
    raw = _read_regular(_store_path(CANDIDATE_STORE, "blobs", f"sha256-{digest[7:]}"), MAX_MANIFEST)
    listing = json.loads(raw)
    if (hashlib.sha256(raw).hexdigest() != digest[7:] or len(raw) != row.get("size")
            or not isinstance(listing, dict) or not isinstance(listing.get("manifests"), list)
            or not any(isinstance(item, dict) and item.get("digest") == f"sha256:{pinned}"
                       for item in listing["manifests"])):
        raise ValueError("Candidate manifest digest mismatch")


def _check_rewritten(manifest, pinned):
    """Accept a manifest the Ollama client rewrote on pull, bound to the pinned one.

    Newer Ollama clients store a manifest of their own (extra fields plus
    entries that reference the registry manifest and its manifest list), so its
    bytes no longer hash to the pinned registry digest. Such a manifest is
    accepted only when it references the pinned registry manifest, that blob in
    the store hashes to the pin, and its config and its layers, once the
    registry manifest reference and an optional manifest list (which must hash
    to its digest and name the pinned manifest) are removed, equal
    the registry manifest's exactly (same media type, digest and size, same order).
    """
    entries = [row for row in manifest["layers"] if isinstance(row, dict)
               and row.get("mediaType") in REFERENCE_TYPES]
    registry_rows = [row for row in entries if row["mediaType"] == REFERENCE_TYPES[0]]
    list_rows = [row for row in entries if row["mediaType"] == REFERENCE_TYPES[1]]
    if [row.get("digest") for row in registry_rows] != [f"sha256:{pinned}"] or len(list_rows) > 1:
        raise ValueError("Candidate manifest digest mismatch")
    if list_rows:
        _check_manifest_list(list_rows[0], pinned)
    registry = _read_regular(_store_path(CANDIDATE_STORE, "blobs", f"sha256-{pinned}"), MAX_MANIFEST)
    if hashlib.sha256(registry).hexdigest() != pinned:
        raise ValueError("Candidate manifest digest mismatch")
    original = json.loads(registry)
    if not isinstance(original, dict) or not isinstance(original.get("layers"), list):
        raise ValueError("Invalid candidate manifest")
    # The config and the remaining layers keep their role, media type and order.
    layers = [_descriptor(row) for row in manifest["layers"] if row not in entries]
    if (_descriptor(manifest.get("config")) != _descriptor(original.get("config"))
            or layers != [_descriptor(row) for row in original["layers"]]):
        raise ValueError("Candidate manifest digest mismatch")


def _manifest(candidate):
    """Verify the exact public manifest and enumerate only its pinned blobs."""
    model, tag = candidate["model"].split(":", 1)
    namespace, name = model.split("/", 1) if "/" in model else ("library", model)
    parts = ("manifests", "registry.ollama.ai", namespace, name, tag)
    raw = _read_regular(_store_path(CANDIDATE_STORE, *parts), MAX_MANIFEST)
    manifest = json.loads(raw)
    if not isinstance(manifest, dict) or not isinstance(manifest.get("layers"), list):
        raise ValueError("Invalid candidate manifest")
    if hashlib.sha256(raw).hexdigest() != candidate["digest"]:
        _check_rewritten(manifest, candidate["digest"])
    records = [manifest.get("config"), *manifest["layers"]]
    digests = []
    for record in records:
        digest = record.get("digest") if isinstance(record, dict) else None
        if not isinstance(digest, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
            raise ValueError("Invalid candidate blob digest")
        digests.append(digest[7:])
    if not digests or len(digests) > 256:
        raise ValueError("Invalid candidate blob count")
    return parts, raw, list(dict.fromkeys(digests))


def _referenced_digests(skip):
    """Return every blob digest named by a manifest other than ``skip``.

    Returns None when any manifest cannot be read, parsed or has an unexpected
    shape: the caller then deletes nothing, because a blob we cannot prove
    unused might be shared.
    """
    store = _store_path(CANDIDATE_STORE, "manifests")
    found = set()
    def unreadable(error):
        """Fail closed: a directory we cannot list may hide a manifest."""
        raise error

    for folder, dirs, files in os.walk(store, onerror=unreadable, followlinks=False):
        # os.walk lists a symlinked directory but never enters it; its manifests are unverifiable.
        if any(os.path.islink(os.path.join(folder, d)) for d in dirs):
            return None
        for name in files:
            path = Path(folder) / name
            if path == skip:
                continue
            try:
                manifest = json.loads(_read_regular(path, MAX_MANIFEST))
            except (OSError, ValueError, RecursionError):
                return None
            layers = manifest.get("layers") if isinstance(manifest, dict) else None
            config = manifest.get("config") if isinstance(manifest, dict) else None
            if not isinstance(layers, list) or not (config is None or isinstance(config, dict)):
                return None
            for row in [config, *layers]:
                if row is None:
                    continue
                digest = row.get("digest") if isinstance(row, dict) else None
                # A descriptor we cannot read as a sha256 digest might hide a shared blob.
                if not isinstance(digest, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
                    return None
                found.add(digest[7:])
    return found


def _unlink_counted(path):
    """Delete one regular file or symlink (never its target); return bytes freed.

    A file that is already missing frees 0 bytes; any other failure raises, so
    the caller can tell "gone" from "still there".
    """
    try:
        size = 0 if path.is_symlink() else path.lstat().st_size
        path.unlink()
    except FileNotFoundError:
        return 0
    return size


def prune_candidate(candidate):
    """Remove an activated model from the candidate store; return bytes freed.

    The serving store now holds its own verified copy, so keeping this one
    would store every model twice. Best effort and never raises: a model that
    cannot be verified, or any other manifest that cannot be parsed, deletes
    nothing. Blobs that another remaining manifest uses are kept, since Ollama
    shares blobs between models. Symlinks are unlinked, never followed.
    """
    try:
        # Step 1: re-verify the candidate; never delete what we cannot identify.
        parts, _raw, digests = _manifest(candidate)
        manifest_path = _store_path(CANDIDATE_STORE, *parts)
        # Step 2: validate every other manifest BEFORE deleting anything.
        keep = _referenced_digests(manifest_path)
        if keep is None:
            logger.warning("LLM candidate prune skipped: a candidate manifest could not be validated")
            return 0
        # Step 3: drop the manifest; if that fails, stop before touching any blob.
        freed = _unlink_counted(manifest_path)
        # Step 4: delete only the blobs nothing else uses (best effort, per file).
        for digest in digests:
            if digest in keep:
                continue
            try:
                freed += _unlink_counted(_store_path(CANDIDATE_STORE, "blobs", f"sha256-{digest}"))
            except OSError as exc:
                logger.warning("LLM candidate prune left a blob behind: %s", exc)
        return freed
    except Exception as exc:  # best effort by contract: pruning must never fail an activation
        logger.warning("LLM candidate prune failed, nothing more deleted: %s", exc)
        return 0


def _copy_blob(digest, target):
    """Copy and hash one blob without following source or destination links."""
    source_path = _store_path(CANDIDATE_STORE, "blobs", f"sha256-{digest}")
    fd = os.open(source_path, os.O_RDONLY | os.O_NOFOLLOW)
    checksum = hashlib.sha256()
    with os.fdopen(fd, "rb") as source, target.open("xb") as output:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ValueError("Model blob is not a regular file")
        while chunk := source.read(1024 * 1024):
            checksum.update(chunk)
            output.write(chunk)
        output.flush()
        os.fsync(output.fileno())
    if checksum.hexdigest() != digest:
        raise ValueError("Candidate blob digest mismatch")
    target.chmod(0o644)


def _hash_file(path):
    """Verify an existing serving blob before reusing it."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    checksum = hashlib.sha256()
    with os.fdopen(fd, "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ValueError("Serving blob is not a regular file")
        while chunk := source.read(1024 * 1024):
            checksum.update(chunk)
    return checksum.hexdigest()


def _atomic_catalog(path, content):
    """Atomically publish or restore a root-managed model catalog."""
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as output:
        temporary = Path(output.name)
        try:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
            os.fchmod(output.fileno(), 0o644)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _remove_added_blobs(added):
    """Remove only blobs still linked to the staged files we installed."""
    for path, device, inode in reversed(added):
        try:
            current = path.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(current.st_mode) or (current.st_dev, current.st_ino) != (device, inode):
            raise ValueError("Serving blob changed during rollback")
        path.unlink()


def publish(candidate, expected_runtime_digest):
    """Stage verified model data and return an exact rollback record."""
    if EXTERNAL_CATALOG.exists() or EXTERNAL_CATALOG.is_symlink():
        raise ValueError("An operator-managed catalog overrides automatic activation")
    marker = _read_regular(CANDIDATE_RUNTIME / "bundle.json", 1024)
    if json.loads(marker) != {"sha256": expected_runtime_digest}:
        raise ValueError("Candidate runtime is not the pinned public release")
    parts, manifest, blobs = _manifest(candidate)
    serving = SERVING_RUNTIME
    created = not serving.exists() and not serving.is_symlink()
    if not created:
        if serving.is_symlink() or _read_regular(serving / "bundle.json", 1024) != marker:
            raise ValueError("Existing serving runtime is not managed by this provisioner")
        expected_env = f"OLLAMA_MODELS={serving / 'models'}\n".encode()
        if _read_regular(serving / "bundle.env", 1024) != expected_env:
            raise ValueError("Existing serving store is not managed by this provisioner")
    token = uuid.uuid4().hex
    with tempfile.TemporaryDirectory(dir=serving.parent) as temp:
        root = Path(temp)
        staged = root / "models"
        (staged / "blobs").mkdir(parents=True)
        for digest in blobs:
            _copy_blob(digest, staged / "blobs" / f"sha256-{digest}")
        manifest_path = staged.joinpath(*parts)
        manifest_path.parent.mkdir(parents=True)
        manifest_path.write_bytes(manifest)
        manifest_path.chmod(0o644)
        if created:
            runtime = root / "runtime"
            shutil.copytree(CANDIDATE_RUNTIME, runtime, symlinks=True)
            shutil.move(staged, runtime / "models")
            env = runtime / "bundle.env"
            env.write_text(f"OLLAMA_MODELS={serving / 'models'}\n", encoding="utf-8")
            catalog = runtime / "llm-models.json"
            catalog.write_text("{}\n", encoding="utf-8")
            (runtime / ".activation-token").write_text(token, encoding="utf-8")
            env.chmod(0o644)
            catalog.chmod(0o644)
            for directory in (runtime / "models", *(runtime / "models").rglob("*")):
                if directory.is_dir():
                    directory.chmod(0o755)
            if serving.exists() or serving.is_symlink():
                raise ValueError("Serving runtime appeared during activation")
            runtime.rename(serving)
            after = (json.dumps({candidate["model"]: candidate["digest"]}) + "\n").encode()
            return {"created": True, "token": token, "before": b"{}\n", "after": after,
                    "committed": False}

        catalog_path = serving / "llm-models.json"
        before = _read_regular(catalog_path, 16384)
        catalog = json.loads(before)
        if not isinstance(catalog, dict) or (candidate["model"] in catalog
                                             and catalog[candidate["model"]] != candidate["digest"]):
            raise ValueError("Existing serving catalog conflicts with the selected model")
        after = (json.dumps({**catalog, candidate["model"]: candidate["digest"]}) + "\n").encode()
        destination = serving / "models"
        added_blobs = []
        try:
            for digest in blobs:
                name = f"sha256-{digest}"
                target = _store_path(destination, "blobs", name)
                if target.exists() or target.is_symlink():
                    if _hash_file(target) != digest:
                        raise ValueError("Existing serving blob digest mismatch")
                else:
                    source = staged / "blobs" / name
                    identity = source.stat()
                    os.link(source, target, follow_symlinks=False)
                    added_blobs.append((target, identity.st_dev, identity.st_ino))
            _mkdirs(destination, parts[:-1])
            target = _store_path(destination, *parts)
            added = not target.exists() and not target.is_symlink()
            if added:
                os.link(manifest_path, target, follow_symlinks=False)
            elif _read_regular(target, MAX_MANIFEST) != manifest:
                raise ValueError("Existing serving manifest conflicts with the selected model")
        except BaseException:
            _remove_added_blobs(added_blobs)
            raise
        return {"created": False, "before": before, "after": after,
                "manifest": target, "manifest_bytes": manifest, "manifest_added": added,
                "added_blobs": added_blobs, "committed": False}


def finalize(record):
    """Approve a staged artifact only after the serving runtime reports its digest."""
    catalog = SERVING_RUNTIME / "llm-models.json"
    if _read_regular(catalog, 16384) != record["before"]:
        raise ValueError("Serving catalog changed during activation")
    _atomic_catalog(catalog, record["after"])
    record["committed"] = True


def rollback(record):
    """Undo only files installed by this activation; preserve unrelated changes."""
    if record["created"]:
        marker = SERVING_RUNTIME / ".activation-token"
        if _read_regular(marker, 128).decode() != record["token"]:
            raise ValueError("Serving runtime changed during rollback")
        shutil.rmtree(SERVING_RUNTIME)
        return
    if record["committed"]:
        catalog = SERVING_RUNTIME / "llm-models.json"
        if _read_regular(catalog, 16384) != record["after"]:
            raise ValueError("Serving catalog changed during rollback")
        _atomic_catalog(catalog, record["before"])
    if record["manifest_added"]:
        target = record["manifest"]
        if _read_regular(target, MAX_MANIFEST) != record["manifest_bytes"]:
            raise ValueError("Serving manifest changed during rollback")
        target.unlink()
    _remove_added_blobs(record["added_blobs"])
