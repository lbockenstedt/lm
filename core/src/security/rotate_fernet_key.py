#!/usr/bin/env python3
"""Rotate the hub's ``LM_FERNET_KEY`` in place — decrypt every at-rest state
file with the CURRENT key, generate a fresh key, and re-encrypt each file with
it. Emits the new ``LM_FERNET_KEY`` line to apply to the hub ``.env`` (and with
``--apply-env`` writes it there directly, backup first).

WHY: ``security/encryption.py`` only falls back to the weak legacy machine-id
key, NOT to a previous ``LM_FERNET_KEY``. So simply changing the env var would
make every existing state blob (``system.json``, ``tenants.json``, ``keys.json``,
``hub_secret.json``) undecryptable and the hub would lose its persisted state.
This script re-encrypts each blob under the new key so rotation is non-
destructive. It also migrates any blob still encrypted with the legacy key to
the new primary key (the same migration that happens incrementally as state is
rewritten — this just does it all at once).

RUN ON THE HUB (as the hub user or root), with the hub STOPPED so no process is
writing state mid-rotation::

    systemctl stop lm-hub  (or however the hub is launched)
    LM_FERNET_KEY="$(grep ^LM_FERNET_KEY= /opt/lm/.env | cut -d= -f2-)" \
      python3 /opt/lm/core/src/security/rotate_fernet_key.py --apply-env
    systemctl start lm-hub

SAFETY:
  * Each re-encrypted file is backed up to ``<file>.pre-rotate.bak`` first.
  * A file that is not a valid Fernet blob (plain JSON such as the
    ``update_recovery`` files ``pending_update.json`` / ``bad_versions.json`` /
    the ``healthy`` marker, or any future plain state) is LEFT UNTOUCHED —
    rotation only touches files that decrypt successfully under the current key
    (primary) or the legacy machine-id key.
  * The new ``.env`` line is written (with ``--apply-env``) only AFTER every
    decryptable file has been re-encrypted, and the env file is backed up to
    ``.env.pre-rotate.bak`` first. If anything fails mid-rotation the script
    exits non-zero before touching ``.env`` so you can re-run after fixing.
  * ``--dry-run`` decrypts + reports counts but writes nothing.

This module is import-safe: importing it does NOT construct the encryption
singleton (that requires ``LM_FERNET_KEY``); the singleton is built lazily inside
``rotate()`` only after the OLD key has been resolved and placed in the env.
"""

import argparse
import os
import shutil
import sys
from typing import List, Optional, Tuple

from cryptography.fernet import Fernet


def _resolve_old_key(env_file: Optional[str]) -> str:
    """Resolve the CURRENT Fernet key: LM_FERNET_KEY env, else parse --env-file."""
    key = os.getenv("LM_FERNET_KEY", "").strip()
    if key:
        return key
    if not env_file or not os.path.exists(env_file):
        raise RuntimeError(
            "LM_FERNET_KEY is not set in the environment and no --env-file was "
            "found. Run with LM_FERNET_KEY=<current key> in the env, or pass "
            "--env-file /opt/lm/.env."
        )
    with open(env_file, "r") as f:
        for line in f:
            line = line.strip()
            if line.startswith("LM_FERNET_KEY="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    raise RuntimeError(f"No LM_FERNET_KEY= line found in {env_file}.")


def _validate_key(key: str, label: str) -> None:
    """Raise RuntimeError if ``key`` is not a valid base64 Fernet key."""
    try:
        Fernet(key.encode())
    except Exception as e:
        raise RuntimeError(f"The {label} is not a valid Fernet key: {e}")


def _build_decryptor(old_key: str):
    """Return a ``decrypt(bytes) -> str`` that tries the OLD primary key, then
    the legacy machine-id key (so blobs encrypted before LM_FERNET_KEY was
    deployed still rotate). Reuses ``HubEncryption._derive_machine_id_fernet``
    via ``__new__`` so the fail-closed primary-key init is bypassed — the legacy
    derivation is host-only and needs no env."""
    try:
        from security.encryption import HubEncryption  # pytest / hub (core/src on path)
    except ImportError:
        from encryption import HubEncryption  # standalone CLI (script dir on sys.path[0])

    old_fernet = Fernet(old_key.encode())
    helper = HubEncryption.__new__(HubEncryption)  # bypass __init__ (no env needed)
    legacy_fernet = helper._derive_machine_id_fernet()  # noqa: SLF001 — reuse the derivation

    def decrypt(content: bytes) -> str:
        try:
            return old_fernet.decrypt(content).decode()
        except Exception:
            return legacy_fernet.decrypt(content).decode()

    return decrypt


def _iter_state_files(state_dir: str) -> List[str]:
    """Top-level regular files in the state dir (does NOT recurse into
    update-backup/). Sorted for deterministic ordering."""
    if not os.path.isdir(state_dir):
        return []
    out = []
    for name in sorted(os.listdir(state_dir)):
        p = os.path.join(state_dir, name)
        if os.path.isfile(p) and not name.endswith(".bak") and not name.endswith(".pre-rotate.bak"):
            out.append(p)
    return out


def rotate(state_dir: str, env_file: Optional[str], apply_env: bool, dry_run: bool) -> Tuple[int, int, str]:
    """Rotate the Fernet key over every decryptable file in ``state_dir``.

    Returns (rotated_count, skipped_count, new_key_str). Raises on any error
    before ``.env`` is touched.
    """
    old_key = _resolve_old_key(env_file)
    _validate_key(old_key, "current (old) LM_FERNET_KEY")

    # Build a decryptor that tries the OLD primary key then the legacy
    # machine-id key. Built directly (not via the module singleton) so the
    # already-constructed hub_encryption in a long-lived process doesn't pin us
    # to the wrong key.
    decryptor = _build_decryptor(old_key)

    new_key_bytes = Fernet.generate_key()
    new_key = new_key_bytes.decode()
    new_fernet = Fernet(new_key_bytes)

    files = _iter_state_files(state_dir)
    rotated, skipped = 0, 0
    plan: List[Tuple[str, str]] = []  # (path, plaintext_json) to re-encrypt

    for path in files:
        try:
            with open(path, "rb") as f:
                content = f.read()
        except OSError as e:
            raise RuntimeError(f"Could not read {path}: {e}")
        if not content:
            skipped += 1  # empty file (e.g. the `healthy` marker) — not encrypted
            continue
        try:
            plaintext = decryptor(content)
        except Exception:
            # Not a Fernet blob under old-primary or legacy → plain JSON / a
            # recovery file / something we don't own. Leave it untouched.
            skipped += 1
            continue
        plan.append((path, plaintext))
        rotated += 1

    if dry_run:
        print(f"[dry-run] would re-encrypt {rotated} file(s) under a new key; "
              f"skipped {skipped} plain/empty file(s).")
        return rotated, skipped, new_key

    # Re-encrypt each file under the new key (backup first).
    for path, plaintext in plan:
        bak = path + ".pre-rotate.bak"
        try:
            shutil.copy2(path, bak)
            with open(path, "wb") as f:
                f.write(new_fernet.encrypt(plaintext.encode()))
        except OSError as e:
            raise RuntimeError(
                f"Failed re-encrypting {path} (backup at {bak}): {e}. "
                f"STOPPED before .env update — re-run after fixing (already-rotated "
                f"files are recoverable from their .pre-rotate.bak)."
            )

    # Update .env ONLY after all files are re-encrypted.
    if apply_env:
        if not env_file:
            raise RuntimeError("--apply-env requires --env-file (or a default path).")
        _write_env_key(env_file, new_key)

    return rotated, skipped, new_key


def _write_env_key(env_file: str, new_key: str) -> None:
    """Backup env_file to .pre-rotate.bak then set LM_FERNET_KEY=<new_key>."""
    if os.path.exists(env_file):
        shutil.copy2(env_file, env_file + ".pre-rotate.bak")
        with open(env_file, "r") as f:
            lines = f.readlines()
        replaced = False
        for i, line in enumerate(lines):
            if line.startswith("LM_FERNET_KEY="):
                lines[i] = f"LM_FERNET_KEY={new_key}\n"
                replaced = True
                break
        if not replaced:
            lines.append(f"LM_FERNET_KEY={new_key}\n")
        with open(env_file, "w") as f:
            f.writelines(lines)
    else:
        with open(env_file, "w") as f:
            f.write(f"LM_FERNET_KEY={new_key}\n")


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description="Rotate the hub LM_FERNET_KEY in place (decrypt + re-encrypt state).")
    p.add_argument("--state-dir", default="/var/lib/lm/state",
                   help="Hub state dir (default /var/lib/lm/state).")
    p.add_argument("--env-file", default="/opt/lm/.env",
                   help="Hub .env to read the old key from / write the new key to (default /opt/lm/.env).")
    p.add_argument("--apply-env", action="store_true",
                   help="Write the new LM_FERNET_KEY to --env-file (backup first). Without it, just print the new line.")
    p.add_argument("--dry-run", action="store_true",
                   help="Report what would rotate; write nothing.")
    args = p.parse_args(argv)

    try:
        rotated, skipped, new_key = rotate(args.state_dir, args.env_file, args.apply_env, args.dry_run)
    except RuntimeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    print(f"Rotated {rotated} encrypted file(s) under the new LM_FERNET_KEY; "
          f"skipped {skipped} plain/empty file(s).")
    if args.apply_env:
        print(f"New LM_FERNET_KEY written to {args.env_file} (backup at {args.env_file}.pre-rotate.bak).")
    else:
        print("Apply the new key to your hub .env (then restart the hub):")
        print(f"  LM_FERNET_KEY={new_key}")
        print("(or re-run with --apply-env to write it to --env-file automatically.)")
    print("Backups of each rotated file are next to it as <file>.pre-rotate.bak.")
    return 0


if __name__ == "__main__":
    sys.exit(main())