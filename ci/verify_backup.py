"""Verify an approved backup manifest without restoring or mutating any source."""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from pathlib import Path

REQUIRED_MANIFEST_KEYS = {
    "schema_version",
    "created_at_utc",
    "source_release",
    "tenant_scope",
    "audit_integrity",
    "redaction_verified",
    "files",
}


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def verify_manifest(manifest_path: Path, root: Path) -> None:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    missing = sorted(REQUIRED_MANIFEST_KEYS - set(manifest))
    if missing:
        raise RuntimeError("backup manifest is missing keys: " + ", ".join(missing))
    if manifest["tenant_scope"] != "verified":
        raise RuntimeError("backup manifest does not confirm tenant scope")
    if manifest["audit_integrity"] is not True:
        raise RuntimeError("backup manifest does not confirm audit integrity")
    if manifest["redaction_verified"] is not True:
        raise RuntimeError("backup manifest does not confirm redaction")
    if not manifest["files"]:
        raise RuntimeError("backup manifest contains no files")

    for entry in manifest["files"]:
        relative_path = Path(entry["path"])
        if relative_path.is_absolute() or ".." in relative_path.parts:
            raise RuntimeError(f"backup manifest contains unsafe path: {relative_path}")
        source = (root / relative_path).resolve()
        if root.resolve() not in source.parents:
            raise RuntimeError(f"backup manifest escapes verification root: {relative_path}")
        if not source.is_file() or source.is_symlink():
            raise RuntimeError(f"backup file is missing or symlinked: {relative_path}")
        if entry.get("sha256") != digest(source):
            raise RuntimeError(f"backup digest mismatch: {relative_path}")


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="redpath-backup-verify-") as directory:
        root = Path(directory)
        data = root / "synthetic-audit.jsonl"
        data.write_text('{"tenant_id":"synthetic","event":"fixture"}\n', encoding="utf-8")
        manifest = root / "manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "schema_version": "redpath-backup/v1",
                    "created_at_utc": "2026-01-01T00:00:00Z",
                    "source_release": "synthetic-fixture",
                    "tenant_scope": "verified",
                    "audit_integrity": True,
                    "redaction_verified": True,
                    "files": [{"path": data.name, "sha256": digest(data)}],
                }
            ),
            encoding="utf-8",
        )
        verify_manifest(manifest, root)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--root", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
        elif args.manifest and args.root:
            verify_manifest(args.manifest, args.root)
        else:
            parser.error("use --self-test or provide both --manifest and --root")
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as exc:
        print(f"Backup verification failed safely: {exc}")
        return 1
    print("Backup verification passed: digests, tenant scope, audit integrity, and redaction metadata are valid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
