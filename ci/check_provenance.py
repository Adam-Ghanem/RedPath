"""Validate a release-candidate evidence manifest without contacting external systems."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

SECRET_PATTERN = re.compile(
    r"(?:AKIA[0-9A-Z]{16}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9_]{20,})"
)
REQUIRED_MANIFEST_KEYS = {
    "schema_version",
    "commit_sha",
    "generated_at_utc",
    "files",
    "sbom_references",
    "verification_commands",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate(manifest_path: Path, artifact_root: Path | None = None) -> None:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    missing = sorted(REQUIRED_MANIFEST_KEYS - set(manifest))
    if missing:
        raise RuntimeError("manifest is missing keys: " + ", ".join(missing))
    commit_sha = manifest["commit_sha"]
    if not isinstance(commit_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", commit_sha):
        raise RuntimeError("manifest commit_sha must be a full lowercase Git SHA")
    if not manifest["files"]:
        raise RuntimeError("manifest must contain at least one release file")
    if not manifest["sbom_references"]:
        raise RuntimeError("manifest must reference at least one SBOM artifact")
    if any(SECRET_PATTERN.search(json.dumps(item, sort_keys=True)) for item in manifest.values()):
        raise RuntimeError("manifest contains a high-risk secret pattern")

    if artifact_root is not None:
        for reference in manifest["sbom_references"]:
            reference_path = Path(reference)
            if reference_path.is_absolute() or ".." in reference_path.parts:
                raise RuntimeError(f"manifest contains an unsafe artifact reference: {reference}")
            if not any(path.is_file() for path in artifact_root.rglob(reference_path.name)):
                raise RuntimeError(f"SBOM or dependency artifact is missing: {reference}")

    for entry in manifest["files"]:
        relative_path = Path(entry["path"])
        if relative_path.is_absolute() or ".." in relative_path.parts:
            raise RuntimeError(f"manifest contains an unsafe file path: {relative_path}")
        source = Path(__file__).resolve().parents[1] / relative_path
        if not source.is_file():
            raise RuntimeError(f"manifest file is missing: {relative_path}")
        if entry.get("sha256") != sha256(source):
            raise RuntimeError(f"manifest digest mismatch: {relative_path}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--artifact-root", type=Path)
    args = parser.parse_args()
    try:
        validate(args.manifest, args.artifact_root)
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as exc:
        print(f"Provenance check failed safely: {exc}")
        return 1
    print("Provenance check passed: commit, file digests, SBOM references, and metadata are valid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
