#!/usr/bin/env python3
"""Validate the static web client manifest against the locked revision."""

import hashlib
import json
import sys
from pathlib import Path


def main() -> None:
    if len(sys.argv) < 2:
        sys.exit("Usage: validate_web_client_manifest.py <locked_revision>")

    locked_rev = sys.argv[1].strip()
    root = Path("static/web_client")
    manifest_path = root / "web_client_manifest.json"

    if not manifest_path.is_file():
        return

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != 1:
        sys.exit("invalid manifest schema_version")
    if manifest.get("source_revision") != locked_rev:
        sys.exit("manifest source_revision does not match locked_revision")

    files = manifest.get("files", {})
    lines = []
    for rel, spec in sorted(files.items()):
        fp = root / rel
        if not fp.is_file() or fp.is_symlink():
            sys.exit(f"missing or invalid file: {rel}")
        data = fp.read_bytes()
        expected_size = spec["size"]
        if len(data) != expected_size:
            sys.exit(f"size mismatch for {rel}")
        sha = hashlib.sha256(data).hexdigest()
        expected_sha = spec["sha256"]
        if sha.lower() != expected_sha.lower():
            sys.exit(f"hash mismatch for {rel}")
        lines.append(f"{rel}:{expected_size}:{expected_sha}")

    expected_root = hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()
    manifest_root = manifest.get("root_digest", "")
    if expected_root.lower() != manifest_root.lower():
        sys.exit("root_digest mismatch in web_client_manifest.json")


if __name__ == "__main__":
    main()
