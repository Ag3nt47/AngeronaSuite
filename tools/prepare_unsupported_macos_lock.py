"""Derive the Ventura development wheel lock by removing only local-build YARA-X."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re


SOURCE_TARGET = "macos-x86_64-base"
DEVELOPMENT_TARGET = "macos-x86_64-ventura-dev"
YARA_ARTIFACT = {
    "filename": "yara_x-1.19.0-cp38-abi3-macosx_14_0_x86_64.whl",
    "name": "yara-x",
    "sha256": "f38e19b0bd3f6af8366ac789778d0c39e359a897473b86c3ff6f9b0c255e631e",
    "size": 9167113,
    "version": "1.19.0",
}
_HASH = re.compile(r"--hash=sha256:([0-9a-f]{64})$")


def derive(
    source_lock: Path,
    source_manifest: Path,
    output_lock: Path,
    output_manifest: Path,
) -> int:
    document = json.loads(source_manifest.read_text(encoding="utf-8"))
    artifacts = document.get("artifacts")
    if (
        document.get("schema") != 1
        or document.get("python") != "cp312"
        or document.get("target") != SOURCE_TARGET
        or not isinstance(artifacts, list)
    ):
        raise ValueError("unexpected Intel macOS base manifest")
    source_hashes = {
        match.group(1)
        for line in source_lock.read_text(encoding="utf-8").splitlines()
        if (match := _HASH.search(line.strip())) is not None
    }
    manifest_hashes = {item.get("sha256") for item in artifacts if isinstance(item, dict)}
    if source_hashes != manifest_hashes or len(source_hashes) != len(artifacts):
        raise ValueError("base lock and manifest do not describe the same exact artifacts")
    yara = [item for item in artifacts if item.get("name", "").casefold() == "yara-x"]
    if yara != [YARA_ARTIFACT]:
        raise ValueError("base YARA-X artifact is not the reviewed 1.19.0 macOS wheel")
    remaining = [item for item in artifacts if item is not yara[0]]
    if not remaining:
        raise ValueError("derived wheel lock would be empty")
    lock_lines = [
        "# Derived from the reviewed Intel base lock for unsupported Ventura development.",
        "# YARA-X 1.19.0 is built separately from its pinned source commit.",
        "--only-binary=:all:",
        "",
    ]
    for item in remaining:
        lock_lines.extend(
            [f"{item['name']}=={item['version']} \\", f"    --hash=sha256:{item['sha256']}", ""]
        )
    derived = {
        "artifacts": remaining,
        "python": "cp312",
        "schema": 1,
        "target": DEVELOPMENT_TARGET,
    }
    output_lock.write_text("\n".join(lock_lines), encoding="utf-8", newline="\n")
    output_manifest.write_text(
        json.dumps(derived, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    return len(remaining)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-lock", type=Path, required=True)
    parser.add_argument("--source-manifest", type=Path, required=True)
    parser.add_argument("--output-lock", type=Path, required=True)
    parser.add_argument("--output-manifest", type=Path, required=True)
    args = parser.parse_args()
    count = derive(
        args.source_lock, args.source_manifest, args.output_lock, args.output_manifest
    )
    print(f"derived {count} exact wheels for {DEVELOPMENT_TARGET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
