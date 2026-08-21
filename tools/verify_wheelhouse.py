"""Fail-closed stdlib-only verification for a downloaded release wheelhouse."""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import stat
from pathlib import Path


_HASH = re.compile(r"--hash=sha256:([0-9a-f]{64})$")
_SAFE_FILENAME = re.compile(r"^[A-Za-z0-9_.+-]+\.whl$")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_wheelhouse(manifest_path: Path, lock_path: Path, wheelhouse: Path, target: str) -> int:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema") != 1 or manifest.get("python") != "cp312":
        raise ValueError("unsupported wheelhouse manifest schema or Python target")
    if manifest.get("target") != target:
        raise ValueError(f"manifest target mismatch: expected {target!r}")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ValueError("manifest contains no artifacts")

    expected: dict[str, dict[str, object]] = {}
    expected_hashes: set[str] = set()
    for item in artifacts:
        if not isinstance(item, dict):
            raise ValueError("invalid artifact entry")
        filename = item.get("filename")
        digest = item.get("sha256")
        size = item.get("size")
        if not isinstance(filename, str) or not _SAFE_FILENAME.fullmatch(filename):
            raise ValueError("unsafe artifact filename")
        if filename in expected:
            raise ValueError(f"duplicate artifact filename: {filename}")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError(f"invalid SHA-256 for {filename}")
        if not isinstance(size, int) or size < 1:
            raise ValueError(f"invalid size for {filename}")
        expected[filename] = item
        expected_hashes.add(digest)

    lock_text = lock_path.read_text(encoding="utf-8")
    if "--only-binary=:all:" not in lock_text:
        raise ValueError("lock does not require wheels")
    lock_hashes = {
        match.group(1)
        for line in lock_text.splitlines()
        if (match := _HASH.search(line.strip())) is not None
    }
    if lock_hashes != expected_hashes or len(lock_hashes) != len(expected):
        raise ValueError("lock hashes do not exactly match the manifest")

    actual = {path.name for path in wheelhouse.iterdir()}
    if actual != set(expected):
        missing = sorted(set(expected) - actual)
        extra = sorted(actual - set(expected))
        raise ValueError(f"wheelhouse set mismatch; missing={missing}, extra={extra}")

    root = wheelhouse.resolve(strict=True)
    for filename, item in expected.items():
        path = wheelhouse / filename
        mode = path.lstat().st_mode
        if path.is_symlink() or not stat.S_ISREG(mode):
            raise ValueError(f"artifact is not a regular file: {filename}")
        if path.resolve(strict=True).parent != root:
            raise ValueError(f"artifact escapes wheelhouse: {filename}")
        if path.stat().st_size != item["size"]:
            raise ValueError(f"artifact size mismatch: {filename}")
        digest = _sha256(path)
        if not _constant_time_equal(digest, str(item["sha256"])):
            raise ValueError(f"artifact SHA-256 mismatch: {filename}")
    return len(expected)


def _constant_time_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left, right)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--wheelhouse", type=Path, required=True)
    parser.add_argument("--target", required=True)
    args = parser.parse_args()
    count = verify_wheelhouse(args.manifest, args.lock, args.wheelhouse, args.target)
    print(f"verified {count} locked wheels for {args.target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
