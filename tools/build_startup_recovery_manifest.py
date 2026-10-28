"""Build the reviewed recovery-bundle manifest and print independent bat pins.

Run only after the operational recovery files and verifier have been reviewed.
This tool does not edit the batch trust anchor or publish Git objects.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import stat


FILES = (
    "Repair-Angerona-Python.ps1",
    "constraints-release.txt",
    "pyproject.toml",
    "requirements-bootstrap-pip.txt",
    "requirements-release-hashed.txt",
    "src/angerona/core/startup_diagnostics.py",
    "src/angerona/core/startup_recovery.py",
    "src/angerona/startup.py",
    "tools/Invoke-AngeronaSourceStartup.ps1",
    "tools/Invoke-AngeronaStartupRepair.ps1",
    "tools/Show-AngeronaStartupRecovery.ps1",
    "tools/angerona_recovery.py",
    "tools/build_srt_compat_wheel.py",
    "tools/source_trust_preflight.py",
    "tools/startup_assistant_capture.ps1",
    "tools/startup_repair_common.ps1",
    "tools/startup_source_recovery.py",
)
MANIFEST = "assets/startup-recovery-manifest.json"
VERIFIER = "tools/verify_startup_recovery_bundle.ps1"
MAX_FILE = 2 * 1024**2
MAX_MANIFEST = 128 * 1024
REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def canonical_text(raw: bytes) -> bytes:
    text = raw.decode("utf-8-sig").replace("\r\n", "\n")
    if "\r" in text or "\0" in text:
        raise ValueError("recovery text contains unsupported lone CR or NUL")
    return text.encode("utf-8")


def git_blob(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def assert_plain_ancestry(path: Path) -> None:
    for component in (*reversed(path.parents), path):
        try:
            info = component.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & REPARSE:
            raise ValueError("recovery build refuses linked paths")


def read_plain(root: Path, relative: str) -> bytes:
    path = root / relative
    assert_plain_ancestry(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_FILE * 2 + 3:
        raise ValueError("recovery input is not a bounded single-link file")
    raw = path.read_bytes()
    data = canonical_text(raw)
    if len(data) > MAX_FILE:
        raise ValueError("recovery file exceeds its canonical byte limit")
    return data


def build_manifest(root: Path) -> tuple[bytes, dict[str, str]]:
    root = root.absolute()
    entries = []
    for relative in FILES:
        data = read_plain(root, relative)
        entries.append(dict(path=relative, bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
                            git_blob_sha1=git_blob(data)))
    if sum(entry["bytes"] for entry in entries) > 32 * 1024**2:
        raise ValueError("recovery bundle exceeds its aggregate byte limit")
    document = dict(schema=1, repository="Ag3nt47/AngeronaSuite", canonical_text="utf8-lf-no-bom",
                    files=entries)
    raw = (json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("utf-8")
    if len(raw) > MAX_MANIFEST:
        raise ValueError("recovery manifest exceeds its byte limit")
    verifier = read_plain(root, VERIFIER)
    pins = dict(manifest_sha256=hashlib.sha256(raw).hexdigest(), manifest_blob_sha1=git_blob(raw),
                verifier_sha256=hashlib.sha256(verifier).hexdigest(), verifier_blob_sha1=git_blob(verifier))
    return raw, pins


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--check", action="store_true")
    options = parser.parse_args(argv)
    raw, pins = build_manifest(options.root)
    destination = options.root / MANIFEST
    assert_plain_ancestry(destination)
    if destination.exists():
        info = destination.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("recovery manifest output is not a single-link file")
    if options.check:
        if canonical_text(destination.read_bytes()) != raw:
            raise SystemExit("recovery manifest differs from the reviewed current files")
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        assert_plain_ancestry(destination)
        destination.write_bytes(raw)
    print(json.dumps(pins, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
