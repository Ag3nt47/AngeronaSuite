"""Build Angerona's deterministic, pure-Python Vosk SRT compatibility wheel."""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


NAME = "srt"
VERSION = "0.0.0+angerona.1"
WHEEL_NAME = f"{NAME}-{VERSION}-py3-none-any.whl"
DIST = f"{NAME}-{VERSION}.dist-info"
FIXED_TIME = (2020, 1, 1, 0, 0, 0)


def _info(name: str) -> ZipInfo:
    info = ZipInfo(name, FIXED_TIME)
    info.compress_type = ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    return info


def _record(rows: list[tuple[str, bytes]]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    for name, payload in rows:
        digest = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=")
        writer.writerow((name, f"sha256={digest.decode('ascii')}", len(payload)))
    writer.writerow((f"{DIST}/RECORD", "", ""))
    return stream.getvalue().encode("utf-8")


def build(out_dir: Path) -> Path:
    root = Path(__file__).resolve().parents[1]
    package = (root / "src" / "srt" / "__init__.py").read_bytes()
    files = [
        ("srt/__init__.py", package),
        (f"{DIST}/METADATA", (
            "Metadata-Version: 2.1\n"
            "Name: srt\n"
            f"Version: {VERSION}\n"
            "Summary: Angerona-maintained Vosk SRT compatibility surface\n"
            "Requires-Python: >=3.10\n\n"
        ).encode("utf-8")),
        (f"{DIST}/WHEEL", (
            "Wheel-Version: 1.0\n"
            "Generator: Angerona deterministic compatibility builder\n"
            "Root-Is-Purelib: true\n"
            "Tag: py3-none-any\n"
        ).encode("utf-8")),
        (f"{DIST}/top_level.txt", b"srt\n"),
    ]
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / WHEEL_NAME
    with ZipFile(target, "w") as wheel:
        for name, payload in files:
            wheel.writestr(_info(name), payload)
        wheel.writestr(_info(f"{DIST}/RECORD"), _record(files))
    return target


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    print(build(args.out))
