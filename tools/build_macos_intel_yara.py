"""Build pinned YARA-X 1.19 for the unsupported Intel Ventura developer path."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import subprocess
import sys
import tarfile
try:
    import tomllib
except ModuleNotFoundError:  # Importable by the repository's Python 3.10 test lane.
    import tomli as tomllib
import urllib.request
import zipfile

try:
    from tools.build_macos_intel_crypto import BUILDER, fetch_pinned
except ModuleNotFoundError:  # Direct execution puts this script's directory on sys.path.
    from build_macos_intel_crypto import BUILDER, fetch_pinned


COMMIT = "fe40349ea12c5ccb89aae9f304b979c4fb410f66"
ROOT_NAME = f"yara-x-{COMMIT}"
SOURCE = {
    "filename": f"yara-x-{COMMIT}.tar.gz",
    "size": 57248783,
    "sha256": "9e796b2aadb95b49ebf1f5bb1cfae765af935e80cb0755cacaa81966c77c521b",
    "url": f"https://codeload.github.com/VirusTotal/yara-x/tar.gz/{COMMIT}",
}


def fetch_source(directory: Path) -> Path:
    path = directory / SOURCE["filename"]
    digest = hashlib.sha256()
    size = 0
    with urllib.request.urlopen(SOURCE["url"], timeout=60) as response, path.open("xb") as out:
        if not response.url.startswith("https://codeload.github.com/VirusTotal/yara-x/"):
            raise ValueError("YARA-X source download left the reviewed HTTPS host")
        while chunk := response.read(1024 * 1024):
            size += len(chunk)
            if size > SOURCE["size"]:
                raise ValueError("YARA-X source exceeds the reviewed size")
            digest.update(chunk)
            out.write(chunk)
    if size != SOURCE["size"] or digest.hexdigest() != SOURCE["sha256"]:
        raise ValueError("YARA-X source does not match its reviewed size/SHA-256")
    return path


def unpack_source(archive: Path, work: Path) -> Path:
    with tarfile.open(archive) as stream:
        entries = stream.getmembers()
        if len(entries) > 3000 or sum(item.size for item in entries) > 100 * 1024 * 1024:
            raise ValueError("YARA-X source archive exceeds extraction limits")
        for item in entries:
            name = PurePosixPath(item.name)
            if (
                name.is_absolute()
                or ".." in name.parts
                or not name.parts
                or name.parts[0] != ROOT_NAME
                or not (item.isfile() or item.isdir())
            ):
                raise ValueError("YARA-X source archive has an unsafe member")
        stream.extractall(work, members=entries, filter="data")
    source = work / ROOT_NAME
    workspace = tomllib.loads((source / "Cargo.toml").read_text(encoding="utf-8"))
    if workspace["workspace"]["package"].get("version") != "1.19.0":
        raise ValueError("YARA-X source version is not 1.19.0")
    lock = tomllib.loads((source / "Cargo.lock").read_text(encoding="utf-8"))
    for package in lock["package"]:
        if "source" in package and (
            package["source"] != "registry+https://github.com/rust-lang/crates.io-index"
            or len(package.get("checksum", "")) != 64
        ):
            raise ValueError("YARA-X Cargo dependency is not a checksummed registry crate")
    return source


def build_environment(work: Path) -> dict[str, str]:
    env = {
        key: os.environ[key]
        for key in (
            "HOME", "PATH", "TMPDIR", "LANG", "LC_ALL", "RUSTUP_HOME",
            "RUSTUP_TOOLCHAIN",
        )
        if key in os.environ
    }
    env.update(
        {
            "CARGO_HOME": str(work / "cargo"),
            "CARGO_BUILD_JOBS": "2",
            "MACOSX_DEPLOYMENT_TARGET": "13.0",
            "PYO3_PYTHON": sys.executable,
            "PIP_NO_INDEX": "1",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return env


def validate_built_wheel(path: Path) -> str:
    from packaging.tags import sys_tags
    from packaging.utils import parse_wheel_filename

    name, version, _build, tags = parse_wheel_filename(path.name)
    if str(name) != "yara-x" or str(version) != "1.19.0" or not tags.intersection(sys_tags()):
        raise ValueError("local YARA-X wheel has an unexpected package, version or platform")
    with zipfile.ZipFile(path) as wheel:
        metadata_name = next(
            (name for name in wheel.namelist() if name.endswith(".dist-info/METADATA")), None
        )
        if metadata_name is None:
            raise ValueError("local YARA-X wheel has no package metadata")
        metadata = wheel.read(metadata_name).decode()
        if (
            "\nName: yara-x\n" not in "\n" + metadata
            or "\nVersion: 1.19.0\n" not in "\n" + metadata
        ):
            raise ValueError("local YARA-X wheel metadata is unexpected")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(work: Path) -> None:
    if sys.platform != "darwin" or platform.machine() != "x86_64":
        raise RuntimeError("the YARA-X Ventura build must run natively on Intel macOS")
    if sys.version_info[:2] != (3, 12):
        raise RuntimeError("the YARA-X Ventura build requires Python 3.12")
    if work.exists() or work.is_symlink():
        raise ValueError("build workspace must be a new directory")
    cargo = shutil.which("cargo")
    if not cargo or not shutil.which("rustc") or not shutil.which("clang"):
        raise RuntimeError("Xcode command-line tools and Rust are required for YARA-X")
    work.mkdir(parents=True, mode=0o700)
    env = build_environment(work)
    source_archive = fetch_source(work)
    fetch_pinned(BUILDER, work)
    source = unpack_source(source_archive, work)
    builder_lock = work / "builder.txt"
    builder_lock.write_text(
        f"maturin==1.14.1 --hash=sha256:{BUILDER['sha256']}\n", encoding="utf-8"
    )
    subprocess.run(
        [
            sys.executable, "-m", "pip", "install", "--no-index", "--no-deps",
            "--require-hashes", "--only-binary=:all:", "--find-links", str(work),
            "-r", str(builder_lock),
        ],
        check=True, env=env, timeout=300,
    )
    manifest = source / "py/Cargo.toml"
    subprocess.run(
        [cargo, "fetch", "--locked", "--manifest-path", str(manifest)],
        cwd=source, env=env, check=True, timeout=1800,
    )
    env["CARGO_NET_OFFLINE"] = "true"
    output = work / "wheels"
    subprocess.run(
        [
            sys.executable, "-m", "maturin", "build", "--manifest-path", str(manifest),
            "--release", "--locked", "--offline", "--interpreter", sys.executable,
            "--out", str(output),
        ],
        cwd=source, env=env, check=True, timeout=3600,
    )
    wheels = list(output.glob("*.whl"))
    if len(wheels) != 1:
        raise ValueError("YARA-X build did not produce exactly one wheel")
    digest = validate_built_wheel(wheels[0])
    local_lock = work / "local-wheel.txt"
    local_lock.write_text(f"yara-x==1.19.0 --hash=sha256:{digest}\n", encoding="utf-8")
    subprocess.run(
        [
            sys.executable, "-m", "pip", "install", "--no-index", "--no-deps",
            "--require-hashes", "--only-binary=:all:", "--find-links", str(output),
            "-r", str(local_lock),
        ],
        check=True, env=env, timeout=300,
    )
    subprocess.run(
        [
            sys.executable, "-c",
            "import yara_x; "
            "r=yara_x.compile('rule angerona_smoke { strings: $a = \"Angerona\" "
            "condition: $a }'); assert len(r.scan(b\"Angerona\").matching_rules)==1",
        ],
        check=True, env=env, timeout=30,
    )
    receipt = {
        "schema": 1,
        "kind": "unsupported-local-native-build",
        "source_commit": COMMIT,
        "source_sha256": SOURCE["sha256"],
        "builder_sha256": BUILDER["sha256"],
        "cargo_lock_sha256": hashlib.sha256(
            (source / "Cargo.lock").read_bytes()
        ).hexdigest(),
        "wheel": wheels[0].name,
        "wheel_sha256": digest,
        "deployment_target": "13.0",
        "platform": platform.platform(),
        "rustc": subprocess.check_output(
            ["rustc", "--version"], env=env, text=True, timeout=15
        ).strip(),
        "smoke_test": "inert YARA-X compile and byte scan passed",
    }
    (work.parent / "yara-build-receipt.json").write_text(
        json.dumps(receipt, indent=2) + "\n", encoding="utf-8"
    )
    if work.is_symlink() or work.resolve().parent != work.parent.resolve():
        raise ValueError("build workspace changed before cleanup")
    shutil.rmtree(work)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    build(args.work.absolute())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
