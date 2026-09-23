"""Build cryptography 50 for Intel macOS from reviewed, hash-pinned inputs.

This deliberately separate native build is not an upstream wheel lock. The
source archive authenticates Cargo.lock; Cargo fetch verifies the locked crate
checksums, and compilation then runs offline with two workers. Native compiler,
Rust and OpenSSL installations remain local prerequisites, recorded in a receipt.
"""
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

ROOT = Path(__file__).resolve().parents[1]
SOURCE = {
    "filename": "cryptography-50.0.0.tar.gz",
    "size": 880201,
    "sha256": "eeac2acb5a20ed25e0ad6d1df9891a520b78b404266b6d11778f25d5d691a6c9",
    "url": "https://files.pythonhosted.org/packages/de/41/6cbdcf9142d00fe82836fbb51e503e58088575cf7a0fe1dbff6695bf0840/cryptography-50.0.0.tar.gz",
}
BUILDER = {
    "filename": "maturin-1.14.1-py3-none-macosx_10_12_x86_64.macosx_11_0_arm64.macosx_10_12_universal2.whl",
    "size": 19680113,
    "sha256": "ffe5ad71f21d1e6603c4dd75f7fee34adf5ed5ebcebb692886549888ebb329ed",
    "url": "https://files.pythonhosted.org/packages/fe/83/294bca639b0e052f1e2f65199b3db258780c7d4e31408b934c9c974a1379/maturin-1.14.1-py3-none-macosx_10_12_x86_64.macosx_11_0_arm64.macosx_10_12_universal2.whl",
}


def fetch_pinned(item: dict, directory: Path) -> Path:
    path = directory / item["filename"]
    digest = hashlib.sha256()
    size = 0
    with urllib.request.urlopen(item["url"], timeout=45) as response, path.open("xb") as output:
        if not response.url.startswith("https://files.pythonhosted.org/"):
            raise ValueError("artifact download left the reviewed HTTPS host")
        while chunk := response.read(1024 * 1024):
            size += len(chunk)
            if size > item["size"]:
                raise ValueError("artifact exceeds reviewed size")
            digest.update(chunk)
            output.write(chunk)
    if size != item["size"] or digest.hexdigest() != item["sha256"]:
        raise ValueError("artifact does not match its reviewed size/SHA-256")
    return path


def unpack_source(archive: Path, work: Path) -> Path:
    with tarfile.open(archive) as stream:
        entries = stream.getmembers()
        if len(entries) > 4000 or sum(item.size for item in entries) > 32 * 1024 * 1024:
            raise ValueError("source archive exceeds extraction limits")
        for item in entries:
            name = PurePosixPath(item.name)
            if (
                name.is_absolute() or ".." in name.parts
                or not name.parts or name.parts[0] != "cryptography-50.0.0"
                or not (item.isfile() or item.isdir())
            ):
                raise ValueError("source archive has an unsafe member")
        stream.extractall(work, members=entries, filter="data")
    source = work / "cryptography-50.0.0"
    config = tomllib.loads((source / "pyproject.toml").read_text())
    if config["tool"]["maturin"].get("locked") is not True:
        raise ValueError("source must require a locked Cargo build")
    lock = tomllib.loads((source / "Cargo.lock").read_text())
    for package in lock["package"]:
        if "source" in package and (
            package["source"] != "registry+https://github.com/rust-lang/crates.io-index"
            or len(package.get("checksum", "")) != 64
        ):
            raise ValueError("Cargo dependency is not pinned to a checksummed registry crate")
    return source


def build_environment(work: Path, openssl: Path) -> dict[str, str]:
    # Drop inherited build flags, wrappers, package indexes, and Cargo overrides.
    env = {key: os.environ[key] for key in ("HOME", "PATH", "TMPDIR", "LANG", "LC_ALL") if key in os.environ}
    env.update({
        "CARGO_HOME": str(work / "cargo"), "CARGO_BUILD_JOBS": "2",
        "OPENSSL_DIR": str(openssl), "OPENSSL_STATIC": "1",
        "MACOSX_DEPLOYMENT_TARGET": "14.0", "PYO3_PYTHON": sys.executable,
        "PIP_NO_INDEX": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "GIT_TERMINAL_PROMPT": "0",
    })
    return env


def validate_built_wheel(path: Path) -> str:
    from packaging.tags import sys_tags
    from packaging.utils import parse_wheel_filename
    name, version, _build, tags = parse_wheel_filename(path.name)
    if name != "cryptography" or str(version) != "50.0.0" or not tags.intersection(sys_tags()):
        raise ValueError("local wheel has an unexpected package, version or platform")
    with zipfile.ZipFile(path) as wheel:
        metadata = wheel.read("cryptography-50.0.0.dist-info/METADATA").decode()
        if "\nName: cryptography\n" not in "\n" + metadata or "\nVersion: 50.0.0\n" not in "\n" + metadata:
            raise ValueError("local wheel metadata does not match cryptography 50")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(work: Path, openssl: Path) -> None:
    if sys.platform != "darwin" or platform.machine() != "x86_64" or sys.version_info[:2] != (3, 12):
        raise RuntimeError("the Intel build must run natively on macOS x86_64 with Python 3.12")
    if work.exists() or work.is_symlink():
        raise ValueError("build workspace must be a new directory")
    if not (openssl / "include/openssl/ssl.h").is_file() or not (openssl / "lib/libcrypto.a").is_file():
        raise RuntimeError("OpenSSL development headers/static libraries are missing; run brew install openssl@3")
    cargo = shutil.which("cargo")
    if not cargo or not shutil.which("rustc") or not shutil.which("clang"):
        raise RuntimeError("Xcode command-line tools and Rust are required for the Intel cryptography build")
    work.mkdir(parents=True, mode=0o700)
    env = build_environment(work, openssl)
    archive = fetch_pinned(SOURCE, work)
    fetch_pinned(BUILDER, work)
    source = unpack_source(archive, work)
    builder_lock = work / "builder.txt"
    builder_lock.write_text(f"maturin==1.14.1 --hash=sha256:{BUILDER['sha256']}\n")
    subprocess.run([sys.executable, "-m", "pip", "install", "--no-index", "--no-deps", "--require-hashes", "--only-binary=:all:", "--find-links", str(work), "-r", str(builder_lock)], check=True, env=env, timeout=300)
    manifest = source / "src/rust/Cargo.toml"
    subprocess.run([cargo, "fetch", "--locked", "--manifest-path", str(manifest)], cwd=source, env=env, check=True, timeout=900)
    env["CARGO_NET_OFFLINE"] = "true"
    output = work / "wheels"
    subprocess.run([sys.executable, "-m", "maturin", "build", "--release", "--locked", "--offline", "--interpreter", sys.executable, "--out", str(output)], cwd=source, env=env, check=True, timeout=1800)
    wheels = list(output.glob("*.whl"))
    if len(wheels) != 1:
        raise ValueError("native build did not produce exactly one wheel")
    digest = validate_built_wheel(wheels[0])
    local_lock = work / "local-wheel.txt"
    local_lock.write_text(f"cryptography==50.0.0 --hash=sha256:{digest}\n")
    subprocess.run([sys.executable, "-m", "pip", "install", "--no-index", "--no-deps", "--require-hashes", "--only-binary=:all:", "--find-links", str(output), "-r", str(local_lock)], check=True, env=env, timeout=300)
    subprocess.run([sys.executable, "-c", "from cryptography.hazmat.primitives.ciphers.aead import AESGCM; k=AESGCM.generate_key(bit_length=256); a=AESGCM(k); n=b'0'*12; assert a.decrypt(n,a.encrypt(n,b'Angerona',None),None)==b'Angerona'"], check=True, env=env, timeout=30)
    receipt = {
        "schema": 1, "kind": "local-native-build", "source_sha256": SOURCE["sha256"],
        "builder_sha256": BUILDER["sha256"], "wheel": wheels[0].name,
        "wheel_sha256": digest, "cargo_lock_sha256": hashlib.sha256((source / "Cargo.lock").read_bytes()).hexdigest(),
        "openssl_prefix": str(openssl), "platform": platform.platform(),
        "rustc": subprocess.check_output(["rustc", "--version"], env=env, text=True, timeout=15).strip(),
        "openssl": subprocess.check_output([str(openssl / "bin/openssl"), "version"], env=env, text=True, timeout=15).strip(),
        "smoke_test": "AES-GCM round trip passed",
    }
    (work.parent / "crypto-build-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    # The caller supplied a new, locally created workspace; no cached builds or
    # source trees are reused as authority for subsequent installations.
    if work.is_symlink() or work.resolve().parent != work.parent.resolve():
        raise ValueError("build workspace changed before cleanup")
    shutil.rmtree(work)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--openssl", type=Path)
    args = parser.parse_args()
    prefix = args.openssl or Path(os.environ.get("OPENSSL_DIR", "/usr/local/opt/openssl@3"))
    build(args.work.absolute(), prefix.absolute())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
