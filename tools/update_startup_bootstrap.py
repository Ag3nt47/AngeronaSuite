"""Regenerate the readable batch bootstrap from reviewed recovery files and pins."""
from __future__ import annotations

import argparse
from pathlib import Path
import re

from build_startup_recovery_manifest import build_manifest, canonical_text

ROOT = Path(__file__).resolve().parents[1]
MARKER = ":__ANGERONA_PINNED_BOOTSTRAP__"


def function_text(text: str, name: str) -> str:
    match = re.search(rf"(?m)^function {re.escape(name)}\b", text)
    if match is None:
        raise ValueError(f"reviewed bootstrap function missing: {name}")
    following = re.search(r"(?m)^function ", text[match.end():])
    end = match.end() + following.start() if following else len(text)
    return text[match.start():end].strip()


def payload(root: Path = ROOT) -> str:
    _, pins = build_manifest(root)
    data = canonical_text((root / "tools/startup_bootstrap_payload.ps1").read_bytes()).decode()
    common = canonical_text((root / "tools/startup_repair_common.ps1").read_bytes()).decode()
    verifier = canonical_text((root / "tools/verify_startup_recovery_bundle.ps1").read_bytes()).decode()
    preferences = function_text(common, "Read-SourceStartupRecoveryPreferences").replace(
        "Assert-PlainRepairPath", "Assert-BootstrapPlainPath"
    ).replace("Assert-PrivateRepairCustody", "Assert-BootstrapPrivate")
    native = function_text(verifier, "Initialize-BundleNative").replace(
        "Assert-BundlePlainPath", "Assert-BootstrapPlainPath"
    ).replace("New-BundlePrivateDirectory", "New-BootstrapPrivateDirectory")
    locks = "\n\n".join(function_text(verifier, name) for name in (
        "Assert-BundleLockCustody", "Open-BundleMutationLock", "Close-BundleMutationLocks", "Enter-BundleMutationLocks"
    )).replace("Assert-BundlePlainPath", "Assert-BootstrapPlainPath").replace(
        "New-BundlePrivateDirectory", "New-BootstrapPrivateDirectory"
    )
    data = data.replace("# __PREFERENCES_FUNCTION__", preferences)
    data = data.replace("# __BUNDLE_NATIVE_FUNCTION__", native)
    data = data.replace("# __BUNDLE_LOCK_FUNCTIONS__", locks)
    for name, value in pins.items():
        data = data.replace("__" + name.upper() + "__", value)
    if re.search(r"__[A-Z_]+__", data):
        raise ValueError("unresolved bootstrap placeholder")
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    destination = ROOT / "start-angerona.bat"
    current = canonical_text(destination.read_bytes()).decode()
    prefix = current.split("\n" + MARKER + "\n", 1)[0].rstrip()
    expected = prefix + "\n\n" + MARKER + "\n" + payload().rstrip() + "\n"
    if args.check:
        if current != expected:
            raise SystemExit("batch bootstrap differs from reviewed sources and pins")
    else:
        destination.write_bytes(expected.replace("\n", "\r\n").encode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
