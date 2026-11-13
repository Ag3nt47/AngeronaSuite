"""Build the reviewed recovery-bundle manifest and print independent bat pins.

Run only after the operational recovery files and verifier have been reviewed.
This tool does not edit the batch trust anchor or publish Git objects.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
from pathlib import Path
import stat


FILES = (
    "Repair-Angerona-Python.ps1",
    "constraints-release.txt",
    "pyproject.toml",
    "requirements-bootstrap-pip.txt",
    "requirements-release-hashed.txt",
    "src/angerona/__init__.py",
    "src/angerona/core/__init__.py",
    "src/angerona/resilience/__init__.py",
    "src/angerona/updater/__init__.py",
    "src/angerona/__main__.py",
    "src/angerona/core/_source_tomli/LICENSE",
    "src/angerona/core/_source_tomli/__init__.py",
    "src/angerona/core/_source_tomli/_parser.py",
    "src/angerona/core/_source_tomli/_re.py",
    "src/angerona/core/_source_tomli/_types.py",
    "src/angerona/core/file_lease.py",
    "src/angerona/core/privilege.py",
    "src/angerona/core/source_activation.py",
    "src/angerona/core/source_activation_broker.py",
    "src/angerona/core/source_activation_file.py",
    "src/angerona/core/source_activation_storage.py",
    "src/angerona/core/source_activation_workspace.py",
    "src/angerona/core/startup_diagnostics.py",
    "src/angerona/core/startup_recovery.py",
    "src/angerona/core/windows_child_job.py",
    "src/angerona/resilience/control_authority.py",
    "src/angerona/resilience/deadman.py",
    "src/angerona/resilience/peer_alerts.py",
    "src/angerona/resilience/component_status.py",
    "src/angerona/resilience/diagnostics.py",
    "src/angerona/resilience/heartbeat.py",
    "src/angerona/resilience/manager.py",
    "src/angerona/resilience/recovery_state.py",
    "src/angerona/resilience/shutdown_token.py",
    "src/angerona/resilience/source_guard.py",
    "src/angerona/resilience/supervisor.py",
    "src/angerona/resilience/watchdog.py",
    "src/angerona/startup.py",
    "src/angerona/updater/github_updater.py",
    "src/angerona/updater/source_git.py",
    "src/angerona/updater/source_stage.py",
    "tools/Invoke-AngeronaSourceStartup.ps1",
    "tools/Invoke-AngeronaStartupRepair.ps1",
    "tools/Resume-AngeronaSourceActivation.ps1",
    "tools/Show-AngeronaStartupRecovery.ps1",
    "tools/activate_source_update.py",
    "tools/angerona_recovery.py",
    "tools/build_srt_compat_wheel.py",
    "tools/publication_git_runtime_profile.json",
    "tools/publication_transport.py",
    "tools/source_trust_preflight.py",
    "tools/startup_assistant_capture.ps1",
    "tools/startup_repair_common.ps1",
    "tools/startup_source_recovery.py",
    "tools/windows_publication_runtime.py",
)
MANIFEST = "assets/startup-recovery-manifest.json"
VERIFIER = "tools/verify_startup_recovery_bundle.ps1"
BATCH = "start-angerona.bat"
BATCH_PINS = {
    "manifestSha": "manifest_sha256", "manifestBlob": "manifest_blob_sha1",
    "verifierSha": "verifier_sha256", "verifierBlob": "verifier_blob_sha1",
}
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


def verify_batch_pins(root: Path, pins: dict[str, str]) -> None:
    """Bind all four literal launcher pins to the reviewed generated bytes.

    This checks repository coherence; an editable launcher is not a publisher
    signature or an independent anti-rollback/consent authority.
    """
    batch = read_plain(root, BATCH)
    assignments = re.findall(
        rb"(?im)^\s*\$(manifestSha|manifestBlob|verifierSha|verifierBlob)\s*=([^\n]*)$", batch)
    for name, key in BATCH_PINS.items():
        matches = [(found, value) for found, value in assignments
                   if found.lower() == name.lower().encode("ascii")]
        if len(matches) != 1:
            raise ValueError(f"recovery launcher pin {name} is missing or assigned more than once")
        found, value = matches[0]
        expected = b"'" + pins[key].encode("ascii") + b"'"
        if found != name.encode("ascii") or value != expected:
            raise ValueError(f"recovery launcher pin {name} differs from the reviewed current files")


def verify_verifier_scope(root: Path) -> None:
    """Keep the bootstrap verifier's independent literal allowlist exact."""
    text = read_plain(root, VERIFIER).decode("utf-8")
    assignments = re.findall(r"(?im)^\s*\$script:BundleFiles\s*=", text)
    block = re.search(r"(?m)^\$script:BundleFiles=@\(\n([\s\S]*?)^\)", text)
    if len(assignments) != 1 or block is None:
        raise ValueError("recovery verifier scope must be one literal closed list")
    declared = []
    for line in block.group(1).splitlines():
        match = re.fullmatch(r"\s*'([^']+)'[,]?\s*", line)
        if match is None:
            raise ValueError("recovery verifier scope contains a nonliteral entry")
        declared.append(match.group(1))
    if tuple(declared) != FILES:
        raise ValueError("recovery verifier scope differs from the reviewed builder files")


def verify_application_scope(root: Path) -> None:
    """Compare the update derivation profile as data, without importing source."""
    source = read_plain(root, "src/angerona/core/startup_recovery.py").decode("utf-8")
    try:
        module = ast.parse(source)
        assignments = [node for node in ast.walk(module)
                       if isinstance(node, (ast.Assign, ast.AnnAssign))
                       and any(isinstance(target, ast.Name) and target.id == "RECOVERY_COHERENCE_FILES"
                               for target in (node.targets if isinstance(node, ast.Assign) else [node.target]))]
        if len(assignments) != 1:
            raise ValueError("recovery application scope must have one assignment")
        value = assignments[0].value
        if not isinstance(value, ast.Tuple) or any(
                not isinstance(row, ast.Constant) or type(row.value) is not str for row in value.elts):
            raise ValueError("recovery application scope must be a literal closed tuple")
        if tuple(row.value for row in value.elts) != FILES:
            raise ValueError("recovery application scope differs from the reviewed builder files")
    except (SyntaxError, RecursionError, MemoryError) as error:
        raise ValueError("recovery application scope cannot be read safely") from error


def check_recovery_bundle(root: Path) -> dict[str, str]:
    """Read-only gate shared by CI, --check and guarded publication."""
    root = Path(root).absolute()
    verify_verifier_scope(root)
    verify_application_scope(root)
    raw, pins = build_manifest(root)
    if read_plain(root, MANIFEST) != raw:
        raise ValueError("recovery manifest differs from the reviewed current files")
    verify_batch_pins(root, pins)
    return pins


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--check", action="store_true")
    options = parser.parse_args(argv)
    if options.check:
        pins = check_recovery_bundle(options.root)
        print(json.dumps(pins, sort_keys=True))
        return 0
    raw, pins = build_manifest(options.root)
    destination = options.root / MANIFEST
    assert_plain_ancestry(destination)
    if destination.exists():
        info = destination.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("recovery manifest output is not a single-link file")
    destination.parent.mkdir(parents=True, exist_ok=True)
    assert_plain_ancestry(destination)
    destination.write_bytes(raw)
    print(json.dumps(pins, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
