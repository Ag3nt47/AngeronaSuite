from __future__ import annotations

import hashlib
import os
import secrets
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from angerona.modules import ransomware_heuristics as ransomware
from angerona.modules import smart_deception


def _smart_module(tmp_path: Path) -> smart_deception.SmartDeception:
    module = smart_deception.SmartDeception()
    target = tmp_path / "decoys"
    target.mkdir()
    module._runtime_root = target
    module._targets = (target,)
    module._manifest = tmp_path / "manifest.json"
    return module


@pytest.mark.parametrize("sample_high", [False, True])
def test_ransomware_rejects_same_inode_overwrite_with_restored_metadata(
    tmp_path: Path, sample_high: bool
) -> None:
    root = tmp_path / "Documents"
    target = root / "sample.bin"
    root.mkdir()
    original = os.urandom(64 * 1024) if sample_high else b"A" * (64 * 1024)
    replacement = b"B" * len(original) if sample_high else os.urandom(len(original))
    target.write_bytes(original)
    timestamp = target.stat().st_mtime_ns
    module = ransomware.RansomwareHeuristicsModule()
    candidates, _snapshot, coverage = module._scan_root(root, time.time())
    assert coverage["complete"] is True
    assert len(candidates) == 1
    identity = target.stat().st_ino

    target.write_bytes(replacement)
    os.utime(target, ns=(timestamp, timestamp))
    assert target.stat().st_ino == identity
    events: list[dict[str, object]] = []
    module.emit = lambda _message, _severity, **details: events.append(details)  # type: ignore[method-assign]

    assert module._evaluate_entropy(candidates, time.time()) == 1
    assert events == []
    assert "content proof stale" in module._last_sample_error


@pytest.mark.skipif(os.name != "nt", reason="NTFS junction regression is Windows-only")
@pytest.mark.parametrize("sample_high", [False, True])
def test_ransomware_rejects_nested_junction_to_same_file_id_alias(
    tmp_path: Path, sample_high: bool
) -> None:
    root = tmp_path / "Documents"
    nested = root / "Projects"
    target = nested / "sample.bin"
    nested.mkdir(parents=True)
    original = os.urandom(64 * 1024) if sample_high else b"A" * (64 * 1024)
    replacement = b"B" * len(original) if sample_high else os.urandom(len(original))
    target.write_bytes(original)
    timestamp = target.stat().st_mtime_ns
    module = ransomware.RansomwareHeuristicsModule()
    candidates, _snapshot, coverage = module._scan_root(root, time.time())
    assert coverage["complete"] is True
    assert len(candidates) == 1

    displaced = tmp_path / "Projects-held"
    redirect = tmp_path / "redirect"
    nested.rename(displaced)
    redirect.mkdir()
    alias = redirect / target.name
    os.link(displaced / target.name, alias)
    alias.write_bytes(replacement)
    os.utime(alias, ns=(timestamp, timestamp))
    command_processor = Path(os.environ["SystemRoot"]) / "System32" / "cmd.exe"
    result = subprocess.run(
        [str(command_processor), "/d", "/c", "mklink", "/J", str(nested), str(redirect)],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if result.returncode != 0:
        pytest.skip(f"NTFS junction creation is unavailable: {result.stderr}")
    try:
        events: list[dict[str, object]] = []
        module.emit = lambda _message, _severity, **details: events.append(details)  # type: ignore[method-assign]
        assert module._evaluate_entropy(candidates, time.time()) == 1
        assert events == []
        assert "identity changed" in module._last_sample_error
    finally:
        if nested.exists():
            os.rmdir(nested)


@pytest.mark.skipif(os.name != "nt", reason="held evidence regression is Windows-only")
def test_deception_missing_and_self_consistent_replacement_are_custody_loss(
    tmp_path: Path,
) -> None:
    module = _smart_module(tmp_path)
    target = module._targets[0] / "token.txt"
    assert module._write_decoy(str(target))
    with target.open("ab") as handle:
        handle.write(b"tampered evidence")
    assert module._retire_tampered_decoy(str(target))
    evidence = next(module._quarantine_directory().glob("*.evidence"))
    evidence.unlink()

    assert module._refresh_quarantine_limits() is False
    module._update_health()
    assert module.health < 100
    assert module._custody_loss >= 1

    forged = b"forged-not-the-original-incident"
    forged_name = (
        f"sdec-{int(time.time() * 1000):013d}-{secrets.token_hex(12)}-"
        f"{hashlib.sha256(forged).hexdigest()}.evidence"
    )
    (module._quarantine_directory() / forged_name).write_bytes(forged)
    assert module._refresh_quarantine_limits() is False
    assert module._quarantine_saturated is True


@pytest.mark.skipif(os.name != "nt", reason="held evidence regression is Windows-only")
def test_deception_foreign_retention_pressure_never_evicts_genuine_evidence(
    tmp_path: Path,
) -> None:
    module = _smart_module(tmp_path)
    target = module._targets[0] / "token.txt"
    assert module._write_decoy(str(target))
    with target.open("ab") as handle:
        handle.write(b"genuine evidence")
    assert module._retire_tampered_decoy(str(target))
    genuine = next(module._quarantine_directory().glob("*.evidence"))
    for index in range(smart_deception._QUARANTINE_MAX_FILES):
        payload = f"foreign-{index}".encode()
        name = (
            f"sdec-{int((time.time() + index + 1) * 1000):013d}-"
            f"{secrets.token_hex(12)}-{hashlib.sha256(payload).hexdigest()}.evidence"
        )
        (module._quarantine_directory() / name).write_bytes(payload)

    assert module._refresh_quarantine_limits() is False
    assert genuine.exists()
    assert module._custody_loss >= 1


@pytest.mark.skipif(os.name != "nt", reason="NTFS hard-link regression is Windows-only")
def test_deception_post_copy_source_alias_is_fail_visible(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _smart_module(tmp_path)
    target = module._targets[0] / "token.txt"
    alias = module._targets[0] / "late-alias.txt"
    assert module._write_decoy(str(target))
    with target.open("ab") as handle:
        handle.write(b"tampered evidence")
    real_copy = module._copy_and_verify_evidence

    def copy_then_alias(source: int, evidence: int, size: int) -> tuple[str, int]:
        receipt = real_copy(source, evidence, size)
        os.link(target, alias)
        return receipt

    monkeypatch.setattr(module, "_copy_and_verify_evidence", copy_then_alias)
    assert module._retire_tampered_decoy(str(target))
    module._update_health()
    assert alias.exists()
    assert module._quarantine_alias_residue >= 1
    assert module._custody_degraded is True
    assert module.health < 100


@pytest.mark.skipif(os.name != "nt", reason="held evidence regression is Windows-only")
def test_deception_pending_crash_object_is_recovered_but_never_healthy(
    tmp_path: Path,
) -> None:
    module = _smart_module(tmp_path)
    assert module._refresh_quarantine_limits() is True
    root = module._quarantine_directory()
    pending = root / f"sdec-pending-{secrets.token_hex(12)}.tmp"
    descriptor = module._create_evidence_file(pending)
    os.write(descriptor, b"partial")
    os.close(descriptor)

    assert module._refresh_quarantine_limits() is True
    module._update_health()
    assert not pending.exists()
    assert module._custody_degraded is True
    assert module._custody_loss >= 1
    assert module.health < 100


@pytest.mark.skipif(os.name != "nt", reason="held evidence regression is Windows-only")
def test_deception_ledger_rollback_against_high_water_is_rejected(
    tmp_path: Path,
) -> None:
    module = _smart_module(tmp_path)
    target = module._targets[0] / "token.txt"
    assert module._write_decoy(str(target))
    with target.open("ab") as handle:
        handle.write(b"first")
    assert module._retire_tampered_decoy(str(target))
    ledger = module._custody_ledger_path()
    old_ledger = tmp_path / "old-ledger.sqlite3"
    shutil.copy2(ledger, old_ledger)

    target.write_bytes(b"second")
    module._decoy_identity[module._path_key(target)] = module._identity(target.stat())
    assert module._retire_tampered_decoy(str(target))
    shutil.copy2(old_ledger, ledger)

    assert module._refresh_quarantine_limits() is False
    assert module._quarantine_saturated is True
