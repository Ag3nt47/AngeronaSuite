from __future__ import annotations

import dataclasses
import importlib
import os
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.modules import ransomware_heuristics as ransomware
from angerona.modules import remediation_actions as actions
from angerona.modules import smart_deception
from angerona.modules import sys_bridge


def _recent_file(path: Path, size: int = ransomware.MIN_FILE_BYTES) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"A" * size)


def test_ransomware_recursive_scan_finds_nested_files_and_reports_coverage(
    tmp_path: Path,
) -> None:
    nested = tmp_path / "Documents" / "Projects" / "2026" / "report.bin"
    _recent_file(nested)
    module = ransomware.RansomwareHeuristicsModule()

    candidates = module._collect_entropy_candidates(tmp_path / "Documents", time.time())
    coverage = module.coverage_snapshot()

    assert str(nested) in candidates
    assert coverage["visited"] == 1
    assert coverage["directories"] == 3
    assert coverage["skipped"] == 0
    assert coverage["truncated"] == 0
    assert coverage["errors"] == 0
    assert coverage["complete"] is True
    assert module.health == 100


def test_ransomware_recursive_budget_is_fail_visible(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "Documents"
    _recent_file(root / "a.bin")
    _recent_file(root / "nested" / "b.bin")
    monkeypatch.setattr(ransomware, "TRAVERSAL_MAX_FILES", 1)
    module = ransomware.RansomwareHeuristicsModule()

    module._collect_entropy_candidates(root, time.time())
    coverage = module.coverage_snapshot()

    assert coverage["visited"] == 1
    assert coverage["truncated"] >= 1
    assert coverage["complete"] is False
    assert module.health < 100
    assert "truncated=" in module.health_note


def test_ransomware_recursive_scan_never_follows_directory_links(
    tmp_path: Path,
) -> None:
    root = tmp_path / "Documents"
    outside = tmp_path / "outside"
    _recent_file(outside / "hidden.bin")
    root.mkdir()
    try:
        os.symlink(outside, root / "linked", target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlinks are unavailable: {exc}")
    module = ransomware.RansomwareHeuristicsModule()

    candidates = module._collect_entropy_candidates(root, time.time())
    coverage = module.coverage_snapshot()

    assert str(outside / "hidden.bin") not in candidates
    assert coverage["skipped"] >= 1
    assert coverage["complete"] is False
    assert module.health < 100


@pytest.mark.skipif(os.name != "nt", reason="NTFS junction regression is Windows-only")
def test_ransomware_watched_root_junction_is_rejected_fail_visible(
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    hidden = outside / "hidden.bin"
    _recent_file(hidden)
    root = tmp_path / "Documents"
    command_processor = Path(os.environ["SystemRoot"]) / "System32" / "cmd.exe"
    result = subprocess.run(
        [
            str(command_processor),
            "/d",
            "/c",
            "mklink",
            "/J",
            str(root),
            str(outside),
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if result.returncode != 0:
        pytest.skip(f"NTFS junction creation is unavailable: {result.stderr}")
    try:
        module = ransomware.RansomwareHeuristicsModule()
        candidates = module._collect_entropy_candidates(root, time.time())
        coverage = module.coverage_snapshot()

        assert str(hidden) not in candidates
        assert coverage["visited"] == 0
        assert coverage["skipped"] >= 1
        assert coverage["errors"] >= 1
        assert coverage["complete"] is False
        assert module.health < 100
        assert "junction" in str(coverage["last_error"])
    finally:
        if root.exists():
            os.rmdir(root)


def test_ransomware_enrolled_root_identity_cannot_be_silently_replaced(
    tmp_path: Path,
) -> None:
    root = tmp_path / "Documents"
    original = root / "original.bin"
    _recent_file(original)
    module = ransomware.RansomwareHeuristicsModule()
    assert str(original) in module._collect_entropy_candidates(root, time.time())
    displaced = tmp_path / "Documents-old"
    root.rename(displaced)
    replacement = root / "replacement.bin"
    _recent_file(replacement)

    candidates = module._collect_entropy_candidates(root, time.time())
    coverage = module.coverage_snapshot()

    assert str(replacement) not in candidates
    assert coverage["complete"] is False
    assert coverage["errors"] >= 1
    assert "identity changed after enrollment" in str(coverage["last_error"])
    assert module.health < 100


@pytest.mark.skipif(os.name != "nt", reason="NTFS junction regression is Windows-only")
def test_ransomware_entropy_sample_rejects_post_enumeration_root_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "Documents"
    original = root / "sample.bin"
    original.parent.mkdir()
    original.write_bytes(bytes(range(256)) * 256)
    redirected = tmp_path / "redirected"
    redirected.mkdir()
    (redirected / original.name).write_bytes(b"A" * (256 * 256))
    displaced = tmp_path / "Documents-held"
    module = ransomware.RansomwareHeuristicsModule()
    module._watch_dirs = [root]
    events: list[dict] = []
    module.emit = lambda message, severity, **details: events.append(details)  # type: ignore[method-assign]
    real_evaluate = module._evaluate_entropy
    command_processor = Path(os.environ["SystemRoot"]) / "System32" / "cmd.exe"
    junction_created = False

    def swap_then_evaluate(candidates, now):
        nonlocal junction_created
        assert candidates
        assert candidates[0].sample_entropy >= 7.99
        assert candidates[0].sample_size == ransomware.SAMPLE_BYTES
        assert len(candidates[0].sample_sha256) == 64
        root.rename(displaced)
        result = subprocess.run(
            [
                str(command_processor),
                "/d",
                "/c",
                "mklink",
                "/J",
                str(root),
                str(redirected),
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode != 0:
            pytest.skip(f"NTFS junction creation is unavailable: {result.stderr}")
        junction_created = True
        return real_evaluate(candidates, now)

    monkeypatch.setattr(module, "_evaluate_entropy", swap_then_evaluate)
    try:
        module._tick()
        coverage = module.coverage_snapshot()

        assert events == []
        assert coverage["complete"] is False
        assert coverage["errors"] >= 1
        assert coverage["skipped"] >= 1
        assert "identity changed" in str(coverage["last_error"])
        assert module.health < 100
    finally:
        if junction_created and root.exists():
            os.rmdir(root)


def test_ransomware_recursive_snapshot_attributes_nested_rename_to_its_directory(
    tmp_path: Path,
) -> None:
    root = tmp_path / "Documents"
    nested = root / "Projects"
    original = nested / "report.doc"
    _recent_file(original)
    module = ransomware.RansomwareHeuristicsModule()
    module._dir_snapshot[module._directory_key(root)] = module._snapshot(root)
    renamed = original.with_suffix(".doc.locked")
    original.rename(renamed)

    module._detect_renames(root, time.time())

    assert len(module._rename_times) == 1
    assert module._rename_times[0][1] == module._directory_key(nested)


def _smart_module(tmp_path: Path) -> smart_deception.SmartDeception:
    module = smart_deception.SmartDeception()
    target = tmp_path / "decoys"
    target.mkdir()
    module._runtime_root = target
    module._targets = (target,)
    module._manifest = tmp_path / "manifest.json"
    return module


def test_smart_deception_exclusive_create_never_clobbers_existing_file(
    tmp_path: Path,
) -> None:
    module = _smart_module(tmp_path)
    target = module._targets[0] / "existing.txt"
    target.write_bytes(b"user-owned")

    assert module._write_decoy(str(target)) is False
    assert target.read_bytes() == b"user-owned"


@pytest.mark.skipif(os.name != "nt", reason="held-object cleanup is Windows-only")
def test_smart_deception_failed_creation_disposes_only_held_object(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _smart_module(tmp_path)
    target = module._targets[0] / "failed-token.txt"
    real_unlink = Path.unlink

    def guarded_unlink(path: Path, *args, **kwargs):
        if path == target:
            raise AssertionError("failed decoy cleanup used a mutable pathname")
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", guarded_unlink)
    monkeypatch.setattr(
        smart_deception.os,
        "fsync",
        lambda _descriptor: (_ for _ in ()).throw(OSError("injected fsync failure")),
    )

    assert module._write_decoy(str(target)) is False
    assert not target.exists()


def test_smart_deception_anchor_read_is_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _smart_module(tmp_path)
    target = module._targets[0] / "token.txt"
    assert module._write_decoy(str(target)) is True
    with target.open("ab") as stream:
        stream.write(b"X" * (2 * 1024 * 1024))
    requested: list[int] = []
    real_read = smart_deception.os.read

    def bounded_read(descriptor: int, count: int) -> bytes:
        requested.append(count)
        return real_read(descriptor, count)

    monkeypatch.setattr(smart_deception.os, "read", bounded_read)

    assert "anchor token missing" in str(module._check_decoy(str(target)))
    assert requested == [smart_deception._MAX_ANCHOR_READ]


def test_smart_deception_replacement_is_not_moved_and_alert_is_deduplicated(
    tmp_path: Path,
) -> None:
    module = _smart_module(tmp_path)
    target = module._targets[0] / "token.txt"
    assert module._write_decoy(str(target)) is True
    target.unlink()
    target.write_bytes(b"replacement-user-object")
    module._decoys = [str(target)]
    events: list[dict] = []
    module.emit = lambda message, severity, **details: events.append(details)  # type: ignore[method-assign]

    module._trip(str(target), "object identity replaced")
    module._trip(str(target), "object identity replaced")
    module._update_health()

    assert target.read_bytes() == b"replacement-user-object"
    assert len(events) == 1
    assert module._trips == 1
    assert module._path_key(target) in module._unresolved_trips
    assert module.health < 100
    assert "unresolved=1" in module.health_note


@pytest.mark.skipif(os.name != "nt", reason="held-object rename is Windows-only")
def test_smart_deception_retirement_uses_held_object_not_path_rename(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _smart_module(tmp_path)
    target = module._targets[0] / "token.txt"
    assert module._write_decoy(str(target)) is True
    with target.open("ab") as stream:
        stream.write(b"tampered")
    monkeypatch.setattr(
        smart_deception.os,
        "rename",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("pathname rename reached")
        ),
    )

    assert module._retire_tampered_decoy(str(target)) is True
    evidence = list(module._quarantine_directory().glob("*.evidence"))

    assert not target.exists()
    assert len(evidence) == 1
    assert module._quarantine_count == 1
    assert module._quarantine_saturated is False


@pytest.mark.skipif(os.name != "nt", reason="held-object rename is Windows-only")
def test_smart_deception_path_swap_cannot_move_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _smart_module(tmp_path)
    target = module._targets[0] / "token.txt"
    displaced = module._targets[0] / "held-original.txt"
    replacement = b"replacement-user-object"
    assert module._write_decoy(str(target)) is True
    with target.open("ab") as stream:
        stream.write(b"tampered")
    real_archive = module._archive_held
    swap_blocked = [False]

    def swap_then_archive(descriptor: int, size: int) -> bool:
        try:
            target.rename(displaced)
        except OSError:
            swap_blocked[0] = True
        else:
            target.write_bytes(replacement)
        return real_archive(descriptor, size)

    monkeypatch.setattr(module, "_archive_held", swap_then_archive)

    assert module._retire_tampered_decoy(str(target)) is True
    assert swap_blocked[0] is True
    assert not target.exists()
    assert not displaced.exists()
    assert len(list(module._quarantine_directory().glob("*.evidence"))) == 1


@pytest.mark.skipif(os.name != "nt", reason="held-object retention is Windows-only")
def test_smart_deception_restage_bounds_evidence_and_logical_slot_alerts(
    tmp_path: Path,
) -> None:
    module = _smart_module(tmp_path)
    target = module._targets[0] / "token.txt"
    assert module._write_decoy(str(target)) is True
    module._decoys = [str(target)]
    events: list[dict] = []
    module.emit = lambda message, severity, **details: events.append(details)  # type: ignore[method-assign]

    for _index in range(smart_deception._QUARANTINE_MAX_FILES + 4):
        with target.open("ab") as stream:
            stream.write(b"X")
        module._trip(str(target), "anchor token missing (encrypted/overwritten)")

    evidence = list(module._quarantine_directory().glob("*.evidence"))
    assert target.exists()
    assert len(events) == 1
    assert module._trips == 1
    assert len(evidence) <= smart_deception._QUARANTINE_MAX_FILES
    assert sum(item.stat().st_size for item in evidence) <= (
        smart_deception._QUARANTINE_MAX_BYTES
    )
    assert module._quarantine_count == len(evidence)
    # Capacity pressure retains every unresolved legitimate receipt.  New
    # evidence is conservatively dropped/fail-visible rather than evicting old
    # custody merely because it is older.
    assert module._quarantine_saturated is True
    assert module._quarantine_dropped == 4


@pytest.mark.skipif(os.name != "nt", reason="held-object retention is Windows-only")
def test_smart_deception_evidence_age_and_unknown_object_are_fail_visible(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _smart_module(tmp_path)
    target = module._targets[0] / "token.txt"
    assert module._write_decoy(str(target)) is True
    with target.open("ab") as stream:
        stream.write(b"tampered")
    assert module._retire_tampered_decoy(str(target)) is True
    evidence = next(module._quarantine_directory().glob("*.evidence"))
    match = smart_deception._QUARANTINE_NAME.fullmatch(evidence.name)
    assert match is not None
    created_at = int(match.group(1)) / 1000.0
    monkeypatch.setattr(
        smart_deception.time,
        "time",
        lambda: created_at + smart_deception._QUARANTINE_MAX_AGE_S + 10,
    )

    assert module._refresh_quarantine_limits() is True
    assert not evidence.exists()
    assert module._quarantine_count == 0
    unknown = module._quarantine_directory() / "unrecognized-object"
    unknown.write_bytes(b"not Angerona evidence")
    assert module._refresh_quarantine_limits() is False
    assert module._quarantine_saturated is True
    module._decoys = [str(target)]
    module._update_health()
    assert module.health < 100
    assert "saturated=1" in module.health_note


@pytest.mark.skipif(os.name != "nt", reason="NTFS hard-link regression is Windows-only")
def test_smart_deception_hardlink_alias_cannot_mutate_sealed_evidence(
    tmp_path: Path,
) -> None:
    module = _smart_module(tmp_path)
    target = module._targets[0] / "token.txt"
    alias = module._targets[0] / "attacker-alias.txt"
    assert module._write_decoy(str(target)) is True
    os.link(target, alias)
    with alias.open("ab") as stream:
        stream.write(b"tampered-through-alias")
    module._decoys = [str(target)]
    module.emit = lambda *_args, **_kwargs: None  # type: ignore[method-assign]

    module._trip(str(target), "anchor token missing (encrypted/overwritten)")
    evidence = next(module._quarantine_directory().glob("*.evidence"))
    sealed = evidence.read_bytes()

    assert target.exists()
    assert alias.exists()
    assert not os.path.samefile(alias, evidence)
    with alias.open("ab") as stream:
        stream.write(b"post-archive-mutation")
    assert evidence.read_bytes() == sealed
    assert module._refresh_quarantine_limits() is True
    assert module._quarantine_alias_residue >= 1
    module._update_health()
    assert module.health < 100
    assert "custody_degraded=1" in module.health_note
    with evidence.open("ab") as stream:
        stream.write(b"direct-custody-drift")
    assert module._refresh_quarantine_limits() is False
    assert module._quarantine_saturated is True


def test_smart_deception_trip_dedup_expires_and_hard_caps_without_run_loop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _smart_module(tmp_path)
    target = str(module._targets[0] / "logical-slot.txt")
    module._decoys = [target]
    now = [1_000.0]
    monkeypatch.setattr(smart_deception.time, "time", lambda: now[0])
    monkeypatch.setattr(module, "_restage_tripped_decoy", lambda _path: True)
    module.emit = lambda *_args, **_kwargs: None  # type: ignore[method-assign]

    for epoch in range(5_000):
        now[0] = 1_000.0 + epoch * (smart_deception._TRIP_DEDUP_S + 1.0)
        module._trip(target, "bounded epoch test")

    assert len(module._trip_alerts) == 1
    assert module._trip_alert_evictions >= 4_999
    assert module._trip_alert_saturated is False
    module._update_health()
    assert module.health == 100
    assert "dedup_evicted=" in module.health_note

    module._trip_alerts = {
        f"{index:064x}": now[0]
        for index in range(smart_deception._TRIP_ALERT_MAX + 17)
    }
    module._prune_trip_alerts(now[0])
    module._update_health()
    assert len(module._trip_alerts) == smart_deception._TRIP_ALERT_MAX
    assert module._trip_alert_saturated is True
    assert module.health < 100
    assert "dedup_saturated=1" in module.health_note


@pytest.mark.skipif(os.name != "nt", reason="held-object cleanup is Windows-only")
def test_smart_deception_cleanup_never_unlinks_verified_decoy_by_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _smart_module(tmp_path)
    target = module._targets[0] / "token.txt"
    assert module._write_decoy(str(target)) is True
    module._decoys = [str(target)]
    module._write_manifest()
    real_unlink = Path.unlink

    def guarded_unlink(path: Path, *args, **kwargs):
        if path == target:
            raise AssertionError("verified decoy was deleted by mutable pathname")
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", guarded_unlink)
    module._cleanup_deployed_decoys()

    assert not target.exists()
    assert module._decoys == []


def _byovd_target(now: float, *, start_type: int = 2) -> actions.ByovdServiceTarget:
    return actions.ByovdServiceTarget(
        schema="angerona.byovd-service-target.v1",
        service_name="VulnerableDriver",
        service_type=1,
        service_object_id="registry:00112233",
        start_type=start_type,
        image_path=r"C:\Windows\System32\drivers\vulnerable.sys",
        image_identity="file:001122334455",
        image_sha256="a" * 64,
        signer_status="valid",
        signer_thumbprint="b" * 40,
        observed_at=now,
    )


def _byovd_authority(
    now: list[float], state: list[actions.ByovdServiceTarget]
) -> actions.ByovdResponseAuthority:
    policy = actions.ByovdPolicyEntry(
        policy_id="policy.byovd.001",
        image_sha256="a" * 64,
        signer_thumbprints=("b" * 40,),
        service_names=("VulnerableDriver",),
        valid_until=now[0] + 3600,
    )

    def observe(service_name: str) -> actions.ByovdServiceTarget:
        assert service_name == "VulnerableDriver"
        return dataclasses.replace(state[0], observed_at=now[0])

    return actions.ByovdResponseAuthority(
        b"K" * 32, (policy,), observe, clock=lambda: now[0]
    )


def test_driver_disable_rejects_plain_driver_fields_without_executing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr(
        actions,
        "run_hidden",
        lambda command, **kwargs: calls.append(command),
    )
    action = actions.DisableDriverServiceAction()

    result = action.apply(
        {"driver": "disk.sys", "path": r"C:\Windows\System32\drivers\disk.sys"},
        tmp_path,
    )

    assert action.matches({"driver": "disk.sys"}) is False
    assert result["ok"] is False
    assert result["changed"] is False
    assert "authenticated exact-target" in result["error"]
    assert calls == []


def test_driver_disable_exact_approval_remains_proposal_only_without_scm_handle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = [1_000.0]
    state = [_byovd_target(now[0])]
    authority = _byovd_authority(now, state)
    target, digest = authority.prepare("VulnerableDriver", "policy.byovd.001")
    approval = authority.approve(
        target,
        policy_id="policy.byovd.001",
        approval_id="approval.byovd.001",
        approved_target_sha256=digest,
    )
    action = actions.DisableDriverServiceAction(authority)
    calls: list[list[str]] = []

    def run(command: list[str], **kwargs):
        del command, kwargs
        raise AssertionError("proposal-only BYOVD action reached a mutation sink")

    monkeypatch.setattr(actions, "run_hidden", run)
    weakness = {"byovd_disable_approval": approval}

    assert action.matches(weakness) is True
    assert not any(
        isinstance(candidate, actions.DisableDriverServiceAction)
        for candidate in actions.ACTIONS
    )
    decision = actions.classify_remediation(weakness)
    assert decision.action is None
    assert isinstance(decision.proposal, actions.DisableDriverServiceAction)
    record = action.apply(weakness, tmp_path)
    assert record["ok"] is False
    assert record["changed"] is False
    assert record["proposal_only"] is True
    assert record["mutation_started"] is False
    assert action.verify({}, record) is False
    retained = action.apply_transactional(
        weakness,
        tmp_path,
        {"ok": True, "changed": True, "mutation_started": True},
    )
    assert retained["ok"] is False
    assert retained["changed"] is False
    assert retained["mutation_started"] is False
    assert action.rollback(record)["ok"] is False
    assert action.verify_rollback(record) is False
    assert calls == []


def test_driver_disable_post_claim_swap_never_mutates_or_reports_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = [1_000.0]
    state = [_byovd_target(now[0])]
    authority = _byovd_authority(now, state)
    target, digest = authority.prepare("VulnerableDriver", "policy.byovd.001")
    approval = authority.approve(
        target,
        policy_id="policy.byovd.001",
        approval_id="approval.byovd.swap",
        approved_target_sha256=digest,
    )
    assert authority.claim(approval) is True
    state[0] = dataclasses.replace(
        state[0], image_identity="file:postclaimreplacement"
    )
    calls: list[list[str]] = []

    def run(command: list[str], **kwargs):
        del kwargs
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(actions, "run_hidden", run)
    action = actions.DisableDriverServiceAction(authority)
    record = action.apply({"byovd_disable_approval": approval}, tmp_path)

    assert record["ok"] is False
    assert record["changed"] is False
    assert record["mutation_started"] is False
    assert calls == []


def test_driver_disable_tamper_staleness_and_target_change_fail_closed() -> None:
    now = [1_000.0]
    state = [_byovd_target(now[0])]
    authority = _byovd_authority(now, state)
    target, digest = authority.prepare("VulnerableDriver", "policy.byovd.001")
    approval = authority.approve(
        target,
        policy_id="policy.byovd.001",
        approval_id="approval.byovd.002",
        approved_target_sha256=digest,
    )
    action = actions.DisableDriverServiceAction(authority)

    tampered = dataclasses.replace(approval, target_sha256="c" * 64)
    assert authority.verify(tampered) is False
    assert action.apply({"byovd_disable_approval": tampered}, Path("."))["ok"] is False
    state[0] = dataclasses.replace(state[0], image_identity="file:replacement001")
    assert authority.verify(approval) is False
    assert action.apply({"byovd_disable_approval": approval}, Path("."))["ok"] is False
    state[0] = target
    now[0] = approval.expires_at
    assert authority.verify(approval) is False
    assert action.apply({"byovd_disable_approval": approval}, Path("."))["ok"] is False


def test_sys_bridge_never_attempts_ambient_native_import(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    imported: list[str] = []
    real_import = __import__

    def guarded_import(name, *args, **kwargs):
        if name == "syscall_bridge":
            imported.append(name)
            raise AssertionError("ambient native import attempted")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", guarded_import)
    module = importlib.reload(sys_bridge)

    assert imported == []
    assert module._BRIDGE_AVAILABLE is False
    bridge = module.SysBridgeModule()
    assert bridge.available is False
    assert "sealed private native bridge" in bridge.self_test()[1]


def test_sys_bridge_fallback_rejects_invalid_process_identifiers() -> None:
    assert sys_bridge._ct_terminate(0) is False
    assert sys_bridge._ct_terminate(-1) is False
    assert sys_bridge._ct_terminate(True) is False


def test_sys_bridge_ctypes_fallback_declares_handle_safe_prototypes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, tuple[object, ...]]] = []

    class Function:
        argtypes = None
        restype = None

        def __init__(self, name: str, result: object) -> None:
            self.name = name
            self.result = result

        def __call__(self, *args):
            calls.append((self.name, args))
            return self.result

    kernel = SimpleNamespace(
        OpenProcess=Function("OpenProcess", 1234),
        TerminateProcess=Function("TerminateProcess", 1),
        CloseHandle=Function("CloseHandle", 1),
    )
    monkeypatch.setattr(sys_bridge, "_k32", None)
    monkeypatch.setattr(sys_bridge.ctypes, "WinDLL", lambda *args, **kwargs: kernel)

    assert sys_bridge._ct_terminate(4242, 7) is True
    assert len(kernel.OpenProcess.argtypes) == 3
    assert kernel.OpenProcess.restype is sys_bridge.ctypes.c_void_p
    assert kernel.TerminateProcess.argtypes[0] is sys_bridge.ctypes.c_void_p
    assert kernel.CloseHandle.argtypes == [sys_bridge.ctypes.c_void_p]
    assert [item[0] for item in calls] == [
        "OpenProcess",
        "TerminateProcess",
        "CloseHandle",
    ]
