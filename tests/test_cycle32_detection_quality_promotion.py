from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest

from angerona.core.detection_evaluation import (
    CohortLoss,
    capture_replay_cohort,
    compare_detection_packages,
)
from angerona.core.detection_packages import DetectionPackage, seal_package
from angerona.core.detection_promotion import (
    DetectionPromotionCoordinator,
    PromotionAuthority,
    PromotionError,
    PromotionPolicy,
    digest_tuning,
)
from angerona.core.detection_quality_store import (
    DetectionQualityStore,
    QualityInputAuthority,
    QualityStoreError,
)
from angerona.core.detection_registry import DetectionPackageRegistry


class _Clock:
    def __init__(self, value: float = 1002.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def set(self, value: float) -> None:
        self.value = value


def _document(version: str, *, marker: str = "shared"):
    return {
        "schema_version": 1,
        "id": "org.angerona.cycle32-promotion",
        "version": version,
        "owner": "Angerona tests",
        "description": "Cycle 32 promotion fixture.",
        "telemetry": ["process.creation"],
        "attack": ["T1059.001"],
        "severity": "medium",
        "confidence": 80,
        "logic": {"type": "sigma-subset", "detection": {
            "selection": {"cmdline|contains": marker}, "condition": "selection",
        }},
        "fixtures": [
            {"name": "hit", "event": {"cmdline": f"tool {marker}"}, "expected_match": True},
            {"name": "miss", "event": {"cmdline": "notepad"}, "expected_match": False},
        ],
        "performance": {"max_eval_ms": 50, "max_events_per_second": 1000},
        "rollback": {"previous_digest": None, "instructions": "Restore predecessor."},
        "expires_at": "2099-01-01T00:00:00Z",
    }


def _write(path, version: str, *, marker: str = "shared"):
    document = seal_package(_document(version, marker=marker))
    path.write_text(json.dumps(document), encoding="utf-8")
    return document


def _cohort(*, source_kind: str = "curated-replay", loss: CohortLoss | None = None):
    return capture_replay_cohort(
        [
            {
                "event_id": "evt-shared", "revision": 1,
                "event": {"cmdline": "tool shared"},
                "label": True, "label_source": "curator",
            },
            {
                "event_id": "evt-none", "revision": 2,
                "event": {"cmdline": "notepad"},
                "label": False, "label_source": "curator",
            },
        ],
        source_id="local-host",
        source_kind=source_kind,
        high_water=2,
        loss=loss,
        captured_at=1000.0,
    )


def _comparison(
    active,
    candidate,
    *,
    source_kind="curated-replay",
    loss=None,
    evaluated_at=1001.0,
):
    return compare_detection_packages(
        _cohort(source_kind=source_kind, loss=loss),
        active=active,
        candidate=candidate,
        evaluated_at=evaluated_at,
    )


def _stack(tmp_path, *, policy=None):
    clock = _Clock()
    registry = DetectionPackageRegistry(tmp_path / "registry", require_signed=False)
    input_authority = QualityInputAuthority(b"i" * 32, clock=clock)
    quality = DetectionQualityStore(
        tmp_path / "quality.jsonl",
        key=b"q" * 32,
        input_authority=input_authority,
        clock=clock,
    )
    chosen_policy = policy or PromotionPolicy()
    coordinator = DetectionPromotionCoordinator(
        registry,
        quality,
        PromotionAuthority(b"p" * 32, clock=clock),
        chosen_policy,
        clock=clock,
    )
    return registry, quality, chosen_policy, coordinator, input_authority, clock


def _stage_pair(tmp_path, registry):
    first_document = _write(tmp_path / "first.json", "1.0.0")
    second_document = _write(tmp_path / "second.json", "1.1.0")
    first = registry.stage(tmp_path / "first.json")
    second = registry.stage(tmp_path / "second.json")
    assert first.ok and second.ok
    assert registry.activate(first_document["id"], first_document["digest"]).ok
    return (
        DetectionPackage(first_document),
        DetectionPackage(second_document),
        first_document["digest"],
        second_document["digest"],
    )


def _receipt(
    quality,
    input_authority,
    policy,
    active,
    candidate,
    *,
    source_kind="curated-replay",
):
    tuning = digest_tuning({"threshold": 7, "window": "5m"})
    comparison = _comparison(active, candidate, source_kind=source_kind)
    attestation = input_authority.issue(
        comparison,
        package_id=candidate.package_id,
        policy_digest=policy.digest,
        signer="analyst-1",
        tuning_digest=tuning,
        resource_coverage=("process.creation", "windows-event"),
    )
    receipt = quality.append_evaluation(
        comparison,
        package_id=candidate.package_id,
        policy_digest=policy.digest,
        signer="analyst-1",
        tuning_digest=tuning,
        resource_coverage=("process.creation", "windows-event"),
        input_attestation=attestation,
    )
    return receipt, tuning


def test_quality_receipts_are_hmac_chained_and_exact_members(tmp_path):
    _registry, quality, policy, _coordinator, input_authority, _clock = _stack(tmp_path)
    active_document = seal_package(_document("1.0.0"))
    candidate_document = seal_package(_document("1.1.0"))
    active, candidate = DetectionPackage(active_document), DetectionPackage(candidate_document)
    first, _tuning = _receipt(quality, input_authority, policy, active, candidate)
    second, _tuning = _receipt(quality, input_authority, policy, active, candidate)
    assert first.sequence == 1 and second.sequence == 2
    assert second.previous_hmac == first.receipt_hmac
    assert quality.verify(first) and quality.verify(second)
    assert quality.get(first.receipt_id) == first

    lines = (tmp_path / "quality.jsonl").read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[0])
    tampered["new_match_count"] = 99
    lines[0] = json.dumps(tampered, sort_keys=True, separators=(",", ":"))
    (tmp_path / "quality.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(QualityStoreError, match="HMAC"):
        quality.receipts()


def test_incomplete_crashed_or_truncated_evaluation_cannot_get_authority(tmp_path):
    _registry, quality, policy, _coordinator, _input_authority, _clock = _stack(tmp_path)
    candidate = DetectionPackage(seal_package(_document("1.1.0")))
    comparison = _comparison(
        None,
        candidate,
        loss=CohortLoss(overflow=True, dropped_rows=3, incomplete_reason="crash gap"),
    )
    assert not comparison.complete
    with pytest.raises(QualityStoreError, match="incomplete"):
        quality.append_evaluation(
            comparison,
            package_id=candidate.package_id,
            policy_digest=policy.digest,
            signer="analyst-1",
            tuning_digest=digest_tuning({}),
            resource_coverage=("process.creation",),
        )

    (tmp_path / "quality.jsonl").write_bytes(b'{"schema":"partial"}')
    with pytest.raises(QualityStoreError, match="incomplete"):
        quality.receipts()


def test_fixture_only_success_is_insufficient_for_promotion(tmp_path):
    registry, quality, policy, coordinator, input_authority, _clock = _stack(tmp_path)
    active, candidate, active_digest, _candidate_digest = _stage_pair(tmp_path, registry)
    quality_receipt, tuning = _receipt(
        quality, input_authority, policy, active, candidate, source_kind="fixtures"
    )
    approval = coordinator.issue_promotion_receipt(
        quality_receipt,
        signer="analyst-1",
        tuning_digest=tuning,
        resource_coverage=("process.creation", "windows-event"),
    )
    result = coordinator.promote(approval)
    assert not result.ok
    assert "fixture-only" in result.errors[0]
    assert registry.active(candidate.package_id).document["digest"] == active_digest


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("package_id", "org.angerona.substituted"),
        ("cohort_digest", "sha256:" + "a" * 64),
        ("policy_digest", "sha256:" + "b" * 64),
        ("signer", "another-analyst"),
        ("tuning_digest", "sha256:" + "c" * 64),
        ("resource_coverage", ("different",)),
    ],
)
def test_promotion_receipt_rejects_every_bound_field_substitution(tmp_path, field, value):
    registry, quality, policy, coordinator, input_authority, _clock = _stack(tmp_path)
    active, candidate, active_digest, _candidate_digest = _stage_pair(tmp_path, registry)
    quality_receipt, tuning = _receipt(
        quality, input_authority, policy, active, candidate
    )
    approval = coordinator.issue_promotion_receipt(
        quality_receipt,
        signer="analyst-1",
        tuning_digest=tuning,
        resource_coverage=("process.creation", "windows-event"),
    )
    forged = replace(approval, **{field: value})
    result = coordinator.promote(forged)
    assert not result.ok
    assert "HMAC" in result.errors[0] or "identity" in result.errors[0]
    assert registry.active(candidate.package_id).document["digest"] == active_digest


def test_stale_receipt_rejected_then_exact_promotion_and_rollback_are_one_use(tmp_path):
    policy = PromotionPolicy(receipt_ttl_seconds=10)
    registry, quality, policy, coordinator, input_authority, clock = _stack(
        tmp_path, policy=policy
    )
    active, candidate, active_digest, candidate_digest = _stage_pair(tmp_path, registry)
    quality_receipt, tuning = _receipt(
        quality, input_authority, policy, active, candidate
    )
    stale = coordinator.issue_promotion_receipt(
        quality_receipt,
        signer="analyst-1",
        tuning_digest=tuning,
        resource_coverage=("process.creation", "windows-event"),
    )
    clock.set(1013.0)
    assert not coordinator.promote(stale).ok

    clock.set(2000.0)
    approval = coordinator.issue_promotion_receipt(
        quality_receipt,
        signer="analyst-1",
        tuning_digest=tuning,
        resource_coverage=("process.creation", "windows-event"),
    )
    clock.set(2001.0)
    promoted = coordinator.promote(approval)
    assert promoted.ok
    assert promoted.activation_epoch == 1
    assert registry.active(candidate.package_id).document["digest"] == candidate_digest
    clock.set(2002.0)
    assert not coordinator.promote(approval).ok

    clock.set(2003.0)
    rollback = coordinator.issue_rollback_receipt(
        package_id=candidate.package_id,
        signer="analyst-1",
        tuning_digest=tuning,
        resource_coverage=("process.creation", "windows-event"),
    )
    clock.set(2004.0)
    rolled_back = coordinator.rollback(rollback)
    assert rolled_back.ok
    assert rolled_back.activation_epoch == 2
    assert registry.active(candidate.package_id).document["digest"] == active_digest
    clock.set(2005.0)
    assert not coordinator.rollback(rollback).ok
    # Returning to the old active digest cannot revive the consumed promotion.
    assert not coordinator.promote(approval).ok


def test_concurrent_candidates_have_exactly_one_winner(tmp_path):
    registry, quality, policy, coordinator, input_authority, _clock = _stack(tmp_path)
    active_document = _write(tmp_path / "first.json", "1.0.0")
    candidate_a_document = _write(tmp_path / "a.json", "1.1.0")
    candidate_b_document = _write(tmp_path / "b.json", "1.2.0")
    for name in ("first.json", "a.json", "b.json"):
        assert registry.stage(tmp_path / name).ok
    assert registry.activate(active_document["id"], active_document["digest"]).ok
    active = DetectionPackage(active_document)
    approvals = []
    for document in (candidate_a_document, candidate_b_document):
        candidate = DetectionPackage(document)
        receipt, tuning = _receipt(
            quality, input_authority, policy, active, candidate
        )
        approvals.append(coordinator.issue_promotion_receipt(
            receipt,
            signer="analyst-1",
            tuning_digest=tuning,
            resource_coverage=("process.creation", "windows-event"),
        ))
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(coordinator.promote, approvals))
    assert sum(result.ok for result in results) == 1
    active_digest = registry.active(active_document["id"]).document["digest"]
    assert active_digest in {candidate_a_document["digest"], candidate_b_document["digest"]}


def test_registry_crash_is_rejected_without_false_completion(tmp_path, monkeypatch):
    registry, quality, policy, coordinator, input_authority, _clock = _stack(tmp_path)
    active, candidate, active_digest, _candidate_digest = _stage_pair(tmp_path, registry)
    receipt, tuning = _receipt(quality, input_authority, policy, active, candidate)
    approval = coordinator.issue_promotion_receipt(
        receipt,
        signer="analyst-1",
        tuning_digest=tuning,
        resource_coverage=("process.creation", "windows-event"),
    )

    def crash(*_args, **_kwargs):
        raise RuntimeError("simulated activation crash")

    monkeypatch.setattr(registry, "activate", crash)
    result = coordinator.promote(approval)
    assert not result.ok and "simulated activation crash" in result.errors[0]
    assert registry.active(candidate.package_id).document["digest"] == active_digest


def test_sanitized_quality_export_omits_authority_signer_and_event_data(tmp_path):
    _registry, quality, policy, _coordinator, input_authority, _clock = _stack(tmp_path)
    active = DetectionPackage(seal_package(_document("1.0.0")))
    candidate = DetectionPackage(seal_package(_document("1.1.0")))
    _receipt(quality, input_authority, policy, active, candidate)
    exported = quality.sanitized_export()
    rendered = json.dumps(exported, sort_keys=True)
    assert "analyst-1" not in rendered
    assert "receipt_hmac" not in rendered
    assert "previous_hmac" not in rendered
    assert "cmdline" not in rendered
    assert "local-host" not in rendered
    assert "process.creation" not in rendered
    assert "windows-event" not in rendered
    assert exported[0]["integrity_scope"] == "authenticated-present-prefix"
    assert exported[0]["external_suffix_anchor"] is False


def test_self_attested_source_signer_and_coverage_are_explicitly_non_promotable(
    tmp_path,
):
    registry, quality, policy, coordinator, _input_authority, _clock = _stack(tmp_path)
    active, candidate, active_digest, _candidate_digest = _stage_pair(tmp_path, registry)
    comparison = _comparison(active, candidate)
    tuning = digest_tuning({"threshold": 7})
    receipt = quality.append_evaluation(
        comparison,
        package_id=candidate.package_id,
        policy_digest=policy.digest,
        signer="self-asserted-admin",
        tuning_digest=tuning,
        resource_coverage=("everything",),
    )
    assert receipt.input_trust == "self-attested"
    approval = coordinator.issue_promotion_receipt(
        receipt,
        signer="self-asserted-admin",
        tuning_digest=tuning,
        resource_coverage=("everything",),
    )
    result = coordinator.promote(approval)
    assert not result.ok
    assert "self-attested" in result.errors[0]
    assert registry.active(candidate.package_id).document["digest"] == active_digest


def test_quality_input_attestation_rejects_coverage_substitution(tmp_path):
    _registry, quality, policy, _coordinator, input_authority, _clock = _stack(tmp_path)
    active = DetectionPackage(seal_package(_document("1.0.0")))
    candidate = DetectionPackage(seal_package(_document("1.1.0")))
    comparison = _comparison(active, candidate)
    tuning = digest_tuning({})
    attestation = input_authority.issue(
        comparison,
        package_id=candidate.package_id,
        signer="analyst-1",
        policy_digest=policy.digest,
        tuning_digest=tuning,
        resource_coverage=("process.creation",),
    )
    with pytest.raises(QualityStoreError, match="coverage substitution"):
        quality.append_evaluation(
            comparison,
            package_id=candidate.package_id,
            policy_digest=policy.digest,
            signer="analyst-1",
            tuning_digest=tuning,
            resource_coverage=("process.creation", "forged-complete-coverage"),
            input_attestation=attestation,
        )


def test_quality_age_uses_injected_clock_and_cannot_be_overridden_by_caller(tmp_path):
    policy = PromotionPolicy(maximum_quality_age_seconds=10)
    registry, quality, policy, coordinator, input_authority, clock = _stack(
        tmp_path, policy=policy
    )
    active, candidate, active_digest, _candidate_digest = _stage_pair(tmp_path, registry)
    receipt, tuning = _receipt(quality, input_authority, policy, active, candidate)
    approval = coordinator.issue_promotion_receipt(
        receipt,
        signer="analyst-1",
        tuning_digest=tuning,
        resource_coverage=("process.creation", "windows-event"),
    )
    clock.set(1013.0)
    result = coordinator.promote(approval)
    assert not result.ok
    assert "maximum policy age" in result.errors[0]
    assert registry.active(candidate.package_id).document["digest"] == active_digest
    with pytest.raises(TypeError):
        coordinator.promote(approval, now=1003.0)


def test_evaluated_at_is_attested_receipted_one_use_and_drives_oldest_age(tmp_path):
    policy = PromotionPolicy(maximum_quality_age_seconds=10)
    registry, quality, policy, coordinator, input_authority, _clock = _stack(
        tmp_path, policy=policy
    )
    active, candidate, active_digest, _candidate_digest = _stage_pair(tmp_path, registry)
    comparison = _comparison(active, candidate, evaluated_at=900.0)
    tuning = digest_tuning({"threshold": 7})
    attestation = input_authority.issue(
        comparison,
        package_id=candidate.package_id,
        signer="analyst-1",
        policy_digest=policy.digest,
        tuning_digest=tuning,
        resource_coverage=("process.creation", "windows-event"),
    )
    receipt = quality.append_evaluation(
        comparison,
        package_id=candidate.package_id,
        signer="analyst-1",
        policy_digest=policy.digest,
        tuning_digest=tuning,
        resource_coverage=("process.creation", "windows-event"),
        input_attestation=attestation,
    )
    assert attestation.evaluated_at == receipt.evaluated_at == 900.0
    with pytest.raises(QualityStoreError, match="already consumed"):
        quality.append_evaluation(
            comparison,
            package_id=candidate.package_id,
            signer="analyst-1",
            policy_digest=policy.digest,
            tuning_digest=tuning,
            resource_coverage=("process.creation", "windows-event"),
            input_attestation=attestation,
        )
    with pytest.raises(QualityStoreError, match="HMAC"):
        quality.append_evaluation(
            comparison,
            package_id=candidate.package_id,
            signer="analyst-1",
            policy_digest=policy.digest,
            tuning_digest=tuning,
            resource_coverage=("process.creation", "windows-event"),
            input_attestation=replace(attestation, evaluated_at=1001.0),
        )
    approval = coordinator.issue_promotion_receipt(
        receipt,
        signer="analyst-1",
        tuning_digest=tuning,
        resource_coverage=("process.creation", "windows-event"),
    )
    result = coordinator.promote(approval)
    assert not result.ok and "maximum policy age" in result.errors[0]
    assert registry.active(candidate.package_id).document["digest"] == active_digest


def test_valid_state_and_checkpoint_rollback_is_detected_by_independent_anchor(tmp_path):
    registry, quality, policy, coordinator, input_authority, clock = _stack(tmp_path)
    original_state = coordinator.state_path.read_bytes()
    original_checkpoint = coordinator.checkpoint_path.read_bytes()
    active, candidate, _active_digest, _candidate_digest = _stage_pair(tmp_path, registry)
    receipt, tuning = _receipt(quality, input_authority, policy, active, candidate)
    approval = coordinator.issue_promotion_receipt(
        receipt,
        signer="analyst-1",
        tuning_digest=tuning,
        resource_coverage=("process.creation", "windows-event"),
    )
    assert coordinator.promote(approval).ok
    anchor_after_consumption = coordinator.anchor_path.read_bytes()
    coordinator.state_path.write_bytes(original_state)
    coordinator.checkpoint_path.write_bytes(original_checkpoint)
    assert coordinator.anchor_path.read_bytes() == anchor_after_consumption
    with pytest.raises(PromotionError, match="monotonic rollback"):
        DetectionPromotionCoordinator(
            registry,
            quality,
            coordinator.authority,
            policy,
            state_path=coordinator.state_path,
            clock=clock,
        )


def test_missing_state_or_checkpoint_fails_closed_and_used_ids_survive_restart(tmp_path):
    registry, quality, policy, coordinator, input_authority, clock = _stack(tmp_path)
    active, candidate, _active_digest, _candidate_digest = _stage_pair(tmp_path, registry)
    receipt, tuning = _receipt(quality, input_authority, policy, active, candidate)
    approval = coordinator.issue_promotion_receipt(
        receipt,
        signer="analyst-1",
        tuning_digest=tuning,
        resource_coverage=("process.creation", "windows-event"),
    )
    assert coordinator.promote(approval).ok
    state = json.loads(coordinator.state_path.read_text(encoding="utf-8"))
    assert state["used_receipts"] == [
        {"receipt_id": approval.receipt_id, "expires_at": approval.expires_at}
    ]
    restarted = DetectionPromotionCoordinator(
        registry,
        quality,
        coordinator.authority,
        policy,
        state_path=coordinator.state_path,
        clock=clock,
    )
    assert not restarted.promote(approval).ok

    restarted.state_path.unlink()
    assert not restarted.promote(approval).ok
    with pytest.raises(PromotionError, match="state/checkpoint pair"):
        DetectionPromotionCoordinator(
            registry,
            quality,
            coordinator.authority,
            policy,
            state_path=restarted.state_path,
            clock=clock,
        )
    restarted.checkpoint_path.unlink()
    with pytest.raises(PromotionError, match="cannot be reinitialized"):
        DetectionPromotionCoordinator(
            registry,
            quality,
            coordinator.authority,
            policy,
            state_path=restarted.state_path,
            clock=clock,
        )


def test_valid_suffix_truncation_is_not_misreported_as_externally_anchored(tmp_path):
    _registry, quality, policy, _coordinator, input_authority, _clock = _stack(tmp_path)
    active = DetectionPackage(seal_package(_document("1.0.0")))
    candidate = DetectionPackage(seal_package(_document("1.1.0")))
    _receipt(quality, input_authority, policy, active, candidate)
    _receipt(quality, input_authority, policy, active, candidate)
    lines = quality.path.read_bytes().splitlines(keepends=True)
    quality.path.write_bytes(lines[0])
    assert len(quality.receipts()) == 1
    exported = quality.sanitized_export()
    assert exported[0]["integrity_scope"] == "authenticated-present-prefix"
    assert exported[0]["external_suffix_anchor"] is False
