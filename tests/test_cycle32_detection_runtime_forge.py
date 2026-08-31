from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor

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
    PromotionPolicy,
    digest_tuning,
)
from angerona.core.detection_quality_store import (
    DetectionQualityStore,
    QualityInputAuthority,
)
from angerona.core.detection_registry import DetectionPackageRegistry
from angerona.core.eventbus import Event, EventBus, Severity
from angerona.core.module_contract import build_capability_contract
from angerona.gui.detection_forge import DetectionForgeService, DetectionForgeWidget
from angerona.modules.detection_runtime import (
    DetectionRuntimeEngine,
    DetectionRuntimeError,
    DetectionRuntimeModule,
)


def _package(
    *, marker: str = "suspicious", version: str = "1.0.0", max_eps: int = 1000,
):
    document = {
        "schema_version": 1,
        "id": "org.angerona.cycle32-runtime",
        "version": version,
        "owner": "Angerona tests",
        "description": "Cycle 32 alert-inert runtime fixture.",
        "telemetry": ["process.creation"],
        "attack": ["T1059.001"],
        "severity": "high",
        "confidence": 85,
        "logic": {"type": "sigma-subset", "detection": {
            "selection": {"cmdline|contains": marker}, "condition": "selection",
        }},
        "fixtures": [
            {"name": "hit", "event": {"cmdline": f"tool {marker}"}, "expected_match": True},
            {"name": "miss", "event": {"cmdline": "notepad"}, "expected_match": False},
        ],
        "performance": {"max_eval_ms": 50, "max_events_per_second": max_eps},
        "rollback": {"previous_digest": None, "instructions": "Restore predecessor."},
        "expires_at": "2099-01-01T00:00:00Z",
    }
    return DetectionPackage(seal_package(document))


def _event(event_id: str, command: str = "tool suspicious"):
    return Event(
        module="Process Monitor",
        message="process creation",
        severity=Severity.MEDIUM,
        ts=100.0,
        details={"event_id": event_id, "cmdline": command},
    )


def _authoritative_active(tmp_path, engine, package, *, epoch: int = 1):
    registry = DetectionPackageRegistry(tmp_path / "active-registry", require_signed=False)
    source = tmp_path / f"{package.document['version']}.json"
    source.write_text(json.dumps(package.document), encoding="utf-8")
    report = registry.stage(source)
    assert report.ok and report.digest == package.document["digest"]
    assert registry.activate(package.package_id, package.document["digest"]).ok
    assert engine.sync_active_from_registry(
        registry,
        package_id=package.package_id,
        expected_digest=package.document["digest"],
        activation_epoch=epoch,
    ) == (package.document["digest"],)
    return registry


def test_shadow_is_alert_inert_and_has_no_evidence_incident_soar_or_response_leak():
    active_publications = []
    engine = DetectionRuntimeEngine(active_sink=active_publications.append)
    engine.bind_shadow(_package())
    assert engine.submit_shadow(_event("evt-shadow"))
    assert engine.process() == (0, 1)
    snapshot = engine.snapshot()
    assert active_publications == []
    assert snapshot.active_findings == 0
    assert len(snapshot.shadow_observations) == 1
    observation = snapshot.shadow_observations[0]
    assert observation.matched
    assert not hasattr(observation, "event")
    assert not hasattr(observation, "response_actions")

    # Even when the engine belongs to a bound module, a shadow match does not
    # enter EventBus history or any downstream subscriber.
    bus = EventBus()
    module = DetectionRuntimeModule(engine=DetectionRuntimeEngine())
    module.bind(bus)
    module.engine.bind_shadow(_package())
    module._on_event(_event("evt-module-shadow"))
    module.engine.process()
    assert bus.recent(10) == []


def test_shadow_flood_cannot_evict_reserved_active_lane_and_drops_are_visible(tmp_path):
    findings = []
    engine = DetectionRuntimeEngine(
        active_capacity=8,
        shadow_capacity=8,
        active_sink=findings.append,
    )
    package = _package()
    _authoritative_active(tmp_path, engine, package)
    engine.bind_shadow(package)
    for index in range(9):
        engine.submit_shadow(_event(f"evt-shadow-{index}"))
    before = engine.snapshot()
    assert before.shadow_drops == 1
    assert before.active_queue_depth == 0

    assert engine.submit(_event("evt-active"), include_shadow=False)
    active_count, shadow_count = engine.process(max_active=8, max_shadow=0)
    assert (active_count, shadow_count) == (1, 0)
    assert len(findings) == 1
    assert findings[0].event_id.startswith("runtime-")
    after = engine.snapshot()
    assert after.active_drops == 0
    assert after.shadow_queue_depth == 8


def test_active_findings_are_digest_bound_nonrecursive_deduplicated_and_observe_only(
    tmp_path,
):
    findings = []
    engine = DetectionRuntimeEngine(active_sink=findings.append)
    package = _package()
    digest = package.document["digest"]
    _authoritative_active(tmp_path, engine, package)
    event = _event("evt-one")
    assert engine.submit(event, include_shadow=False)
    assert engine.submit(event, include_shadow=False)
    engine.process()
    assert len(findings) == 1
    finding = findings[0]
    assert finding.package_digest == digest
    details = finding.event_details()
    assert details["response_authorized"] is False
    assert details["response_authority"] == "observe-only"
    assert details["response_actions"] == []
    assert details["incident_authorized"] is False
    assert details["soar_authorized"] is False
    assert engine.snapshot().active_deduplicated == 1

    spoofed_recursive = Event(
        module=DetectionRuntimeModule.name,
        message="generated",
        severity=Severity.HIGH,
        details={
            "detection_runtime_generated": True,
            "parent_detection_digest": digest,
            "event_id": "evt-recursive",
            "cmdline": "tool suspicious",
        },
    )
    assert engine.submit(spoofed_recursive, include_shadow=False)
    engine.process()
    assert len(findings) == 2
    assert engine.snapshot().recursive_events_rejected == 0


def test_per_rule_rate_budget_is_enforced_without_shadow_cross_talk(tmp_path):
    findings = []
    engine = DetectionRuntimeEngine(active_sink=findings.append, clock=lambda: 50.0)
    package = _package(max_eps=1)
    _authoritative_active(tmp_path, engine, package)
    engine.bind_shadow(package)
    assert engine.submit(_event("evt-a"), include_shadow=False)
    assert engine.submit(_event("evt-b"), include_shadow=False)
    engine.process(max_shadow=0)
    snapshot = engine.snapshot()
    assert len(findings) == 1
    assert snapshot.active_budget_drops == 1
    assert snapshot.shadow_budget_drops == 0


def test_bound_rule_mutation_fails_integrity_without_emitting_detection(tmp_path):
    findings = []
    engine = DetectionRuntimeEngine(active_sink=findings.append)
    _authoritative_active(tmp_path, engine, _package())
    bound_document = engine._active_rules[0].package.document
    bound_document["confidence"] = 99
    engine.submit(_event("evt-mutated"), include_shadow=False)
    engine.process()
    assert findings == []
    assert engine.snapshot().rule_integrity_failures == 1


def test_active_lane_rejects_caller_packages_and_requires_exact_registry_state(tmp_path):
    engine = DetectionRuntimeEngine()
    package = _package()
    assert not hasattr(engine, "bind_active")
    registry = DetectionPackageRegistry(tmp_path / "staged-only", require_signed=False)
    source = tmp_path / "staged.json"
    source.write_text(json.dumps(package.document), encoding="utf-8")
    assert registry.stage(source).ok
    with pytest.raises(DetectionRuntimeError, match="active digest"):
        engine.sync_active_from_registry(
            registry,
            package_id=package.package_id,
            expected_digest=package.document["digest"],
            activation_epoch=1,
        )


def test_spoofed_recursion_markers_are_evaluated_but_internal_publication_is_not(
    tmp_path,
):
    engine = DetectionRuntimeEngine()
    _authoritative_active(tmp_path, engine, _package())
    module = DetectionRuntimeModule(engine=engine)
    bus = EventBus()
    module.bind(bus)
    bus.subscribe(module._on_event)
    spoof = Event(
        module=DetectionRuntimeModule.name,
        message="attacker controlled",
        severity=Severity.HIGH,
        details={
            "detection_runtime_generated": True,
            "parent_detection_digest": "sha256:" + "f" * 64,
            "event_id": "claimed-recursion",
            "cmdline": "tool suspicious",
        },
    )
    bus.publish(spoof)
    engine.process(max_shadow=0)
    snapshot = engine.snapshot()
    assert snapshot.active_findings == 1
    assert snapshot.recursive_events_rejected == 1
    assert snapshot.active_queue_depth == 0
    assert len(bus.recent(10)) == 2


def test_claimed_id_and_source_cursor_collisions_are_visible_not_dedupe_poison(
    tmp_path,
):
    findings = []
    engine = DetectionRuntimeEngine(active_sink=findings.append)
    _authoritative_active(tmp_path, engine, _package())
    assert engine.submit(_event("same-claim", "tool suspicious one"), source_cursor=7)
    assert engine.submit(_event("same-claim", "tool suspicious two"), source_cursor=7)
    engine.process(max_shadow=0)
    snapshot = engine.snapshot()
    assert len(findings) == 2
    assert snapshot.event_id_collisions == 1
    assert snapshot.source_cursor_collisions == 1
    assert snapshot.active_deduplicated == 0


def test_budget_rejection_does_not_mark_event_seen_before_successful_evaluation(tmp_path):
    now = [50.0]
    findings = []
    engine = DetectionRuntimeEngine(active_sink=findings.append, clock=lambda: now[0])
    _authoritative_active(tmp_path, engine, _package(max_eps=1))
    first = _event("evt-first")
    retry = _event("evt-retry")
    assert engine.submit(first, include_shadow=False)
    assert engine.submit(retry, include_shadow=False)
    engine.process(max_shadow=0)
    assert len(findings) == 1
    assert engine.snapshot().active_budget_drops == 1
    now[0] = 52.0
    assert engine.submit(retry, include_shadow=False)
    engine.process(max_shadow=0)
    assert len(findings) == 2


def test_activation_epoch_drops_queued_old_rule_work_instead_of_reinterpreting_it(
    tmp_path,
):
    findings = []
    engine = DetectionRuntimeEngine(active_sink=findings.append)
    first = _package(version="1.0.0")
    registry = _authoritative_active(tmp_path, engine, first, epoch=1)
    assert engine.submit(_event("queued-under-one"), include_shadow=False)

    second = _package(marker="second-marker", version="1.1.0")
    source = tmp_path / "second.json"
    source.write_text(json.dumps(second.document), encoding="utf-8")
    assert registry.stage(source).ok
    assert registry.activate(second.package_id, second.document["digest"]).ok
    engine.sync_active_from_registry(
        registry,
        package_id=second.package_id,
        expected_digest=second.document["digest"],
        activation_epoch=2,
    )
    snapshot = engine.snapshot()
    assert snapshot.active_activation_epoch == 2
    assert snapshot.active_epoch_drops == 1
    assert snapshot.active_queue_depth == 0
    engine.process(max_shadow=0)
    assert findings == []


def test_active_backlog_strictly_preempts_bounded_shadow_work(tmp_path):
    findings = []
    engine = DetectionRuntimeEngine(active_sink=findings.append)
    package = _package()
    _authoritative_active(tmp_path, engine, package)
    engine.bind_shadow(package)
    assert engine.submit(_event("active-a"), include_shadow=False)
    assert engine.submit(_event("active-b"), include_shadow=False)
    assert engine.submit_shadow(_event("shadow-a"))
    assert engine.process(max_active=1, max_shadow=8) == (1, 0)
    assert engine.snapshot().shadow_queue_depth == 1
    active, shadow = engine.process(
        max_active=8,
        max_shadow=8,
        max_shadow_evaluations=1,
        shadow_slice_ms=5,
    )
    assert (active, shadow) == (1, 1)
    assert len(findings) == 2


def test_inflight_active_process_serializes_before_any_shadow_work(tmp_path, monkeypatch):
    engine = DetectionRuntimeEngine()
    package = _package()
    _authoritative_active(tmp_path, engine, package)
    engine.bind_shadow(package)
    active_started = threading.Event()
    shadow_started = threading.Event()
    release_active = threading.Event()
    original = DetectionPackage.evaluate

    def blocking_evaluate(self, event):
        command = str(event.get("cmdline", ""))
        if "active-block" in command:
            active_started.set()
            assert release_active.wait(5)
        elif "shadow-block" in command:
            shadow_started.set()
        return original(self, event)

    monkeypatch.setattr(DetectionPackage, "evaluate", blocking_evaluate)
    assert engine.submit(
        _event("active-inflight", "tool suspicious active-block"),
        include_shadow=False,
    )
    assert engine.submit_shadow(_event("shadow-waiting", "tool suspicious shadow-block"))
    with ThreadPoolExecutor(max_workers=2) as executor:
        active_future = executor.submit(engine.process, max_active=1, max_shadow=0)
        assert active_started.wait(2)
        shadow_future = executor.submit(engine.process, max_active=0, max_shadow=1)
        try:
            assert not shadow_started.wait(0.2)
        finally:
            release_active.set()
        assert active_future.result(timeout=5) == (1, 0)
        assert shadow_future.result(timeout=5) == (0, 1)
    assert shadow_started.is_set()


def test_registry_transition_sync_failure_clears_retired_active_rules(
    tmp_path, monkeypatch,
):
    clock = lambda: 1002.0
    registry = DetectionPackageRegistry(tmp_path / "registry", require_signed=False)
    input_authority = QualityInputAuthority(b"i" * 32, clock=clock)
    quality = DetectionQualityStore(
        tmp_path / "quality.jsonl",
        key=b"q" * 32,
        input_authority=input_authority,
        clock=clock,
    )
    policy = PromotionPolicy()
    coordinator = DetectionPromotionCoordinator(
        registry,
        quality,
        PromotionAuthority(b"p" * 32, clock=clock),
        policy,
        clock=clock,
    )
    active = _package(version="1.0.0")
    candidate = _package(version="1.1.0")
    for name, package in (("active.json", active), ("candidate.json", candidate)):
        path = tmp_path / name
        path.write_text(json.dumps(package.document), encoding="utf-8")
        assert registry.stage(path).ok
    initial_cohort = capture_replay_cohort(
        [
            {
                "event_id": "hit", "revision": 1,
                "event": {"cmdline": "tool suspicious"},
                "label": True, "label_source": "curator",
            },
            {
                "event_id": "miss", "revision": 2,
                "event": {"cmdline": "notepad"},
                "label": False, "label_source": "curator",
            },
        ],
        source_id="local-host",
        source_kind="curated-replay",
        high_water=2,
        captured_at=1000.0,
    )
    tuning = digest_tuning({"threshold": 7})
    initial_comparison = compare_detection_packages(
        initial_cohort, active=None, candidate=active, evaluated_at=1001.0,
    )
    initial_attestation = input_authority.issue(
        initial_comparison,
        package_id=active.package_id,
        signer="analyst-1",
        policy_digest=policy.digest,
        tuning_digest=tuning,
        resource_coverage=("process.creation",),
    )
    initial_quality = quality.append_evaluation(
        initial_comparison,
        package_id=active.package_id,
        signer="analyst-1",
        policy_digest=policy.digest,
        tuning_digest=tuning,
        resource_coverage=("process.creation",),
        input_attestation=initial_attestation,
    )
    initial_result = coordinator.promote(coordinator.issue_promotion_receipt(
        initial_quality,
        signer="analyst-1",
        tuning_digest=tuning,
        resource_coverage=("process.creation",),
    ))
    assert initial_result.ok
    runtime = DetectionRuntimeEngine()
    runtime.sync_active_from_registry(
        registry,
        package_id=active.package_id,
        expected_digest=active.document["digest"],
        activation_epoch=initial_result.activation_epoch,
    )
    original_sync = runtime.sync_active_set_from_registry
    cohort = capture_replay_cohort(
        [
            {
                "event_id": "hit", "revision": 1,
                "event": {"cmdline": "tool suspicious"},
                "label": True, "label_source": "curator",
            },
            {
                "event_id": "miss", "revision": 2,
                "event": {"cmdline": "notepad"},
                "label": False, "label_source": "curator",
            },
        ],
        source_id="local-host",
        source_kind="curated-replay",
        high_water=2,
        captured_at=1000.0,
    )
    comparison = compare_detection_packages(
        cohort, active=active, candidate=candidate, evaluated_at=1001.0
    )
    attestation = input_authority.issue(
        comparison,
        package_id=candidate.package_id,
        signer="analyst-1",
        policy_digest=policy.digest,
        tuning_digest=tuning,
        resource_coverage=("process.creation",),
    )
    quality_receipt = quality.append_evaluation(
        comparison,
        package_id=candidate.package_id,
        signer="analyst-1",
        policy_digest=policy.digest,
        tuning_digest=tuning,
        resource_coverage=("process.creation",),
        input_attestation=attestation,
    )
    approval = coordinator.issue_promotion_receipt(
        quality_receipt,
        signer="analyst-1",
        tuning_digest=tuning,
        resource_coverage=("process.creation",),
    )
    service = DetectionForgeService(
        registry=registry,
        runtime=runtime,
        quality_store=quality,
        promotion=coordinator,
    )

    def fail_sync(*_args, **_kwargs):
        raise RuntimeError("simulated runtime reconciliation failure")

    monkeypatch.setattr(runtime, "sync_active_set_from_registry", fail_sync)
    result = service.promote(approval)
    assert not result.ok and result.state == "runtime-fail-closed"
    assert registry.active(candidate.package_id).document["digest"] == candidate.document["digest"]
    assert runtime.snapshot().active_digests == ()
    # The exact committed epoch remains safely retryable after the transient
    # binding fault, but only against the authoritative registry digest.
    assert original_sync(
        registry,
        expected_bindings={candidate.package_id: candidate.document["digest"]},
        activation_epoch=result.activation_epoch,
    ) == (candidate.document["digest"],)


def test_detection_runtime_has_native_v12_detect_only_contract():
    module = DetectionRuntimeModule()
    contract = build_capability_contract(
        module, capability_id="angerona.detection-runtime"
    )
    assert contract.schema_version == 12
    assert contract.implementation_version == "1.13.0"
    assert contract.metadata_level == "native"
    assert contract.mode == "detect"
    assert contract.response_authority == "none"
    assert contract.egress == "none"
    assert contract.high_risk_permissions == ()
    assert contract.metadata_gaps == ()
    assert module.self_test()[0]


def test_detection_forge_service_and_embeddable_widget_expose_seven_clickable_views(
    tmp_path,
):
    registry = DetectionPackageRegistry(tmp_path / "registry", require_signed=False)
    runtime = DetectionRuntimeEngine()
    quality = DetectionQualityStore(tmp_path / "quality.jsonl", key=b"q" * 32)
    service = DetectionForgeService(
        registry=registry,
        runtime=runtime,
        quality_store=quality,
    )
    package = _package()
    cohort = service.replay(
        [
            {
                "event_id": "evt-hit", "revision": 1,
                "event": {"cmdline": "tool suspicious"},
                "label": True, "label_source": "curator",
            },
            {
                "event_id": "evt-miss", "revision": 2,
                "event": {"cmdline": "notepad"},
                "label": False, "label_source": "curator",
            },
        ],
        source_id=r"C:\Users\operator\sensitive\replay.jsonl",
        source_kind="curated-replay",
        high_water=2,
    )
    assert cohort.cohort_digest.startswith("sha256:")
    comparison = service.compare(active=None, candidate=package)
    policy = PromotionPolicy()
    service.record_quality(
        package_id=package.package_id,
        policy_digest=policy.digest,
        signer="analyst-1",
        tuning_digest=digest_tuning({"threshold": 7}),
        resource_coverage=("process.creation",),
    )
    service.shadow(package)
    export = service.sanitized_export()
    rendered = json.dumps(export, sort_keys=True)
    assert export["contains_raw_events"] is False
    assert "evt-hit" not in rendered
    assert "analyst-1" not in rendered
    assert "receipt_hmac" not in rendered
    assert "source_id" not in export["cohort"]
    assert "operator" not in rendered
    assert "replay.jsonl" not in rendered
    assert comparison.precision == 1.0 and comparison.recall == 1.0

    widget = DetectionForgeWidget(service)
    assert widget.tabs.count() == 7
    assert tuple(widget.tabs.tabText(index) for index in range(7)) == widget.VIEW_NAMES
    assert all(table.isSortingEnabled() for table in widget._tables.values())
    assert all(table.selectionBehavior() for table in widget._tables.values())
    # Every view has at least one exact gate row and each row carries clickable detail data.
    assert all(table.rowCount() >= 1 for table in widget._tables.values())
    for table in widget._tables.values():
        assert isinstance(table.item(0, 0).data(256), dict)  # Qt.UserRole
    widget.close()


def test_sanitized_export_recursively_omits_incomplete_reason_and_coverage_paths(
    tmp_path,
):
    registry = DetectionPackageRegistry(tmp_path / "registry", require_signed=False)
    quality = DetectionQualityStore(tmp_path / "quality.jsonl", key=b"q" * 32)
    service = DetectionForgeService(
        registry=registry,
        runtime=DetectionRuntimeEngine(),
        quality_store=quality,
    )
    secret = r"C:\Users\operator\Sensitive Evidence\capture.evtx"
    service.replay(
        [{
            "event_id": "secret-event-name",
            "revision": 1,
            "event": {"cmdline": "tool suspicious"},
            "label": True,
            "label_source": "operator-private-label",
        }],
        source_id=secret,
        source_kind="import",
        high_water=1,
        loss=CohortLoss(incomplete_reason=secret),
    )
    rendered = json.dumps(service.sanitized_export(), sort_keys=True)
    assert secret not in rendered
    assert "Sensitive Evidence" not in rendered
    assert "secret-event-name" not in rendered
    assert "operator-private-label" not in rendered


def test_sanitized_export_recursively_redacts_nested_open_codes(tmp_path, monkeypatch):
    registry = DetectionPackageRegistry(tmp_path / "registry", require_signed=False)
    quality = DetectionQualityStore(tmp_path / "quality.jsonl", key=b"q" * 32)
    service = DetectionForgeService(
        registry=registry,
        runtime=DetectionRuntimeEngine(),
        quality_store=quality,
    )
    secret = r"C:\Users\operator\private\evaluation.evtx"
    monkeypatch.setattr(
        quality,
        "sanitized_export",
        lambda: ({
            "source_kind_code": secret,
            "reason_codes": ["caller-free-form-reason"],
            "nested": {"errors": [secret], "note": secret},
        },),
    )
    export = service.sanitized_export()
    rendered = json.dumps(export, sort_keys=True)
    assert secret not in rendered
    receipt = export["quality_receipts"][0]
    assert receipt["source_kind_code"] == "invalid"
    assert receipt["reason_codes"] == []
    assert "errors" not in receipt["nested"]
    assert receipt["nested"]["note"] == "redacted"
