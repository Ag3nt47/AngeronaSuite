from __future__ import annotations

import json
import time
from base64 import b64encode
from dataclasses import dataclass
from types import SimpleNamespace

import pytest

from angerona.core.detection_evaluation import (
    capture_replay_cohort,
    compare_detection_packages,
)
from angerona.core.detection_packages import DetectionPackage, seal_package
from angerona.core.detection_promotion import (
    DetectionPromotionCoordinator,
    PromotionAuthority,
    PromotionPolicy,
    PromotionResult,
    digest_tuning,
)
from angerona.core.detection_quality_store import (
    DetectionQualityStore,
    QualityInputAuthority,
)
from angerona.core.detection_registry import DetectionPackageRegistry
from angerona.core.eventbus import Event, EventBus, Severity
from angerona.gui.detection_forge import DetectionForgeService
from angerona.modules.detection_runtime import (
    DetectionRuntimeEngine,
    DetectionRuntimeModule,
)


class _Clock:
    def __init__(self, value: float = 1002.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


def _document(version: str, marker: str, *, package_id: str = "org.angerona.round2"):
    return seal_package({
        "schema_version": 1,
        "id": package_id,
        "version": version,
        "owner": "Angerona cycle 34",
        "description": "Round 2 detection governance regression fixture.",
        "telemetry": ["process.creation"],
        "attack": ["T1059.001"],
        "severity": "high",
        "confidence": 90,
        "logic": {"type": "sigma-subset", "detection": {
            "selection": {"cmdline|contains": marker},
            "condition": "selection",
        }},
        "fixtures": [
            {
                "name": "hit",
                "event": {"cmdline": f"tool {marker}"},
                "expected_match": True,
            },
            {
                "name": "miss",
                "event": {"cmdline": "notepad"},
                "expected_match": False,
            },
        ],
        "performance": {"max_eval_ms": 50, "max_events_per_second": 1000},
        "rollback": {
            "previous_digest": None,
            "instructions": "Restore the retained predecessor.",
        },
        "expires_at": "2099-01-01T00:00:00Z",
    })


def _stage(tmp_path, registry, version: str, marker: str) -> DetectionPackage:
    document = _document(version, marker)
    source = tmp_path / f"{version}-{marker}.json"
    source.write_text(json.dumps(document), encoding="utf-8")
    report = registry.stage(source)
    assert report.ok
    return DetectionPackage(document)


@dataclass
class _Stack:
    registry: DetectionPackageRegistry
    quality: DetectionQualityStore
    input_authority: QualityInputAuthority
    policy: PromotionPolicy
    authority: PromotionAuthority
    coordinator: DetectionPromotionCoordinator
    clock: _Clock


def _stack(
    tmp_path,
    *,
    root_key: bytes | None = None,
    module=None,
    manager=None,
    engine=None,
) -> _Stack:
    clock = _Clock()
    registry = DetectionPackageRegistry(
        tmp_path / "registry",
        require_signed=False,
        transition_authority=root_key,
    )
    input_authority = QualityInputAuthority(b"i" * 32, clock=clock)
    quality = DetectionQualityStore(
        tmp_path / "quality.jsonl",
        key=b"q" * 32,
        input_authority=input_authority,
        clock=clock,
    )
    policy = PromotionPolicy()
    authority = PromotionAuthority(b"p" * 32, clock=clock)
    coordinator = DetectionPromotionCoordinator(
        registry,
        quality,
        authority,
        policy,
        clock=clock,
        transition_capability=root_key,
        runtime_module=module,
        runtime_manager=manager,
        runtime_engine=engine,
    )
    return _Stack(
        registry, quality, input_authority, policy, authority, coordinator, clock
    )


def _approval(stack: _Stack, candidate: DetectionPackage):
    active = stack.registry.active(candidate.package_id)
    cohort = capture_replay_cohort(
        [
            {
                "event_id": "evt-hit",
                "revision": 1,
                "event": {"cmdline": "tool shared"},
                "label": True,
                "label_source": "curator",
            },
            {
                "event_id": "evt-miss",
                "revision": 2,
                "event": {"cmdline": "notepad"},
                "label": False,
                "label_source": "curator",
            },
        ],
        source_id="local-host",
        source_kind="curated-replay",
        high_water=2,
        captured_at=1000.0,
    )
    comparison = compare_detection_packages(
        cohort,
        active=active,
        candidate=candidate,
        evaluated_at=1001.0,
    )
    tuning = digest_tuning({"window": "5m"})
    attestation = stack.input_authority.issue(
        comparison,
        package_id=candidate.package_id,
        policy_digest=stack.policy.digest,
        signer="cycle34-operator",
        tuning_digest=tuning,
        resource_coverage=("process.creation",),
    )
    quality = stack.quality.append_evaluation(
        comparison,
        package_id=candidate.package_id,
        policy_digest=stack.policy.digest,
        signer="cycle34-operator",
        tuning_digest=tuning,
        resource_coverage=("process.creation",),
        input_attestation=attestation,
    )
    return stack.coordinator.issue_promotion_receipt(
        quality,
        signer="cycle34-operator",
        tuning_digest=tuning,
        resource_coverage=("process.creation",),
    )


def _wait_live(module: DetectionRuntimeModule) -> None:
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        thread = module._thread  # noqa: SLF001 - exact lifecycle identity regression
        if module._subscribed and thread is not None and thread.is_alive():  # noqa: SLF001
            return
        time.sleep(0.01)
    raise AssertionError("runtime module did not become live")


def test_root_policy_rejects_signature_downgrade_and_authority_substitution(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    trust = tmp_path / "trusted.json"
    trust.write_text(json.dumps({
        "keys": {"release": {"public_key": b64encode(public).decode("ascii")}}
    }), encoding="utf-8")
    document = _document("1.0.0", "shared")
    source = tmp_path / "signed.json"
    source.write_text(json.dumps(document), encoding="utf-8")
    signature = tmp_path / "signed.sig.json"
    signature.write_text(json.dumps({
        "key_id": "release",
        "signature": b64encode(private.sign(source.read_bytes())).decode("ascii"),
    }), encoding="utf-8")
    key = b"g" * 32
    root = tmp_path / "registry"
    registry = DetectionPackageRegistry(
        root,
        trusted_keys=trust,
        require_signed=True,
        transition_authority=key,
    )
    staged = registry.stage(source, signature=signature)
    assert staged.ok
    assert registry.activate(
        staged.package_id,
        staged.digest,
        transition_capability=key,
    ).ok

    with pytest.raises(Exception, match="cannot be downgraded"):
        DetectionPackageRegistry(
            root,
            trusted_keys=trust,
            require_signed=False,
            transition_authority=key,
        )
    with pytest.raises(Exception, match="authority"):
        DetectionPackageRegistry(
            root,
            trusted_keys=trust,
            require_signed=True,
            transition_authority=b"x" * 32,
        )
    with pytest.raises(Exception, match="authority"):
        DetectionPackageRegistry(
            root,
            trusted_keys=trust,
            require_signed=True,
            transition_authority=object(),
        )

    restarted = DetectionPackageRegistry(
        root,
        trusted_keys=trust,
        require_signed=True,
        transition_authority=key,
    )
    assert restarted.active_set({staged.package_id: staged.digest})[0].package_id == staged.package_id

    # A weak handle opened before production claims a new root also re-reads the
    # persistent policy at transition time; it cannot outlive the upgrade.
    upgrade_root = tmp_path / "upgrade-registry"
    stale_weak = DetectionPackageRegistry(
        upgrade_root,
        trusted_keys=trust,
        require_signed=False,
        transition_authority=key,
    )
    unsigned = _document("2.0.0", "shared")
    unsigned_source = tmp_path / "unsigned-upgrade.json"
    unsigned_source.write_text(json.dumps(unsigned), encoding="utf-8")
    weak_stage = stale_weak.stage(unsigned_source)
    assert weak_stage.ok
    captured_weak_manifest = stale_weak.manifest_path.read_bytes()
    DetectionPackageRegistry(
        upgrade_root,
        trusted_keys=trust,
        require_signed=True,
        transition_authority=key,
    )
    stale_weak.manifest_path.write_bytes(captured_weak_manifest)
    assert not stale_weak.activate(
        weak_stage.package_id,
        weak_stage.digest,
        transition_capability=key,
    ).ok


def test_root_governed_transition_requires_exact_live_subscribed_module(tmp_path):
    bus = EventBus()
    module = DetectionRuntimeModule()
    module.bind(bus)
    manager = SimpleNamespace(bus=bus, modules={module.name: module})
    module.start()
    _wait_live(module)
    try:
        stack = _stack(
            tmp_path,
            root_key=b"g" * 32,
            module=module,
            manager=manager,
            engine=module.engine,
        )
        candidate = _stage(tmp_path, stack.registry, "1.0.0", "shared")
        approval = _approval(stack, candidate)
        engine = module.engine
        initial = engine.snapshot()
        test_capability = engine.seal_active_authority(
            stack.registry,
            module,
            transition_capability=b"g" * 32,
            manager=manager,
        )

        rogue = DetectionPackageRegistry(
            tmp_path / "rogue-registry", require_signed=False
        )
        rogue_package = _stage(tmp_path, rogue, "9.9.0", "rogue")
        assert rogue.activate(
            rogue_package.package_id, rogue_package.document["digest"]
        ).ok
        with pytest.raises(Exception, match="authority"):
            engine.sync_active_set_from_registry(
                rogue,
                expected_bindings={
                    rogue_package.package_id: rogue_package.document["digest"]
                },
                activation_epoch=999,
            )
        same_root_wrong_instance = DetectionPackageRegistry(
            stack.registry.root,
            require_signed=False,
            transition_authority=b"g" * 32,
        )
        with pytest.raises(Exception, match="registry identity"):
            engine.sync_active_set_from_registry(
                same_root_wrong_instance,
                expected_bindings={},
                activation_epoch=999,
                runtime_authority=test_capability,
            )
        with pytest.raises(Exception, match="authority"):
            engine.fail_closed_active(activation_epoch=999)
        assert engine.snapshot() == initial

        original_bus = module._bus  # noqa: SLF001
        module._bus = EventBus()  # noqa: SLF001
        assert not stack.coordinator.promote(approval).ok
        module._bus = original_bus  # noqa: SLF001

        module.stop()
        thread = module._thread  # noqa: SLF001
        if thread is not None:
            thread.join(timeout=2.0)
        assert not stack.coordinator.promote(approval).ok
        with pytest.raises(Exception, match="not live"):
            engine.sync_active_set_from_registry(
                stack.registry,
                expected_bindings={},
                activation_epoch=999,
                runtime_authority=test_capability,
            )

        module.start()
        _wait_live(module)
        with pytest.raises(Exception, match="stale"):
            engine.sync_active_set_from_registry(
                stack.registry,
                expected_bindings={},
                activation_epoch=999,
                runtime_authority=test_capability,
            )
        assert engine.snapshot() == initial
        result = stack.coordinator.promote(approval)
        assert result.ok
        snapshot = engine.snapshot()
        assert snapshot.active_activation_epoch == result.activation_epoch
        assert snapshot.active_digests == (candidate.document["digest"],)

        with pytest.raises(Exception, match="substitution"):
            DetectionForgeService(
                registry=stack.registry,
                runtime=DetectionRuntimeEngine(),
                quality_store=stack.quality,
                promotion=stack.coordinator,
            )
    finally:
        module.stop()
        thread = module._thread  # noqa: SLF001
        if thread is not None:
            thread.join(timeout=2.0)


@pytest.mark.parametrize("race", ["stop", "replace"])
def test_lifecycle_change_after_receipt_verification_cannot_commit(
    tmp_path, monkeypatch, race,
):
    bus = EventBus()
    module = DetectionRuntimeModule()
    module.bind(bus)
    manager = SimpleNamespace(bus=bus, modules={module.name: module})
    module.start()
    _wait_live(module)
    stack = _stack(
        tmp_path,
        root_key=b"g" * 32,
        module=module,
        manager=manager,
        engine=module.engine,
    )
    candidate = _stage(tmp_path, stack.registry, "1.0.0", "shared")
    approval = _approval(stack, candidate)
    original_verify = stack.authority.verify

    def race_after_verify(receipt):
        original_verify(receipt)
        if race == "stop":
            module.stop()
            thread = module._thread  # noqa: SLF001
            if thread is not None:
                thread.join(timeout=2.0)
        else:
            manager.modules[module.name] = DetectionRuntimeModule()

    monkeypatch.setattr(stack.authority, "verify", race_after_verify)
    try:
        result = stack.coordinator.promote(approval)
        assert not result.ok
        assert stack.registry.active(candidate.package_id) is None
        bindings, epoch = stack.coordinator.authoritative_runtime_bindings()
        assert bindings == () and epoch == 0
        snapshot = module.engine.snapshot()
        assert snapshot.active_digests == ()
        assert snapshot.active_activation_epoch == 0
    finally:
        manager.modules[module.name] = module
        module.stop()
        thread = module._thread  # noqa: SLF001
        if thread is not None:
            thread.join(timeout=2.0)


@pytest.mark.parametrize("race", ["stop", "replace"])
def test_lifecycle_change_inside_commit_boundary_cannot_publish_authority(
    tmp_path, monkeypatch, race,
):
    bus = EventBus()
    module = DetectionRuntimeModule()
    module.bind(bus)
    manager = SimpleNamespace(bus=bus, modules={module.name: module})
    module.start()
    _wait_live(module)
    stack = _stack(
        tmp_path,
        root_key=b"g" * 32,
        module=module,
        manager=manager,
        engine=module.engine,
    )
    candidate = _stage(tmp_path, stack.registry, "1.0.0", "shared")
    approval = _approval(stack, candidate)
    original_commit = stack.coordinator._commit_transition  # noqa: SLF001

    def race_at_commit(*args, **kwargs):
        if race == "stop":
            module.stop()
        else:
            manager.modules[module.name] = DetectionRuntimeModule()
        return original_commit(*args, **kwargs)

    monkeypatch.setattr(stack.coordinator, "_commit_transition", race_at_commit)
    try:
        result = stack.coordinator.promote(approval)
        assert not result.ok
        assert stack.registry.active(candidate.package_id) is None
        bindings, epoch = stack.coordinator.authoritative_runtime_bindings()
        assert bindings == () and epoch == 0
        snapshot = module.engine.snapshot()
        assert snapshot.active_digests == ()
        assert snapshot.active_activation_epoch == 0
    finally:
        manager.modules[module.name] = module
        module.stop()
        thread = module._thread  # noqa: SLF001
        if thread is not None:
            thread.join(timeout=2.0)


def test_restart_restores_exact_prestart_runtime_then_allows_live_transition(
    tmp_path,
):
    first_engine = DetectionRuntimeEngine()
    initial = _stack(tmp_path, root_key=b"g" * 32, engine=first_engine)
    first = _stage(tmp_path, initial.registry, "1.0.0", "shared")
    first_result = initial.coordinator.promote(_approval(initial, first))
    assert first_result.ok
    initial.coordinator.close()

    bus = EventBus()
    module = DetectionRuntimeModule()
    module.bind(bus)
    manager = SimpleNamespace(bus=bus, modules={module.name: module})
    restarted = _stack(
        tmp_path,
        root_key=b"g" * 32,
        module=module,
        manager=manager,
        engine=module.engine,
    )
    bindings, epoch = restarted.coordinator.restore_runtime_for_startup()
    assert bindings == ((first.package_id, first.document["digest"]),)
    assert epoch == first_result.activation_epoch
    assert module.lifecycle_generation == 0
    assert module.engine.snapshot().active_digests == (first.document["digest"],)

    module.start()
    _wait_live(module)
    try:
        assert module.lifecycle_generation == 1
        assert module.engine.snapshot().active_digests == (first.document["digest"],)
        second = _stage(tmp_path, restarted.registry, "1.1.0", "shared")
        second_result = restarted.coordinator.promote(_approval(restarted, second))
        assert second_result.ok
        snapshot = module.engine.snapshot()
        assert snapshot.active_activation_epoch == second_result.activation_epoch
        assert snapshot.active_digests == (second.document["digest"],)
    finally:
        module.stop()
        thread = module._thread  # noqa: SLF001
        if thread is not None:
            thread.join(timeout=2.0)


def test_same_registered_module_restart_rotates_capability_and_retains_rules(
    tmp_path,
):
    bus = EventBus()
    module = DetectionRuntimeModule()
    module.bind(bus)
    manager = SimpleNamespace(bus=bus, modules={module.name: module})
    module.start()
    _wait_live(module)
    stack = _stack(
        tmp_path,
        root_key=b"g" * 32,
        module=module,
        manager=manager,
        engine=module.engine,
    )
    candidate = _stage(tmp_path, stack.registry, "1.0.0", "shared")
    result = stack.coordinator.promote(_approval(stack, candidate))
    assert result.ok
    before = module.engine.snapshot()
    stale_capability = module.engine.seal_active_authority(
        stack.registry,
        module,
        transition_capability=b"g" * 32,
        manager=manager,
    )

    module.stop()
    thread = module._thread  # noqa: SLF001
    if thread is not None:
        thread.join(timeout=2.0)
    module.start()
    _wait_live(module)
    try:
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            after = module.engine.snapshot()
            if module.lifecycle_generation == 2 and after.active_digests:
                break
            time.sleep(0.01)
        assert module.lifecycle_generation == 2
        assert after.active_activation_epoch == result.activation_epoch
        assert after.active_digests == (candidate.document["digest"],)
        assert after.rule_integrity_failures == before.rule_integrity_failures

        with pytest.raises(Exception, match="authority"):
            module.engine.sync_active_set_from_registry(
                stack.registry,
                expected_bindings={candidate.package_id: candidate.document["digest"]},
                activation_epoch=result.activation_epoch + 100,
                runtime_authority=stale_capability,
            )
        unchanged = module.engine.snapshot()
        assert unchanged.active_activation_epoch == result.activation_epoch
        assert unchanged.active_digests == (candidate.document["digest"],)

        second = _stage(tmp_path, stack.registry, "1.1.0", "shared")
        second_result = stack.coordinator.promote(_approval(stack, second))
        assert second_result.ok
        assert module.engine.snapshot().active_digests == (
            second.document["digest"],
        )
    finally:
        module.stop()
        thread = module._thread  # noqa: SLF001
        if thread is not None:
            thread.join(timeout=2.0)


def test_live_manager_replacement_fail_closes_old_exact_engine_once(tmp_path):
    bus = EventBus()
    module = DetectionRuntimeModule()
    module.bind(bus)
    manager = SimpleNamespace(bus=bus, modules={module.name: module})
    module.start()
    _wait_live(module)
    stack = _stack(
        tmp_path,
        root_key=b"g" * 32,
        module=module,
        manager=manager,
        engine=module.engine,
    )
    candidate = _stage(tmp_path, stack.registry, "1.0.0", "shared")
    result = stack.coordinator.promote(_approval(stack, candidate))
    assert result.ok
    before = module.engine.snapshot()

    replacement = DetectionRuntimeModule()
    replacement.bind(bus)
    manager.modules[module.name] = replacement
    try:
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            after = module.engine.snapshot()
            if not after.active_digests:
                break
            time.sleep(0.01)
        assert after.active_digests == ()
        assert after.active_activation_epoch == result.activation_epoch
        assert after.rule_integrity_failures == before.rule_integrity_failures + 1
        time.sleep(0.15)
        assert (
            module.engine.snapshot().rule_integrity_failures
            == after.rule_integrity_failures
        )
    finally:
        manager.modules[module.name] = module
        module.stop()
        thread = module._thread  # noqa: SLF001
        if thread is not None:
            thread.join(timeout=2.0)


def test_stopped_owner_cannot_leave_rules_evaluable_outside_module(tmp_path):
    bus = EventBus()
    module = DetectionRuntimeModule()
    module.bind(bus)
    manager = SimpleNamespace(bus=bus, modules={module.name: module})
    module.start()
    _wait_live(module)
    stack = _stack(
        tmp_path,
        root_key=b"g" * 32,
        module=module,
        manager=manager,
        engine=module.engine,
    )
    candidate = _stage(tmp_path, stack.registry, "1.0.0", "shared")
    result = stack.coordinator.promote(_approval(stack, candidate))
    assert result.ok
    before = module.engine.snapshot()

    module.stop()
    thread = module._thread  # noqa: SLF001
    if thread is not None:
        thread.join(timeout=2.0)
    module.engine.process()
    after = module.engine.snapshot()
    assert after.active_digests == ()
    assert after.active_activation_epoch == result.activation_epoch
    assert after.rule_integrity_failures == before.rule_integrity_failures + 1
    module.engine.process()
    assert (
        module.engine.snapshot().rule_integrity_failures
        == after.rule_integrity_failures
    )


def test_explicit_standalone_root_coordinator_seals_and_reconciles_exact_engine(
    tmp_path,
):
    engine = DetectionRuntimeEngine()
    stack = _stack(tmp_path, root_key=b"g" * 32, engine=engine)
    candidate = _stage(tmp_path, stack.registry, "1.0.0", "shared")
    result = stack.coordinator.promote(_approval(stack, candidate))
    assert result.ok
    snapshot = engine.snapshot()
    assert snapshot.active_activation_epoch == result.activation_epoch
    assert snapshot.active_digests == (candidate.document["digest"],)


@pytest.mark.parametrize("boundary", ["journal", "registry", "state", "checkpoint", "anchor"])
def test_authenticated_transaction_recovers_each_commit_boundary(
    tmp_path, monkeypatch, boundary,
):
    stack = _stack(tmp_path)
    first = _stage(tmp_path, stack.registry, "1.0.0", "shared")
    assert stack.coordinator.promote(_approval(stack, first)).ok
    second = _stage(tmp_path, stack.registry, "1.1.0", "shared")
    approval = _approval(stack, second)

    triggered = False
    if boundary == "journal":
        original = stack.coordinator._write_transaction  # noqa: SLF001

        def fail_journal(*args, **kwargs):
            nonlocal triggered
            if not triggered:
                triggered = True
                raise OSError("journal boundary")
            return original(*args, **kwargs)

        monkeypatch.setattr(stack.coordinator, "_write_transaction", fail_journal)
    elif boundary == "registry":
        original = stack.registry._write_manifest  # noqa: SLF001

        def fail_registry(manifest):
            nonlocal triggered
            active = manifest["packages"][second.package_id][second.document["digest"]]["state"]
            if active == "active" and not triggered:
                triggered = True
                raise OSError("registry boundary")
            return original(manifest)

        monkeypatch.setattr(stack.registry, "_write_manifest", fail_registry)
    else:
        original = stack.coordinator._atomic_write  # noqa: SLF001
        target = {
            "state": stack.coordinator.state_path,
            "checkpoint": stack.coordinator.checkpoint_path,
            "anchor": stack.coordinator.anchor_path,
        }[boundary]

        def fail_state(path, payload, *, prefix):
            nonlocal triggered
            if path == target and stack.coordinator.transaction_path.exists() and not triggered:
                triggered = True
                raise OSError(f"{boundary} boundary")
            return original(path, payload, prefix=prefix)

        monkeypatch.setattr(stack.coordinator, "_atomic_write", fail_state)

    stack.coordinator.promote(approval)
    assert triggered
    restarted = DetectionPromotionCoordinator(
        stack.registry,
        stack.quality,
        stack.authority,
        stack.policy,
        clock=stack.clock,
    )
    bindings, epoch = restarted.authoritative_runtime_bindings()
    inventory = restarted._registry_active_bindings(stack.registry.inventory())  # noqa: SLF001
    assert dict(bindings) == inventory
    assert epoch >= 1
    assert not restarted.transaction_path.exists()
    if boundary != "journal":
        retry = restarted.promote(approval)
        assert not retry.ok
        assert "consumed" in retry.errors[0]


def test_candidate_tamper_restores_old_active_set_and_restart_authority(
    tmp_path, monkeypatch,
):
    stack = _stack(tmp_path)
    first = _stage(tmp_path, stack.registry, "1.0.0", "shared")
    assert stack.coordinator.promote(_approval(stack, first)).ok
    second = _stage(tmp_path, stack.registry, "1.1.0", "shared")
    approval = _approval(stack, second)
    original = stack.coordinator._validate_registry_active_locked  # noqa: SLF001

    def tamper(manifest, bindings):
        target = stack.registry.packages / stack.registry._filename(  # noqa: SLF001
            second.document["digest"]
        )
        target.write_bytes(b'{"tampered":true}')
        return original(manifest, bindings)

    monkeypatch.setattr(stack.coordinator, "_validate_registry_active_locked", tamper)
    result = stack.coordinator.promote(approval)
    assert not result.ok
    assert stack.registry.active(first.package_id).document["digest"] == first.document["digest"]

    restarted = DetectionPromotionCoordinator(
        stack.registry,
        stack.quality,
        stack.authority,
        stack.policy,
        clock=stack.clock,
    )
    bindings, _epoch = restarted.authoritative_runtime_bindings()
    assert dict(bindings) == {first.package_id: first.document["digest"]}
    assert not restarted.transaction_path.exists()
    retry = restarted.promote(approval)
    assert not retry.ok and "consumed" in retry.errors[0]


def test_completed_journal_cannot_roll_registry_back_at_same_serial(
    tmp_path, monkeypatch,
):
    stack = _stack(tmp_path)
    candidate = _stage(tmp_path, stack.registry, "1.0.0", "shared")
    approval = _approval(stack, candidate)
    original_clear = stack.coordinator._clear_transaction  # noqa: SLF001
    monkeypatch.setattr(stack.coordinator, "_clear_transaction", lambda: None)
    assert stack.coordinator.promote(approval).ok
    transaction = json.loads(
        stack.coordinator.transaction_path.read_text(encoding="utf-8")
    )
    state_after = stack.coordinator.state_path.read_bytes()
    stack.registry._write_manifest(transaction["old_registry"])  # noqa: SLF001

    with pytest.raises(Exception, match="cannot roll back"):
        DetectionPromotionCoordinator(
            stack.registry,
            stack.quality,
            stack.authority,
            stack.policy,
            clock=stack.clock,
        )
    assert stack.coordinator.state_path.read_bytes() == state_after
    monkeypatch.setattr(stack.coordinator, "_clear_transaction", original_clear)


def test_captured_old_journal_cannot_rollback_later_authority_or_replay_receipt(
    tmp_path, monkeypatch,
):
    stack = _stack(tmp_path)
    first = _stage(tmp_path, stack.registry, "1.0.0", "shared")
    first_approval = _approval(stack, first)
    original_clear = stack.coordinator._clear_transaction  # noqa: SLF001
    monkeypatch.setattr(stack.coordinator, "_clear_transaction", lambda: None)
    assert stack.coordinator.promote(first_approval).ok
    captured_journal = stack.coordinator.transaction_path.read_bytes()
    captured = json.loads(captured_journal)
    original_clear()
    monkeypatch.setattr(stack.coordinator, "_clear_transaction", original_clear)

    second = _stage(tmp_path, stack.registry, "1.1.0", "shared")
    assert stack.coordinator.promote(_approval(stack, second)).ok
    authority_after = tuple(
        path.read_bytes() for path in (
            stack.coordinator.state_path,
            stack.coordinator.checkpoint_path,
            stack.coordinator.anchor_path,
        )
    )
    stack.registry._write_manifest(captured["old_registry"])  # noqa: SLF001
    stack.coordinator.transaction_path.write_bytes(captured_journal)

    with pytest.raises(Exception, match="stale|diverged"):
        DetectionPromotionCoordinator(
            stack.registry,
            stack.quality,
            stack.authority,
            stack.policy,
            clock=stack.clock,
        )
    assert authority_after == tuple(
        path.read_bytes() for path in (
            stack.coordinator.state_path,
            stack.coordinator.checkpoint_path,
            stack.coordinator.anchor_path,
        )
    )
    replay = stack.coordinator.promote(first_approval)
    assert not replay.ok
    assert "stale" in replay.errors[0] or "diverged" in replay.errors[0]


def test_stale_reconcile_failure_cannot_clear_newer_runtime_epoch(tmp_path):
    first_registry = DetectionPackageRegistry(tmp_path / "first", require_signed=False)
    second_registry = DetectionPackageRegistry(tmp_path / "second", require_signed=False)
    first = _stage(tmp_path, first_registry, "1.0.0", "first")
    second = _stage(tmp_path, second_registry, "1.1.0", "second")
    assert first_registry.activate(first.package_id, first.document["digest"]).ok
    assert second_registry.activate(second.package_id, second.document["digest"]).ok
    engine = DetectionRuntimeEngine()
    engine.sync_active_set_from_registry(
        first_registry,
        expected_bindings={first.package_id: first.document["digest"]},
        activation_epoch=1,
    )

    class _RacePromotion:
        def assert_runtime_identity(self, runtime):
            assert runtime is engine

        def authoritative_runtime_bindings(self):
            engine.sync_active_set_from_registry(
                second_registry,
                expected_bindings={second.package_id: second.document["digest"]},
                activation_epoch=2,
            )
            raise RuntimeError("stale reconcile fault")

    service = DetectionForgeService(
        registry=second_registry,
        runtime=engine,
        promotion=_RacePromotion(),  # type: ignore[arg-type]
    )
    stale = PromotionResult(
        ok=False,
        action="promote",
        package_id=first.package_id,
        target_digest=first.document["digest"],
        previous_digest=None,
        state="rejected",
        activation_epoch=1,
    )
    reconciled = service._reconcile_transition(stale)  # noqa: SLF001
    assert not reconciled.ok
    snapshot = engine.snapshot()
    assert snapshot.active_activation_epoch == 2
    assert snapshot.active_digests == (second.document["digest"],)


def test_runtime_revalidates_and_clears_rules_after_key_revocation(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    trust = tmp_path / "runtime-trust.json"
    trust.write_text(json.dumps({
        "keys": {"release": {"public_key": b64encode(public).decode("ascii")}}
    }), encoding="utf-8")
    package = _document("1.0.0", "shared")
    source = tmp_path / "runtime-signed.json"
    source.write_text(json.dumps(package), encoding="utf-8")
    signature = tmp_path / "runtime-signed.sig.json"
    signature.write_text(json.dumps({
        "key_id": "release",
        "signature": b64encode(private.sign(source.read_bytes())).decode("ascii"),
    }), encoding="utf-8")
    registry = DetectionPackageRegistry(
        tmp_path / "runtime-registry",
        trusted_keys=trust,
        require_signed=True,
    )
    staged = registry.stage(source, signature=signature)
    assert staged.ok and registry.activate(staged.package_id, staged.digest).ok
    clock = _Clock(0.0)
    findings = []
    engine = DetectionRuntimeEngine(
        clock=clock,
        active_sink=findings.append,
        authority_revalidation_seconds=0.05,
    )
    engine.sync_active_set_from_registry(
        registry,
        expected_bindings={staged.package_id: staged.digest},
        activation_epoch=1,
    )
    engine.submit(Event(
        module="Process Monitor",
        message="process creation",
        severity=Severity.HIGH,
        ts=1.0,
        details={"event_id": "revoked", "cmdline": "tool shared"},
    ))
    trust.write_text('{"keys":{}}', encoding="utf-8")
    clock.value = 1.0
    engine.process()
    snapshot = engine.snapshot()
    assert snapshot.active_digests == ()
    assert snapshot.active_queue_depth == 0
    assert snapshot.rule_integrity_failures >= 1
    assert findings == []
    assert registry.inventory()[staged.package_id][staged.digest]["state"] == "quarantined"


def test_failed_revalidation_counts_integrity_only_when_same_epoch_is_cleared(
    tmp_path, monkeypatch,
):
    registry = DetectionPackageRegistry(tmp_path / "cas-registry", require_signed=False)
    package = _stage(tmp_path, registry, "1.0.0", "shared")
    assert registry.activate(package.package_id, package.document["digest"]).ok
    clock = _Clock(0.0)
    engine = DetectionRuntimeEngine(
        clock=clock,
        authority_revalidation_seconds=0.05,
    )
    engine.sync_active_set_from_registry(
        registry,
        expected_bindings={package.package_id: package.document["digest"]},
        activation_epoch=1,
    )
    monkeypatch.setattr(
        registry,
        "active_set",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("revoked")),
    )
    monkeypatch.setattr(
        engine,
        "_fail_closed_active_locked",
        lambda **_kwargs: False,
    )
    clock.value = 1.0
    engine.process()
    snapshot = engine.snapshot()
    assert snapshot.active_digests == (package.document["digest"],)
    assert snapshot.rule_integrity_failures == 0
