from __future__ import annotations

import base64
import json
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from angerona.core import detection_registry as registry_module
from angerona.core.detection_packages import DetectionPackage, seal_package
from angerona.core.detection_registry import DetectionPackageRegistry
from angerona.core.eventbus import Event, Severity
from angerona.modules import detection_runtime as runtime_module
from angerona.modules.detection_runtime import DetectionRuntimeEngine


def _package(index: int) -> DetectionPackage:
    return DetectionPackage(seal_package({
        "schema_version": 1,
        "id": f"org.angerona.round3-perf-{index:03d}",
        "version": "1.0.0",
        "owner": "Angerona tests",
        "description": "Cycle 34 runtime decode coalescing fixture.",
        "telemetry": ["process.creation"],
        "attack": ["T1059.001"],
        "severity": "high",
        "confidence": 85,
        "logic": {
            "type": "sigma-subset",
            "detection": {
                "selection": {"cmdline|contains": "needle"},
                "condition": "selection",
            },
        },
        "fixtures": [
            {
                "name": "hit",
                "event": {"cmdline": "tool needle"},
                "expected_match": True,
            },
        ],
        "performance": {
            "max_eval_ms": 1000,
            "max_events_per_second": 1000000,
        },
        "rollback": {
            "previous_digest": None,
            "instructions": "Restore the predecessor.",
        },
        "expires_at": "2099-01-01T00:00:00Z",
    }))


def _active_registry(tmp_path, count: int, *, authority: bytes | None = None):
    registry = DetectionPackageRegistry(
        tmp_path / "registry",
        require_signed=False,
        transition_authority=authority,
    )
    packages = tuple(_package(index) for index in range(count))
    bindings: dict[str, str] = {}
    for package in packages:
        source = tmp_path / f"{package.package_id}.json"
        source.write_text(json.dumps(package.document), encoding="utf-8")
        staged = registry.stage(source)
        assert staged.ok
        activated = registry.activate(
            package.package_id,
            str(package.document["digest"]),
            transition_capability=authority,
        )
        assert activated.ok
        bindings[package.package_id] = str(package.document["digest"])
    return registry, packages, bindings


def test_runtime_decodes_one_event_once_per_active_and_shadow_work(
    tmp_path, monkeypatch,
) -> None:
    registry, packages, bindings = _active_registry(tmp_path, 4)
    findings = []
    engine = DetectionRuntimeEngine(
        active_sink=findings.append,
        clock=lambda: 100.0,
        authority_revalidation_seconds=5.0,
    )
    engine.sync_active_set_from_registry(
        registry,
        expected_bindings=bindings,
        activation_epoch=1,
    )
    engine.bind_shadow(packages)

    decode_calls = 0
    original = runtime_module._QueuedEvent.event  # noqa: SLF001

    def counted_event(queued):
        nonlocal decode_calls
        decode_calls += 1
        return original(queued)

    monkeypatch.setattr(runtime_module._QueuedEvent, "event", counted_event)  # noqa: SLF001
    assert engine.submit(Event(
        module="Process Monitor",
        message="process created",
        severity=Severity.MEDIUM,
        ts=100.0,
        details={"cmdline": "tool needle", "payload": "x" * 32_000},
    ))
    assert engine.process(
        max_active=1,
        max_shadow=1,
        max_shadow_evaluations=8,
        shadow_slice_ms=25.0,
    ) == (1, 1)
    assert decode_calls == 2
    assert len(findings) == 4
    assert len(engine.snapshot().shadow_observations) == 4


def test_runtime_cached_decode_failure_remains_visible_for_every_rule() -> None:
    engine = DetectionRuntimeEngine()
    rules = tuple(runtime_module._bind_rule(_package(index)) for index in range(4))  # noqa: SLF001
    queued = runtime_module._QueuedEvent(  # noqa: SLF001
        "event-invalid",
        "sha256:" + "1" * 64,
        None,
        None,
        "{invalid-json",
    )
    work = runtime_module._QueuedWork(queued, 1)  # noqa: SLF001
    assert engine._active_evaluate(work, rules) == []  # noqa: SLF001
    assert engine.snapshot().evaluation_failures == len(rules)


def test_runtime_malformed_decode_is_once_per_lane_and_shadow_slice(
    monkeypatch,
) -> None:
    engine = DetectionRuntimeEngine()
    rules = tuple(runtime_module._bind_rule(_package(index)) for index in range(4))  # noqa: SLF001
    queued = runtime_module._QueuedEvent(  # noqa: SLF001
        "event-invalid-sliced",
        "sha256:" + "2" * 64,
        None,
        None,
        "{invalid-json",
    )
    calls = 0
    original = runtime_module._QueuedEvent.event  # noqa: SLF001

    def counted_event(event):
        nonlocal calls
        calls += 1
        return original(event)

    monkeypatch.setattr(runtime_module._QueuedEvent, "event", counted_event)  # noqa: SLF001

    active_work = runtime_module._QueuedWork(queued, 1)  # noqa: SLF001
    assert engine._active_evaluate(active_work, rules) == []  # noqa: SLF001
    assert calls == 1

    shadow_work = runtime_module._QueuedWork(queued, 1)  # noqa: SLF001
    next_rule, used = engine._shadow_evaluate(  # noqa: SLF001
        shadow_work,
        rules,
        deadline=float("inf"),
        remaining_evaluations=2,
    )
    assert (next_rule, used) == (2, 2)
    assert calls == 2
    next_rule, used = engine._shadow_evaluate(  # noqa: SLF001
        runtime_module._QueuedWork(queued, 1, next_rule),  # noqa: SLF001
        rules,
        deadline=float("inf"),
        remaining_evaluations=2,
    )
    assert (next_rule, used) == (len(rules), 2)
    assert calls == 3
    assert engine.snapshot().evaluation_failures == len(rules) * 2


def test_runtime_attributes_shared_decode_time_to_every_rule_budget(
    monkeypatch,
) -> None:
    virtual_time = [0.0]
    engine = DetectionRuntimeEngine(work_clock=lambda: virtual_time[0])
    rules = tuple(
        replace(runtime_module._bind_rule(_package(index)), max_eval_ms=5.0)  # noqa: SLF001
        for index in range(4)
    )
    queued = runtime_module._QueuedEvent(  # noqa: SLF001
        "event-budget",
        "sha256:" + "3" * 64,
        None,
        None,
        json.dumps({"cmdline": "tool needle"}),
    )
    original = runtime_module._QueuedEvent.event  # noqa: SLF001

    def delayed_event(event):
        virtual_time[0] += 0.010
        return original(event)

    monkeypatch.setattr(runtime_module._QueuedEvent, "event", delayed_event)  # noqa: SLF001
    active = engine._active_evaluate(  # noqa: SLF001
        runtime_module._QueuedWork(queued, 1),  # noqa: SLF001
        rules,
    )
    assert len(active) == len(rules)
    assert all(finding.elapsed_ms == pytest.approx(10.0) for finding, _sink in active)
    assert all(finding.budget_exceeded for finding, _sink in active)

    next_rule, used = engine._shadow_evaluate(  # noqa: SLF001
        runtime_module._QueuedWork(queued, 1),  # noqa: SLF001
        rules,
        deadline=float("inf"),
        remaining_evaluations=len(rules),
    )
    assert (next_rule, used) == (len(rules), len(rules))
    snapshot = engine.snapshot()
    assert snapshot.budget_violations == len(rules) * 2
    assert len(snapshot.shadow_observations) == len(rules)
    assert all(
        observation.elapsed_ms == pytest.approx(10.0)
        and observation.disposition == "budget-exceeded"
        for observation in snapshot.shadow_observations
    )


def test_active_set_checks_root_governance_twice_not_once_per_package(
    tmp_path, monkeypatch,
) -> None:
    authority = b"g" * 32
    registry, _packages, bindings = _active_registry(
        tmp_path, 8, authority=authority
    )
    anchor_reads = 0
    original = registry._read_governance_anchor  # noqa: SLF001

    def counted_anchor():
        nonlocal anchor_reads
        anchor_reads += 1
        return original()

    monkeypatch.setattr(registry, "_read_governance_anchor", counted_anchor)
    active = registry.active_set(bindings)
    assert tuple(package.package_id for package in active) == tuple(sorted(bindings))
    assert anchor_reads == 2


def _signed_active_registry(tmp_path, count: int, authority: bytes):
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    trust = tmp_path / "trusted.json"
    trust.write_text(json.dumps({
        "keys": {
            "release": {
                "public_key": base64.b64encode(public).decode("ascii"),
            },
        },
    }), encoding="utf-8")
    registry = DetectionPackageRegistry(
        tmp_path / "signed-registry",
        trusted_keys=trust,
        require_signed=True,
        transition_authority=authority,
    )
    bindings: dict[str, str] = {}
    for package in (_package(index) for index in range(count)):
        source = tmp_path / f"{package.package_id}.signed.json"
        source.write_text(json.dumps(package.document), encoding="utf-8")
        signature = tmp_path / f"{package.package_id}.sig.json"
        signature.write_text(json.dumps({
            "key_id": "release",
            "signature": base64.b64encode(
                private.sign(source.read_bytes())
            ).decode("ascii"),
        }), encoding="utf-8")
        staged = registry.stage(source, signature=signature)
        assert staged.ok
        assert registry.activate(
            staged.package_id,
            staged.digest,
            transition_capability=authority,
        ).ok
        bindings[staged.package_id] = staged.digest
    return registry, bindings


@pytest.mark.parametrize("mutate_on_read", [1, 2])
def test_signed_active_set_rejects_governance_anchor_entry_or_exit_mutation(
    tmp_path,
    monkeypatch,
    mutate_on_read,
) -> None:
    registry, bindings = _signed_active_registry(tmp_path, 4, b"s" * 32)
    anchor_bytes = registry.governance_anchor_path.read_bytes()
    reads = 0
    original = registry._read_governance_anchor  # noqa: SLF001

    def mutate_anchor():
        nonlocal reads
        reads += 1
        if reads == mutate_on_read:
            registry.governance_anchor_path.write_text("{}", encoding="utf-8")
        return original()

    monkeypatch.setattr(registry, "_read_governance_anchor", mutate_anchor)
    try:
        with pytest.raises(Exception, match="governance|anchor"):
            registry.active_set(bindings)
    finally:
        registry.governance_anchor_path.write_bytes(anchor_bytes)


def _multi_key_signed_registry(tmp_path):
    private_keys = {
        "key1": Ed25519PrivateKey.generate(),
        "key2": Ed25519PrivateKey.generate(),
    }
    encoded_keys = {
        key_id: {
            "public_key": base64.b64encode(private.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )).decode("ascii"),
        }
        for key_id, private in private_keys.items()
    }
    trust = tmp_path / "multi-key-trust.json"
    trust.write_text(json.dumps({"keys": encoded_keys}), encoding="utf-8")
    authority = b"m" * 32
    registry = DetectionPackageRegistry(
        tmp_path / "multi-key-registry",
        trusted_keys=trust,
        require_signed=True,
        transition_authority=authority,
    )
    bindings: dict[str, str] = {}
    for index, key_id in enumerate(("key1", "key2")):
        package = _package(index)
        source = tmp_path / f"multi-{index}.json"
        source.write_text(json.dumps(package.document), encoding="utf-8")
        signature = tmp_path / f"multi-{index}.sig.json"
        signature.write_text(json.dumps({
            "key_id": key_id,
            "signature": base64.b64encode(
                private_keys[key_id].sign(source.read_bytes())
            ).decode("ascii"),
        }), encoding="utf-8")
        staged = registry.stage(source, signature=signature)
        assert staged.ok
        assert registry.activate(
            staged.package_id,
            staged.digest,
            transition_capability=authority,
        ).ok
        bindings[staged.package_id] = staged.digest
    return registry, bindings, trust, encoded_keys


def test_signed_multi_package_active_set_uses_one_immutable_trust_snapshot(
    tmp_path, monkeypatch,
) -> None:
    registry, bindings, _trust, _keys = _multi_key_signed_registry(tmp_path)
    reads = 0
    original = registry._read_trust_store_snapshot  # noqa: SLF001

    def counted_snapshot():
        nonlocal reads
        reads += 1
        return original()

    monkeypatch.setattr(registry, "_read_trust_store_snapshot", counted_snapshot)
    active = registry.active_set(bindings)
    assert tuple(package.package_id for package in active) == tuple(sorted(bindings))
    assert reads == 1


def test_active_set_rejects_cross_package_trust_rotation(
    tmp_path, monkeypatch,
) -> None:
    registry, bindings, trust, keys = _multi_key_signed_registry(tmp_path)
    verifications = 0
    original = registry._verify_signature_artifacts  # noqa: SLF001

    def rotate_after_first(*args, **kwargs):
        nonlocal verifications
        result = original(*args, **kwargs)
        verifications += 1
        if verifications == 1:
            replacement = trust.with_suffix(".replacement")
            replacement.write_text(json.dumps({
                "keys": {"key2": keys["key2"]},
            }), encoding="utf-8")
            replacement.replace(trust)
        return result

    monkeypatch.setattr(
        registry, "_verify_signature_artifacts", rotate_after_first
    )
    with pytest.raises(Exception, match="trust store changed"):
        registry.active_set(bindings)
    assert verifications == 2


@pytest.mark.parametrize(
    "replacement",
    [
        b'{"keys":{"bad":{"public_key":"!!!"}}}',
        b"x" * (registry_module._MAX_TRUST_STORE_BYTES + 1),  # noqa: SLF001
    ],
    ids=("malformed", "oversized"),
)
def test_active_set_rejects_malformed_or_oversized_trust_snapshot(
    tmp_path, replacement,
) -> None:
    registry, bindings, trust, _keys = _multi_key_signed_registry(tmp_path)
    trust.write_bytes(replacement)
    with pytest.raises(Exception, match="trust store|exceeds"):
        registry.active_set(bindings)


def test_active_set_rejects_trust_store_mutation_at_exit(
    tmp_path, monkeypatch,
) -> None:
    registry, bindings, trust, keys = _multi_key_signed_registry(tmp_path)
    original = registry._assert_trust_store_stable  # noqa: SLF001
    mutated = False

    def mutate_at_exit(snapshot):
        nonlocal mutated
        if not mutated:
            mutated = True
            replacement = trust.with_suffix(".exit-replacement")
            replacement.write_text(
                json.dumps({"keys": keys}, indent=2), encoding="utf-8"
            )
            replacement.replace(trust)
        return original(snapshot)

    monkeypatch.setattr(registry, "_assert_trust_store_stable", mutate_at_exit)
    with pytest.raises(Exception, match="trust store changed"):
        registry.active_set(bindings)
    assert mutated


def test_active_set_rejects_signature_generation_change_at_exit(
    tmp_path, monkeypatch,
) -> None:
    registry, bindings, _trust, _keys = _multi_key_signed_registry(tmp_path)
    original = registry_module._assert_file_stamp_unchanged  # noqa: SLF001
    mutated = False

    def mutate_signature(stamp, *, maximum):
        nonlocal mutated
        if not mutated and stamp.path.name.endswith(".sig.json"):
            mutated = True
            stamp.path.write_text("{}", encoding="utf-8")
        return original(stamp, maximum=maximum)

    monkeypatch.setattr(
        registry_module, "_assert_file_stamp_unchanged", mutate_signature
    )
    with pytest.raises(Exception, match="security artifact changed"):
        registry.active_set(bindings)
    assert mutated
