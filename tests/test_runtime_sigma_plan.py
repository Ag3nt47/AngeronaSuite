"""Semantic and trust-boundary controls for owned runtime-only Sigma plans."""
from __future__ import annotations

import copy
import json
from dataclasses import FrozenInstanceError, fields, is_dataclass

import pytest

from angerona.core import sigma_engine
from angerona.core.detection_packages import (
    DetectionPackage,
    PackageValidationError,
    seal_package,
    validate_package,
)
from angerona.core.detection_registry import DetectionPackageRegistry
from angerona.core.eventbus import Event, Severity
from angerona.modules import detection_runtime as runtime


def _package(detection=None):
    if detection is None:
        detection = {
            "selection": {"cmdline|contains": "needle"},
            "condition": "selection",
        }
    return DetectionPackage(seal_package({
        "schema_version": 1,
        "id": "org.angerona.runtime-plan-test",
        "version": "1.0.0",
        "owner": "Angerona tests",
        "description": "Synthetic immutable runtime plan controls.",
        "telemetry": ["process.creation"],
        "attack": ["T1059.001"],
        "severity": "high",
        "confidence": 85,
        "logic": {"type": "sigma-subset", "detection": detection},
        "fixtures": [{
            "name": "synthetic match",
            "event": {"cmdline": "tool needle"},
            "expected_match": True,
        }],
        "performance": {"max_eval_ms": 1000, "max_events_per_second": 1000000},
        "rollback": {"previous_digest": None, "instructions": "Restore predecessor."},
        "expires_at": "2099-01-01T00:00:00Z",
    }))


def _event(index):
    return Event(
        module="Synthetic process sensor",
        message="synthetic creation",
        severity=Severity.MEDIUM,
        ts=100.0 + index,
        details={"cmdline": "tool needle", "event_id": f"plan-event-{index}"},
    )


def _active(tmp_path, engine, package):
    registry = DetectionPackageRegistry(tmp_path / "registry", require_signed=False)
    source = tmp_path / "package.json"
    source.write_text(json.dumps(package.document), encoding="utf-8")
    staged = registry.stage(source)
    assert staged.ok
    assert registry.activate(package.package_id, package.document["digest"]).ok
    assert engine.sync_active_from_registry(
        registry, package_id=package.package_id,
        expected_digest=package.document["digest"], activation_epoch=1,
    ) == (package.document["digest"],)
    return registry


_CASES = [
    ({"selection": {"image": "tool.exe"}, "condition": "selection"},
     {"image": "TOOL.EXE"}, True),
    ({"selection": {"Image": "tool.exe"}, "condition": "selection"},
     {"image": "tool.exe"}, False),
    ({"selection": {"image|contains": "TOOL"}, "condition": "selection"},
     {"image": "path/tool.exe"}, True),
    ({"selection": {"image|startswith": "PATH"}, "condition": "selection"},
     {"image": "path/tool.exe"}, True),
    ({"selection": {"image|endswith": ".EXE"}, "condition": "selection"},
     {"image": "path/tool.exe"}, True),
    ({"selection": {"image|contains": "tool"}, "condition": "selection"},
     {}, False),
    ({"selection": {"image": "None"}, "condition": "selection"},
     {"image": None}, False),
    ({"selection": {"port": 443}, "condition": "selection"},
     {"port": "443"}, True),
    ({"selection": {"enabled": True}, "condition": "selection"},
     {"enabled": "TRUE"}, True),
    ({"selection": {"enabled": False}, "condition": "selection"},
     {"enabled": 0}, False),
    ({"selection": {"name": "straße"}, "condition": "selection"},
     {"name": "STRASSE"}, False),
    ({"selection": {"name": "ÉCHO"}, "condition": "selection"},
     {"name": "écho"}, True),
    ({"selection": {"image": ["other.exe", "tool.exe"]}, "condition": "selection"},
     {"image": "tool.exe"}, True),
    ({"selection": [{"image": "other.exe"}, {"image": "tool.exe"}],
      "condition": "selection"}, {"image": "tool.exe"}, True),
    ({"selection": {"image": "tool.exe", "user": "alice"}, "condition": "selection"},
     {"image": "tool.exe"}, False),
    ({"selection": {"module": "sensor", "message": "spawn", "severity": "HIGH"},
      "condition": "selection"},
     {"module": "SENSOR", "message": "SPAWN", "severity": "high"}, True),
    ({"selection": {"image": "tool.exe"}, "filter": {"user": "system"},
      "condition": "selection and not filter"},
     {"image": "tool.exe", "user": "alice"}, True),
    ({"selection": {"image": "tool.exe"}, "filter": {"user": "system"},
      "condition": "selection and not filter"},
     {"image": "tool.exe", "user": "SYSTEM"}, False),
    ({"selection": {"image": "tool.exe"}, "filter": {"user": "alice"},
      "condition": "selection and filter"},
     {"image": "tool.exe", "user": "alice"}, True),
    ({"selection": {"image": "tool.exe"}, "filter": {"user": "alice"},
      "condition": "selection or filter"}, {"user": "alice"}, True),
    ({"selection": {"image": "tool.exe"}, "filter": {"user": "alice"},
      "condition": "selection and  filter"},
     {"image": "tool.exe", "user": "alice"}, True),
    ({"selection": {"image": "tool.exe"}, "filter": {"user": "alice"},
      "condition": "selection\tand\tfilter"},
     {"image": "tool.exe", "user": "alice"}, False),
    ({"selection": {"image": "tool.exe"}, "filter": {"user": "system"},
      "condition": "SELECTION AND NOT FILTER"},
     {"image": "tool.exe", "user": "alice"}, True),
    ({"selection_a": {"image": "tool.exe"}, "selection_b": {"user": "alice"},
      "condition": "all of selection*"},
     {"image": "tool.exe", "user": "alice"}, True),
    ({"selection_a": {"image": "tool.exe"}, "selection_b": {"user": "alice"},
      "condition": "1 of selection*"}, {"user": "alice"}, True),
    ({"selection": {"image": "tool.exe"}, "_filter": {"user": "system"},
      "condition": "all of them"}, {"image": "tool.exe", "user": "alice"}, True),
    ({"_filter": {"user": "system"}, "condition": "all of them"},
     {"user": "system"}, False),
    ({"selection": {"image": "tool.exe"}, "other": {"user": "alice"},
      "condition": "1 of them"}, {"user": "alice"}, True),
    ({"selection": {"image": "tool.exe"}, "other": {"user": "alice"},
      "condition": "any of them"}, {"user": "alice"}, True),
    ({"selection": {"image|contains": "*.exe"}, "condition": "selection"},
     {"image": "literal *.exe argument"}, True),
    # These package-schema-admitted shapes already fail the public matcher.
    ({"selection": {"image": None}, "condition": "selection"}, {}, False),
    ({"selection": {"port": 443.0}, "condition": "selection"}, {"port": 443.0}, False),
    ({"selection": {"image": ""}, "condition": "selection"}, {"image": ""}, False),
    ({"selection": {"image": "*.exe"}, "condition": "selection"},
     {"image": "*.exe"}, False),
    ({"selection": {"image": "?tool"}, "condition": "selection"},
     {"image": "?tool"}, False),
    ({"selection": {"image": ["tool.exe", None]}, "condition": "selection"},
     {"image": "tool.exe"}, False),
    ({"selection.dot": {"image": "tool.exe"}, "condition": "selection.dot"},
     {"image": "tool.exe"}, False),
    ({"1selection": {"image": "tool.exe"}, "condition": "1selection"},
     {"image": "tool.exe"}, False),
    ({"selection": {"image": "tool.exe"}, "Selection": {"user": "alice"},
      "condition": "all of them"}, {"image": "tool.exe", "user": "alice"}, False),
    ({"selection": {"image": "tool.exe"}, "filter": {"user": "alice"},
      "other": {"pid": 42}, "condition": "selection and filter or other"},
     {"image": "tool.exe", "user": "alice", "pid": 42}, False),
]


_PACKAGE_CASES = [case for case in _CASES if " and not " not in case[0]["condition"].lower()]
_NEGATION_CASES = [case for case in _CASES if " and not " in case[0]["condition"].lower()]


@pytest.mark.parametrize(("detection", "event", "expected"), _PACKAGE_CASES)
def test_owned_plan_preserves_package_matcher_semantics(detection, event, expected):
    package = _package(copy.deepcopy(detection))
    validate_package(package.document)
    rule = runtime._bind_rule(package)
    assert package.evaluate(event) is expected
    assert rule.package._evaluate_runtime_plan(rule.plan, event) is expected


@pytest.mark.parametrize(("detection", "event", "expected"), _NEGATION_CASES)
def test_plan_negation_parity_does_not_widen_existing_package_admission(
    detection, event, expected,
):
    package = _package(copy.deepcopy(detection))
    # Existing package tokenization refuses AND NOT although the underlying
    # public matcher supports it. This performance change preserves admission.
    with pytest.raises(PackageValidationError, match="condition"):
        validate_package(package.document)
    plan = sigma_engine._compile_runtime_plan(copy.deepcopy(detection))
    assert package.evaluate(event) is expected
    assert package._evaluate_runtime_plan(plan, event) is expected


def _assert_deep_immutable(value):
    if is_dataclass(value):
        assert value.__dataclass_params__.frozen
        assert not hasattr(value, "__dict__")
        for field in fields(value):
            _assert_deep_immutable(getattr(value, field.name))
    elif isinstance(value, tuple):
        for item in value:
            _assert_deep_immutable(item)
    else:
        assert value is None or type(value) in (str, int, bool)


def test_plan_owns_no_caller_containers_and_is_deeply_immutable():
    source = {
        "selection": {"cmdline|contains": ["needle", "other"]},
        "condition": "selection",
    }
    package = _package(source)
    rule = runtime._bind_rule(package)
    _assert_deep_immutable(rule.plan)
    with pytest.raises(FrozenInstanceError):
        rule.plan.negate = 0
    with pytest.raises(FrozenInstanceError):
        rule.plan.selections[0][0][0].field = "changed"
    with pytest.raises(TypeError):
        rule.plan.selections[0][0][0].expected[0] = "changed"
    source["selection"]["cmdline|contains"][:] = ["changed"]
    source["condition"] = "unknown"
    assert not package.evaluate({"cmdline": "tool needle"})
    # The runtime owns a JSON snapshot; caller edits do not replace its plan.
    rule.verify()
    assert rule.package._evaluate_runtime_plan(rule.plan, {"cmdline": "tool needle"})


def test_existing_depth_limit_refuses_nested_selection_and_value_lists_before_compilation(
    monkeypatch,
):
    source = {
        "selection": [{"cmdline|contains": ["needle", "other"]}],
        "condition": "selection",
    }
    package = _package(source)
    # Package schema permits this shape, but the existing runtime normalizer
    # reaches scalar depth 6: logic1/detection2/list3/map4/list5/scalar6.
    validate_package(package.document)
    compilation_calls = []

    def forbidden_compilation(detection):
        compilation_calls.append(detection)
        raise AssertionError("over-depth rule reached the plan compiler")

    monkeypatch.setattr(runtime, "_compile_runtime_plan", forbidden_compilation)
    with pytest.raises(runtime.DetectionRuntimeError, match="nesting depth"):
        runtime._bind_rule(package)
    assert compilation_calls == []


def test_compilation_is_per_binding_but_rule_verification_repeats_in_both_lanes(
    tmp_path, monkeypatch,
):
    compilation_calls = []
    verification_calls = []
    original_compile = runtime._compile_runtime_plan
    original_verify = runtime._RuntimeRule.verify
    original_matcher = sigma_engine._rule_supported

    def compile_once(detection):
        compilation_calls.append(detection)
        return original_compile(detection)

    def verify_each(rule):
        verification_calls.append(id(rule))
        return original_verify(rule)

    monkeypatch.setattr(runtime, "_compile_runtime_plan", compile_once)
    monkeypatch.setattr(runtime._RuntimeRule, "verify", verify_each)
    findings = []
    engine = runtime.DetectionRuntimeEngine(
        active_sink=findings.append, clock=lambda: 100.0,
    )
    package = _package()
    _active(tmp_path, engine, package)
    engine.bind_shadow(package)
    assert len(compilation_calls) == 2
    assert engine._active_rules[0].plan is not engine._shadow_rules[0].plan

    def no_runtime_revalidation(*args, **kwargs):
        raise AssertionError("compiled runtime must not repeat Sigma parsing")

    monkeypatch.setattr(sigma_engine, "_rule_supported", no_runtime_revalidation)
    for index in range(3):
        assert engine.submit(_event(index))
        assert engine.process(max_active=1, max_shadow=1) == (1, 1)
    assert len(compilation_calls) == 2
    assert verification_calls.count(id(engine._active_rules[0])) == 3
    assert verification_calls.count(id(engine._shadow_rules[0])) == 3
    assert len(findings) == 3
    assert len(engine.snapshot().shadow_observations) == 3
    assert engine.snapshot().rule_integrity_failures == 0

    # Ordinary mutable-dictionary callers retain the defensive public path.
    monkeypatch.setattr(sigma_engine, "_rule_supported", original_matcher)
    package.document["logic"]["detection"]["selection"]["cmdline|contains"] = None
    assert package.evaluate({"cmdline": "tool needle"}) is False


@pytest.mark.parametrize("lane", ["active", "shadow"])
def test_bound_document_tamper_stops_plan_evaluation_in_each_lane(
    tmp_path, monkeypatch, lane,
):
    findings = []
    engine = runtime.DetectionRuntimeEngine(active_sink=findings.append)
    package = _package()
    if lane == "active":
        _active(tmp_path, engine, package)
        bound = engine._active_rules[0]
    else:
        engine.bind_shadow(package)
        bound = engine._shadow_rules[0]
    bound.package.document["logic"]["detection"]["selection"]["cmdline|contains"] = "changed"
    evaluations = []

    def forbidden(*args):
        evaluations.append(True)
        raise AssertionError("tampered rule reached compiled evaluation")

    monkeypatch.setattr(DetectionPackage, "_evaluate_runtime_plan", forbidden)
    if lane == "active":
        assert engine.submit(_event(1), include_shadow=False)
    else:
        assert engine.submit_shadow(_event(1))
    engine.process()
    assert evaluations == []
    assert findings == []
    snapshot = engine.snapshot()
    assert snapshot.rule_integrity_failures == 1
    assert snapshot.shadow_observations == ()


def test_plan_does_not_grant_active_authority_or_change_shadow_deduplication():
    findings = []
    engine = runtime.DetectionRuntimeEngine(active_sink=findings.append)
    engine.bind_shadow(_package())
    event = _event(1)
    assert engine.submit(event, include_shadow=False)
    assert engine.snapshot().active_queue_depth == 0
    assert engine.snapshot().active_digests == ()
    assert engine.submit_shadow(event)
    assert engine.submit_shadow(event)
    assert engine.process() == (0, 2)
    snapshot = engine.snapshot()
    assert findings == []
    assert snapshot.active_findings == 0
    assert snapshot.shadow_deduplicated == 1
    assert len(snapshot.shadow_observations) == 1
    assert snapshot.shadow_observations[0].matched
