from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.core import detection_promotion as promotion_module
from angerona.core.detection_promotion import (
    DetectionPromotionCoordinator,
    PromotionAuthority,
    PromotionError,
    PromotionPolicy,
    PromotionReceipt,
)
from angerona.core.detection_quality_store import (
    DetectionQualityStore,
    QualityInputAuthority,
)
from angerona.core.detection_registry import DetectionPackageRegistry
from angerona.core.eventbus import EventBus
from angerona.modules.detection_runtime import (
    DetectionRuntimeEngine,
    DetectionRuntimeModule,
)

from test_cycle34_round2_detection import (
    _approval,
    _stage,
    _stack,
    _wait_live,
)


def _python_environment() -> dict[str, str]:
    environment = os.environ.copy()
    source = str(Path(__file__).resolve().parents[1] / "src")
    inherited = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = (
        source if not inherited else source + os.pathsep + inherited
    )
    return environment


def _run_child(script: str, *arguments: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", script, *(str(argument) for argument in arguments)],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
        env=_python_environment(),
    )


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _rewrite_as_legacy(stack, schema: str) -> None:
    state = json.loads(stack.coordinator.state_path.read_text(encoding="utf-8"))
    state.pop("authority_time_floor")
    if schema.endswith(".v2"):
        state.pop("active_bindings")
    state["schema"] = schema
    state["hmac"] = ""
    unsigned_state = dict(state)
    unsigned_state.pop("hmac")
    state["hmac"] = stack.authority.state_mac(unsigned_state)
    checkpoint = {
        "schema": "angerona.detection-promotion-checkpoint.v1",
        "serial": state["serial"],
        "transition_head": state["transition_head"],
        "state_hmac": state["hmac"],
        "hmac": "",
    }
    unsigned_checkpoint = dict(checkpoint)
    unsigned_checkpoint.pop("hmac")
    checkpoint["hmac"] = stack.authority.state_mac(
        unsigned_checkpoint, checkpoint=True
    )
    anchor = {
        "schema": "angerona.detection-promotion-monotonic-anchor.v1",
        "serial": state["serial"],
        "transition_head": state["transition_head"],
        "state_hmac": state["hmac"],
        "hmac": "",
    }
    unsigned_anchor = dict(anchor)
    unsigned_anchor.pop("hmac")
    anchor["hmac"] = stack.authority.state_mac(
        unsigned_anchor, anchor=True
    )
    stack.coordinator.state_path.write_bytes(_canonical(state))
    stack.coordinator.checkpoint_path.write_bytes(_canonical(checkpoint))
    stack.coordinator.anchor_path.write_bytes(_canonical(anchor))


def _legacy_a_b_a_state(tmp_path, schema: str):
    stack = _stack(tmp_path)
    first = _stage(tmp_path, stack.registry, "1.0.0", "shared")
    first_approval = _approval(stack, first)
    assert stack.coordinator.promote(first_approval).ok

    stack.clock.value = 1003.0
    second = _stage(tmp_path, stack.registry, "1.1.0", "shared")
    second_approval = _approval(stack, second)
    assert stack.coordinator.promote(second_approval).ok

    stack.clock.value = 1904.0
    rollback = stack.coordinator.issue_rollback_receipt(
        package_id=first.package_id,
        signer="cycle34-operator",
        tuning_digest="sha256:" + "2" * 64,
        resource_coverage=("process.creation",),
    )
    assert stack.coordinator.rollback(rollback).ok
    before = json.loads(stack.coordinator.state_path.read_text(encoding="utf-8"))
    assert before["serial"] == 3
    assert second_approval.receipt_id not in {
        item["receipt_id"] for item in before["used_receipts"]
    }
    _rewrite_as_legacy(stack, schema)
    return stack, first, second_approval


def test_governance_anchor_rejects_partial_and_missing_anchor_replay(tmp_path):
    root = tmp_path / "registry"
    key = b"g" * 32
    weak = DetectionPackageRegistry(
        root,
        require_signed=False,
        transition_authority=key,
    )
    captured_weak_manifest = weak.manifest_path.read_bytes()

    strong = DetectionPackageRegistry(
        root,
        require_signed=True,
        transition_authority=key,
    )
    current_anchor = strong.governance_anchor_path.read_bytes()
    weak.manifest_path.write_bytes(captured_weak_manifest)
    with pytest.raises(Exception, match="partially rolled back|signature policy"):
        strong.inventory()
    assert strong.governance_anchor_path.read_bytes() == current_anchor

    # A fresh process has no in-memory policy floor.  Deleting the durable
    # anchor must still fail closed; an existing governed manifest is never
    # treated as a legacy manifest eligible to mint a replacement anchor.
    strong.governance_anchor_path.unlink()
    child = _run_child(
        """
import sys
from angerona.core.detection_registry import DetectionPackageRegistry
try:
    DetectionPackageRegistry(sys.argv[1], require_signed=True,
                             transition_authority=b'g' * 32)
except Exception as exc:
    print(type(exc).__name__ + ':' + str(exc))
    raise SystemExit(0)
raise SystemExit(3)
""",
        root,
    )
    assert child.returncode == 0, child.stderr
    assert "anchor is missing" in child.stdout
    assert not strong.governance_anchor_path.exists()


def test_root_owner_lease_allows_exact_owner_only_and_rejects_foreign_process(
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
    sibling = None
    try:
        sibling_registry = DetectionPackageRegistry(
            stack.registry.root,
            require_signed=False,
            transition_authority=b"g" * 32,
        )
        sibling = DetectionPromotionCoordinator(
            sibling_registry,
            stack.quality,
            stack.authority,
            stack.policy,
            clock=stack.clock,
            transition_capability=b"g" * 32,
            runtime_module=module,
            runtime_manager=manager,
            runtime_engine=module.engine,
        )

        with pytest.raises(PromotionError, match="foreign authority"):
            DetectionPromotionCoordinator(
                sibling_registry,
                stack.quality,
                stack.authority,
                stack.policy,
                state_path=tmp_path / "alternate-promotion-state.json",
                clock=stack.clock,
                transition_capability=b"g" * 32,
                runtime_module=module,
                runtime_manager=manager,
                runtime_engine=module.engine,
            )

        alternate_quality = DetectionQualityStore(
            stack.quality.path,
            key=b"q" * 32,
            input_authority=stack.input_authority,
            clock=stack.clock,
        )
        authority_mismatches = (
            (alternate_quality, stack.authority, stack.policy),
            (
                stack.quality,
                PromotionAuthority(b"p" * 32, clock=stack.clock),
                stack.policy,
            ),
            (stack.quality, stack.authority, PromotionPolicy()),
        )
        for quality, authority, policy in authority_mismatches:
            with pytest.raises(PromotionError, match="foreign authority"):
                DetectionPromotionCoordinator(
                    sibling_registry,
                    quality,
                    authority,
                    policy,
                    clock=stack.clock,
                    transition_capability=b"g" * 32,
                    runtime_module=module,
                    runtime_manager=manager,
                    runtime_engine=module.engine,
                )

        original_registry = sibling.registry
        alternate_registries = (
            DetectionPackageRegistry(
                tmp_path / "alternate-governed-registry",
                require_signed=False,
                transition_authority=b"g" * 32,
            ),
            DetectionPackageRegistry(
                tmp_path / "alternate-ungoverned-registry",
                require_signed=False,
            ),
        )
        for alternate_registry in alternate_registries:
            sibling.registry = alternate_registry
            with pytest.raises(PromotionError, match="authority binding changed"):
                with sibling._locked():  # noqa: SLF001 - mutation regression
                    pass
        sibling.registry = original_registry

        original_lock_path = sibling.lock_path
        sibling.lock_path = tmp_path / "alternate-promotion.lock"
        with pytest.raises(PromotionError, match="authority binding changed"):
            with sibling._locked():  # noqa: SLF001 - mutation regression
                pass
        sibling.lock_path = original_lock_path

        original_clock = sibling._clock  # noqa: SLF001 - binding regression
        sibling._clock = lambda: stack.clock.value  # noqa: SLF001
        with pytest.raises(PromotionError, match="authority binding changed"):
            with sibling._locked():  # noqa: SLF001 - mutation regression
                pass
        sibling._clock = original_clock  # noqa: SLF001

        with pytest.raises(PromotionError, match="foreign runtime"):
            DetectionPromotionCoordinator(
                sibling_registry,
                stack.quality,
                stack.authority,
                stack.policy,
                clock=stack.clock,
                transition_capability=b"g" * 32,
                runtime_engine=DetectionRuntimeEngine(),
            )

        child = _run_child(
            """
import sys
from angerona.core.detection_promotion import (DetectionPromotionCoordinator,
                                                PromotionAuthority)
from angerona.core.detection_quality_store import (DetectionQualityStore,
                                                    QualityInputAuthority)
from angerona.core.detection_registry import DetectionPackageRegistry
from angerona.modules.detection_runtime import DetectionRuntimeEngine
clock = lambda: 1002.0
try:
    registry = DetectionPackageRegistry(sys.argv[1], require_signed=False,
                                        transition_authority=b'g' * 32)
    inputs = QualityInputAuthority(b'i' * 32, clock=clock)
    quality = DetectionQualityStore(sys.argv[2], key=b'q' * 32,
                                    input_authority=inputs, clock=clock)
    DetectionPromotionCoordinator(registry, quality,
        PromotionAuthority(b'p' * 32, clock=clock), clock=clock,
        transition_capability=b'g' * 32,
        runtime_engine=DetectionRuntimeEngine())
except Exception as exc:
    print(type(exc).__name__ + ':' + str(exc))
    raise SystemExit(0)
raise SystemExit(3)
""",
            stack.registry.root,
            stack.quality.path,
        )
        assert child.returncode == 0, child.stderr
        assert "owner lease" in child.stdout
    finally:
        if sibling is not None:
            sibling.close()
        stack.coordinator.close()
        module.stop()
        thread = module._thread  # noqa: SLF001 - exact owner cleanup
        if thread is not None:
            thread.join(timeout=2.0)


def test_ungoverned_coordinator_rejects_registry_authority_swap(tmp_path):
    stack = _stack(tmp_path / "development")
    original_registry = stack.coordinator.registry
    try:
        replacement = DetectionPackageRegistry(
            tmp_path / "governed-replacement",
            require_signed=False,
            transition_authority=b"g" * 32,
        )
        stack.coordinator.registry = replacement
        with pytest.raises(PromotionError, match="authority binding changed"):
            with stack.coordinator._locked():  # noqa: SLF001 - mutation regression
                pass
    finally:
        stack.coordinator.registry = original_registry
        stack.coordinator.close()


def test_root_owner_lease_allows_equivalent_default_authority_clock(tmp_path):
    key = b"g" * 32
    clock = lambda: 1002.0
    registry = DetectionPackageRegistry(
        tmp_path / "registry",
        require_signed=False,
        transition_authority=key,
    )
    inputs = QualityInputAuthority(b"i" * 32, clock=clock)
    quality = DetectionQualityStore(
        tmp_path / "quality.jsonl",
        key=b"q" * 32,
        input_authority=inputs,
        clock=clock,
    )
    authority = PromotionAuthority(b"p" * 32, clock=clock)
    policy = PromotionPolicy()
    engine = DetectionRuntimeEngine()
    first = DetectionPromotionCoordinator(
        registry,
        quality,
        authority,
        policy,
        transition_capability=key,
        runtime_engine=engine,
    )
    sibling = None
    try:
        sibling_registry = DetectionPackageRegistry(
            registry.root,
            require_signed=False,
            transition_authority=key,
        )
        sibling = DetectionPromotionCoordinator(
            sibling_registry,
            quality,
            authority,
            policy,
            transition_capability=key,
            runtime_engine=engine,
        )
        with sibling._locked():  # noqa: SLF001 - exact shared authority proof
            pass
    finally:
        if sibling is not None:
            sibling.close()
        first.close()


class _FirstLockEntryGate:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._gate_next_entry = True
        self.blocked = threading.Event()
        self.resume = threading.Event()

    def __enter__(self):
        if self._gate_next_entry:
            self._gate_next_entry = False
            self.blocked.set()
            if not self.resume.wait(timeout=5.0):
                raise RuntimeError("test lock gate timed out")
        self._lock.acquire()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._lock.release()
        return False


def test_locked_rechecks_lifecycle_after_close_and_foreign_takeover(tmp_path):
    stack = _stack(
        tmp_path,
        root_key=b"g" * 32,
        engine=DetectionRuntimeEngine(),
    )
    coordinator = stack.coordinator
    gate = _FirstLockEntryGate()
    coordinator._thread_lock = gate  # noqa: SLF001 - deterministic TOCTOU gate
    entered = threading.Event()
    errors: list[BaseException] = []
    foreign = None

    def stale_operation() -> None:
        try:
            with coordinator._locked():  # noqa: SLF001 - exact lifecycle boundary
                entered.set()
        except BaseException as exc:  # noqa: BLE001 - preserve thread failure
            errors.append(exc)

    worker = threading.Thread(target=stale_operation, daemon=True)
    worker.start()
    try:
        assert gate.blocked.wait(timeout=5.0)
        coordinator.close()
        foreign = DetectionPromotionCoordinator(
            stack.registry,
            stack.quality,
            stack.authority,
            stack.policy,
            clock=stack.clock,
            transition_capability=b"g" * 32,
            runtime_engine=DetectionRuntimeEngine(),
        )
        with foreign._locked():  # noqa: SLF001 - prove completed takeover
            pass
        gate.resume.set()
        worker.join(timeout=5.0)
        assert not worker.is_alive()
        assert not entered.is_set()
        assert len(errors) == 1
        assert isinstance(errors[0], PromotionError)
        assert "closed" in str(errors[0])
    finally:
        gate.resume.set()
        worker.join(timeout=5.0)
        if foreign is not None:
            foreign.close()
        coordinator.close()


def test_owner_binding_rejects_creator_pid_change(tmp_path, monkeypatch):
    stack = _stack(
        tmp_path,
        root_key=b"g" * 32,
        engine=DetectionRuntimeEngine(),
    )
    creator_pid = os.getpid()
    try:
        with monkeypatch.context() as patch:
            patch.setattr(
                promotion_module, "_discard_inherited_owner_leases", lambda: None
            )
            patch.setattr(promotion_module.os, "getpid", lambda: creator_pid + 1)
            with pytest.raises(PromotionError, match="authority binding changed"):
                with stack.coordinator._locked():  # noqa: SLF001
                    pass
        with stack.coordinator._locked():  # noqa: SLF001 - parent remains valid
            pass
    finally:
        stack.coordinator.close()


@pytest.mark.skipif(not hasattr(os, "fork"), reason="POSIX fork semantics required")
def test_forked_coordinator_cannot_use_or_unlock_parent_owner_lease(tmp_path):
    stack = _stack(
        tmp_path,
        root_key=b"g" * 32,
        engine=DetectionRuntimeEngine(),
    )
    read_fd, write_fd = os.pipe()
    child_pid = os.fork()
    if child_pid == 0:  # pragma: no cover - exercised only on POSIX
        os.close(read_fd)
        result: dict[str, object] = {}
        try:
            try:
                with stack.coordinator._locked():  # noqa: SLF001
                    result["inherited_use"] = "accepted"
            except PromotionError as exc:
                result["inherited_use"] = str(exc)
            stack.coordinator.close()
            try:
                takeover = DetectionPromotionCoordinator(
                    stack.registry,
                    stack.quality,
                    stack.authority,
                    stack.policy,
                    clock=stack.clock,
                    transition_capability=b"g" * 32,
                    runtime_engine=DetectionRuntimeEngine(),
                )
            except PromotionError as exc:
                result["takeover"] = str(exc)
            else:
                result["takeover"] = "accepted"
                takeover.close()
        except BaseException as exc:  # noqa: BLE001
            result["child_error"] = f"{type(exc).__name__}: {exc}"
        os.write(write_fd, json.dumps(result).encode("utf-8"))
        os.close(write_fd)
        os._exit(0)

    os.close(write_fd)
    try:
        payload = bytearray()
        while chunk := os.read(read_fd, 4096):
            payload.extend(chunk)
        _waited_pid, status = os.waitpid(child_pid, 0)
        assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
        result = json.loads(payload.decode("utf-8"))
        assert "authority binding changed" in result["inherited_use"]
        assert "another process" in result["takeover"]
        assert "child_error" not in result
        with stack.coordinator._locked():  # noqa: SLF001 - parent lease survived
            pass
    finally:
        os.close(read_fd)
        stack.coordinator.close()


def test_pruned_receipt_cannot_replay_after_true_restart_and_clock_rollback(
    tmp_path,
):
    stack = _stack(tmp_path)
    first = _stage(tmp_path, stack.registry, "1.0.0", "shared")
    first_approval = _approval(stack, first)
    assert stack.coordinator.promote(first_approval).ok

    stack.clock.value = first_approval.expires_at + 1.0
    second = _stage(tmp_path, stack.registry, "1.1.0", "shared")
    assert stack.coordinator.promote(_approval(stack, second)).ok
    advanced = json.loads(stack.coordinator.state_path.read_text(encoding="utf-8"))
    assert advanced["authority_time_floor"] == stack.clock.value
    assert first_approval.receipt_id not in {
        item["receipt_id"] for item in advanced["used_receipts"]
    }

    stack.coordinator.close()
    child = _run_child(
        """
import sys
from angerona.core.detection_promotion import (DetectionPromotionCoordinator,
                                                PromotionAuthority)
from angerona.core.detection_quality_store import (DetectionQualityStore,
                                                    QualityInputAuthority)
from angerona.core.detection_registry import DetectionPackageRegistry
clock = lambda: 1002.0
try:
    registry = DetectionPackageRegistry(sys.argv[1], require_signed=False)
    inputs = QualityInputAuthority(b'i' * 32, clock=clock)
    quality = DetectionQualityStore(sys.argv[2], key=b'q' * 32,
                                    input_authority=inputs, clock=clock)
    DetectionPromotionCoordinator(registry, quality,
        PromotionAuthority(b'p' * 32, clock=clock), clock=clock)
except Exception as exc:
    print(type(exc).__name__ + ':' + str(exc))
    raise SystemExit(0)
raise SystemExit(3)
""",
        stack.registry.root,
        stack.quality.path,
    )
    assert child.returncode == 0, child.stderr
    assert "clock rollback" in child.stdout


@pytest.mark.parametrize("schema", [
    "angerona.detection-promotion-state.v2",
    "angerona.detection-promotion-state.v3",
])
def test_legacy_migration_rejects_a_b_a_replay_after_fresh_process_rollback(
    tmp_path, schema,
):
    stack, _first, captured = _legacy_a_b_a_state(tmp_path, schema)
    receipt_path = tmp_path / "captured-b-receipt.json"
    receipt_path.write_text(json.dumps(captured.to_dict()), encoding="utf-8")
    stack.coordinator.close()

    child = _run_child(
        """
import json
import sys
from angerona.core.detection_promotion import (DetectionPromotionCoordinator,
                                                PromotionAuthority,
                                                PromotionReceipt)
from angerona.core.detection_quality_store import (DetectionQualityStore,
                                                    QualityInputAuthority)
from angerona.core.detection_registry import DetectionPackageRegistry
clock = lambda: 1102.0
try:
    registry = DetectionPackageRegistry(sys.argv[1], require_signed=False)
    inputs = QualityInputAuthority(b'i' * 32, clock=clock)
    quality = DetectionQualityStore(sys.argv[2], key=b'q' * 32,
                                    input_authority=inputs, clock=clock)
    coordinator = DetectionPromotionCoordinator(registry, quality,
        PromotionAuthority(b'p' * 32, clock=clock), clock=clock)
except Exception as exc:
    print(type(exc).__name__ + ':' + str(exc))
    raise SystemExit(0)
raw = json.loads(open(sys.argv[3], encoding='utf-8').read())
raw['resource_coverage'] = tuple(raw['resource_coverage'])
result = coordinator.promote(PromotionReceipt(**raw))
print('unexpected-replay:' + str(result.ok) + ':' + '|'.join(result.errors))
raise SystemExit(4 if result.ok else 3)
""",
        stack.registry.root,
        stack.quality.path,
        receipt_path,
    )
    assert child.returncode == 0, child.stdout + child.stderr
    assert "clock rollback predates legacy history" in child.stdout


@pytest.mark.parametrize("schema", [
    "angerona.detection-promotion-state.v2",
    "angerona.detection-promotion-state.v3",
])
def test_legacy_migration_preserves_pruned_receipts_at_safe_upgrade_time(
    tmp_path, schema,
):
    stack, first, captured = _legacy_a_b_a_state(tmp_path, schema)
    stack.coordinator.close()
    migrated = DetectionPromotionCoordinator(
        stack.registry,
        stack.quality,
        stack.authority,
        stack.policy,
        clock=stack.clock,
    )
    state = json.loads(migrated.state_path.read_text(encoding="utf-8"))
    assert state["authority_time_floor"] == 1904.0
    assert state["active_bindings"] == {
        first.package_id: first.document["digest"]
    }
    used = {item["receipt_id"]: item["expires_at"] for item in state["used_receipts"]}
    assert captured.receipt_id in used
    assert used[captured.receipt_id] >= 1003.0 + 86_400.0
    assert {
        transition["receipt_id"] for transition in state["transitions"][:-1]
    }.issubset(used)

    stack.clock.value = 1102.0
    replay = migrated.promote(captured)
    assert not replay.ok
    assert "clock rollback" in replay.errors[0]


def test_abort_and_rollback_keep_non_decreasing_authority_time(tmp_path):
    stack = _stack(tmp_path)
    first = _stage(tmp_path, stack.registry, "1.0.0", "shared")
    assert stack.coordinator.promote(_approval(stack, first)).ok

    stack.clock.value = 1100.0
    second = _stage(tmp_path, stack.registry, "1.1.0", "shared")
    assert stack.coordinator.promote(_approval(stack, second)).ok

    stack.clock.value = 1150.0
    broken = _stage(tmp_path, stack.registry, "1.2.0", "shared")
    broken_approval = _approval(stack, broken)
    package_path = stack.registry.packages / stack.registry._filename(  # noqa: SLF001
        broken.document["digest"]
    )
    package_path.write_bytes(b'{"tampered":true}')
    rejected = stack.coordinator.promote(broken_approval)
    assert not rejected.ok
    after_abort = json.loads(
        stack.coordinator.state_path.read_text(encoding="utf-8")
    )
    assert after_abort["authority_time_floor"] == 1150.0
    assert broken_approval.receipt_id in {
        item["receipt_id"] for item in after_abort["used_receipts"]
    }
    assert not stack.coordinator.promote(broken_approval).ok

    stack.clock.value = 1200.0
    rollback = stack.coordinator.issue_rollback_receipt(
        package_id=first.package_id,
        signer="cycle34-operator",
        tuning_digest="sha256:" + "1" * 64,
        resource_coverage=("process.creation",),
    )
    assert rollback.target_digest == first.document["digest"]
    rolled_back = stack.coordinator.rollback(rollback)
    assert rolled_back.ok
    after_rollback = json.loads(
        stack.coordinator.state_path.read_text(encoding="utf-8")
    )
    assert after_rollback["authority_time_floor"] == 1200.0
    assert after_rollback["active_bindings"] == {
        first.package_id: first.document["digest"]
    }


def test_pending_journal_is_recovered_before_next_authority_entry(
    tmp_path, monkeypatch,
):
    stack = _stack(tmp_path)
    candidate = _stage(tmp_path, stack.registry, "1.0.0", "shared")
    approval = _approval(stack, candidate)
    original_clear = stack.coordinator._clear_transaction  # noqa: SLF001
    monkeypatch.setattr(stack.coordinator, "_clear_transaction", lambda: None)
    assert stack.coordinator.promote(approval).ok
    assert stack.coordinator.transaction_path.exists()
    monkeypatch.setattr(stack.coordinator, "_clear_transaction", original_clear)

    bindings, epoch = stack.coordinator.authoritative_runtime_bindings()
    assert bindings == ((candidate.package_id, candidate.document["digest"]),)
    assert epoch == 1
    assert not stack.coordinator.transaction_path.exists()


def test_quarantined_active_binding_converges_and_unrelated_transition_recovers(
    tmp_path,
):
    stack = _stack(tmp_path)
    active = _stage(tmp_path, stack.registry, "1.0.0", "shared")
    assert stack.coordinator.promote(_approval(stack, active)).ok
    package_path = stack.registry.packages / stack.registry._filename(  # noqa: SLF001
        active.document["digest"]
    )
    package_path.write_bytes(b'{"tampered":true}')
    assert stack.registry.active(active.package_id) is None

    bindings, converged_epoch = stack.coordinator.authoritative_runtime_bindings()
    assert bindings == ()
    assert converged_epoch == 2
    assert not stack.coordinator.transaction_path.exists()

    replacement = _stage(
        tmp_path,
        stack.registry,
        "2.0.0",
        "shared",
    )
    recovered = stack.coordinator.promote(_approval(stack, replacement))
    assert recovered.ok
    assert stack.registry.active(replacement.package_id).document["digest"] == (
        replacement.document["digest"]
    )


def test_quarantine_commit_failure_recovers_on_restart_and_burns_receipt(
    tmp_path, monkeypatch,
):
    stack = _stack(tmp_path)
    active = _stage(tmp_path, stack.registry, "1.0.0", "shared")
    assert stack.coordinator.promote(_approval(stack, active)).ok
    candidate = _stage(tmp_path, stack.registry, "1.1.0", "shared")
    approval = _approval(stack, candidate)
    package_path = stack.registry.packages / stack.registry._filename(  # noqa: SLF001
        candidate.document["digest"]
    )
    package_path.write_bytes(b'{"tampered":true}')

    original_write_state = stack.coordinator._write_state  # noqa: SLF001
    failed = False

    def fail_once(state, *, recovering=False):
        nonlocal failed
        if stack.coordinator.transaction_path.exists() and not failed:
            failed = True
            raise OSError("quarantine state boundary")
        return original_write_state(state, recovering=recovering)

    monkeypatch.setattr(stack.coordinator, "_write_state", fail_once)
    assert not stack.coordinator.promote(approval).ok
    assert failed and stack.coordinator.transaction_path.exists()
    stack.coordinator.close()

    restarted = DetectionPromotionCoordinator(
        stack.registry,
        stack.quality,
        stack.authority,
        stack.policy,
        clock=stack.clock,
    )
    bindings, epoch = restarted.authoritative_runtime_bindings()
    assert dict(bindings) == {active.package_id: active.document["digest"]}
    assert epoch == 2
    assert not restarted.transaction_path.exists()
    replay = restarted.promote(approval)
    assert not replay.ok
    assert "consumed" in replay.errors[0]
