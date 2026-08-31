from __future__ import annotations

import http.client
import hashlib
import json
import threading
from pathlib import Path
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
    PromotionError,
    PromotionPolicy,
    digest_tuning,
)
from angerona.core.detection_quality_store import (
    DetectionQualityStore,
    QualityInputAuthority,
)
from angerona.core.detection_registry import DetectionPackageRegistry
from angerona.core.eventbus import Event, EventBus, Severity
from angerona.core.operations_center import LocalOperationsCenter
from angerona.gui.detection_forge import DetectionForgeService
from angerona.gui.main_window import MainWindow
from angerona.modules.detection_runtime import (
    DetectionRuntimeEngine,
    DetectionRuntimeModule,
)
from angerona.modules.fleet_health_monitor import FleetHealthMonitorModule
from tools import serve_canvas


def _document(package_id: str, version: str, marker: str) -> dict[str, object]:
    return seal_package({
        "schema_version": 1,
        "id": package_id,
        "version": version,
        "owner": "Angerona remediation tests",
        "description": "Governed multi-package runtime regression fixture.",
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
        "rollback": {"previous_digest": None, "instructions": "Restore predecessor."},
        "expires_at": "2099-01-01T00:00:00Z",
    })


def _request(server, path: str, *, host: str | None = None) -> tuple[int, bytes]:
    connection = http.client.HTTPConnection(
        serve_canvas.LOOPBACK_HOST, server.server_port, timeout=3
    )
    try:
        headers = {
            "Host": host or f"{serve_canvas.LOOPBACK_HOST}:{server.server_port}"
        }
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def test_canvas_server_is_loopback_host_checked_allowlisted_and_bounded(
    tmp_path, monkeypatch,
):
    (tmp_path / "diagnostics").mkdir()
    (tmp_path / "flow_canvas.html").write_text(
        "<!doctype html><title>Angerona</title>", encoding="utf-8"
    )
    (tmp_path / "diagnostics" / "flow_metrics.json").write_text(
        '{"schema":"test"}', encoding="utf-8"
    )
    monkeypatch.setattr(serve_canvas, "_REPOSITORY_ROOT", tmp_path)
    monkeypatch.setattr(serve_canvas, "_RUNTIME_DATA_ROOT", tmp_path)
    monkeypatch.setattr(serve_canvas, "_valid_metrics", lambda _payload: True)
    server = serve_canvas.create_server(0)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        assert server.server_address[0] == "127.0.0.1"
        status, payload = _request(server, "/flow_canvas.html?refresh=1")
        assert status == 200 and b"Angerona" in payload
        status, payload = _request(server, "/diagnostics/flow_metrics.json")
        assert status == 200 and payload.lstrip().startswith(b"{")

        for forbidden in (
            "/",
            "/.git/config",
            "/analysis/loop/state.json",
            "/diagnostics/status.txt",
            "/%2e%2e/.env",
        ):
            assert _request(server, forbidden)[0] == 404
        assert _request(server, "/flow_canvas.html", host="attacker.invalid")[0] == 421

        original = serve_canvas._ALLOWED_ARTIFACTS["/flow_canvas.html"]
        monkeypatch.setitem(
            serve_canvas._ALLOWED_ARTIFACTS,
            "/flow_canvas.html",
            (*original[:3], 1),
        )
        assert _request(server, "/flow_canvas.html")[0] == 413
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)

    batch = Path("serve-canvas.bat").read_text(encoding="utf-8")
    canvas = Path("flow_canvas.html").read_text(encoding="utf-8")
    assert "-m http.server" not in batch
    assert "tools\\serve_canvas.py" in batch and "py -3" not in batch
    assert "integrity=\"sha384-" in canvas and "crossorigin=\"anonymous\"" in canvas


def test_canvas_server_rejects_allowlisted_symlink(tmp_path, monkeypatch):
    secret = tmp_path / "secret.txt"
    secret.write_text("must-not-serve", encoding="utf-8")
    flow = tmp_path / "flow_canvas.html"
    try:
        flow.symlink_to(secret)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")
    monkeypatch.setattr(serve_canvas, "_REPOSITORY_ROOT", tmp_path)
    server = serve_canvas.create_server(0)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        assert _request(server, "/flow_canvas.html")[0] == 404
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)


def test_production_registry_denies_direct_transition_without_coordinator_capability(
    tmp_path,
):
    capability = object()
    registry = DetectionPackageRegistry(
        tmp_path / "registry",
        require_signed=False,
        transition_authority=capability,
    )
    document = _document("org.angerona.cycle34-boundary", "1.0.0", "boundary")
    source = tmp_path / "boundary.json"
    source.write_text(json.dumps(document), encoding="utf-8")
    staged = registry.stage(source)
    assert staged.ok

    for report in (
        registry.activate(staged.package_id, staged.digest),
        registry.activate(
            staged.package_id, staged.digest, transition_capability=object()
        ),
        registry.rollback(staged.package_id),
        registry.retire(staged.package_id, staged.digest),
    ):
        assert not report.ok and report.state == "governance-required"
    assert registry.inventory()[staged.package_id][staged.digest]["state"] == "staged"


def test_operations_composition_binds_exact_live_detection_and_fleet_modules(tmp_path):
    bus = EventBus()
    runtime_module = DetectionRuntimeModule()
    runtime_module.bind(bus)
    fleet_module = FleetHealthMonitorModule()
    manager = SimpleNamespace(bus=bus, modules={
        runtime_module.name: runtime_module,
        fleet_module.name: fleet_module,
    })
    service = LocalOperationsCenter(
        tmp_path,
        manager=manager,
        master_key=b"c" * 32,
    )
    try:
        assert service.detection_runtime is runtime_module.engine
        assert service.detection_promotion is not None
        assert fleet_module._fabric is service.fleet_fabric
        assert fleet_module._tenant_id == "local"
        _health, reason, _details = fleet_module.observe_once()
        assert "not bound" not in reason
    finally:
        service.close()
    service.close()
    assert fleet_module._fabric is None
    health, reason, _details = fleet_module.observe_once()
    assert health == 35 and "not bound" in reason


def test_impostor_runtime_disables_governance_and_registry_stays_locked(tmp_path):
    manager = SimpleNamespace(modules={
        DetectionRuntimeModule.name: SimpleNamespace(engine=DetectionRuntimeEngine()),
        FleetHealthMonitorModule.name: FleetHealthMonitorModule(),
    })
    service = LocalOperationsCenter(
        tmp_path,
        manager=manager,
        master_key=b"d" * 32,
    )
    try:
        assert service.detection_promotion is None
        assert service.enterprise_program_status()["detection_runtime"] is False
        report = service.detections.activate(
            "org.angerona.missing", "sha256:" + "0" * 64
        )
        assert not report.ok and report.state == "governance-required"
    finally:
        service.close()


def test_operations_service_composition_is_single_flight_and_close_is_idempotent(
    tmp_path, monkeypatch,
):
    created: list[object] = []
    started = threading.Event()
    release = threading.Event()

    class _Service:
        def __init__(self):
            self.close_calls = 0

        def close(self):
            self.close_calls += 1

    def factory(*_args, **_kwargs):
        service = _Service()
        created.append(service)
        started.set()
        assert release.wait(3)
        return service

    monkeypatch.setattr(
        "angerona.core.operations_center.LocalOperationsCenter", factory
    )
    window = SimpleNamespace(
        _operations_service=None,
        _operations_service_lock=threading.Lock(),
        _operations_service_shutdown=False,
        _operations_service_cancel=threading.Event(),
        _operations_service_state="waiting",
        _operations_service_build_token=None,
        _operations_service_completion=threading.Event(),
        _operations_service_error="",
        _operations_modules_discovered=threading.Event(),
        _operations_modules_ready=threading.Event(),
        config=SimpleNamespace(data_dir=tmp_path),
        evidence_store=None,
        manager=SimpleNamespace(),
    )
    with pytest.raises(RuntimeError, match="discovery"):
        MainWindow._ensure_operations_service(window)
    window._operations_modules_discovered.set()
    results: list[object] = []
    errors: list[BaseException] = []

    def compose(*, startup_owner=False):
        try:
            results.append(MainWindow._ensure_operations_service(
                window,
                startup_owner=startup_owner,
                wait=startup_owner,
            ))
        except BaseException as exc:
            errors.append(exc)

    workers = [
        threading.Thread(target=compose, kwargs={"startup_owner": True}),
        threading.Thread(target=compose),
    ]
    workers[0].start()
    assert started.wait(2)
    workers[1].start()
    workers[1].join(timeout=1)
    assert not workers[1].is_alive()
    release.set()
    for worker in workers:
        worker.join(timeout=3)
        assert not worker.is_alive()
    assert len(created) == 1 and results == [created[0]]
    assert len(errors) == 1 and "in progress" in str(errors[0])

    MainWindow._close_operations_service(window)
    MainWindow._close_operations_service(window)
    assert created[0].close_calls == 1
    with pytest.raises(RuntimeError, match="shutting down"):
        MainWindow._ensure_operations_service(window)


class _Clock:
    def __call__(self) -> float:
        return 1002.0


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _write_authenticated_state(
    state_path: Path,
    authority: PromotionAuthority,
    *,
    schema: str,
    serial: int,
    transitions: list[dict[str, object]],
    active_bindings: dict[str, str] | None = None,
    prior_head: str = "0" * 64,
    authority_time_floor: float | None = None,
) -> None:
    head = prior_head
    for transition in transitions:
        head = hashlib.sha256(head.encode("ascii") + _canonical(transition)).hexdigest()
    state: dict[str, object] = {
        "schema": schema,
        "serial": serial,
        "used_receipts": [],
        "transitions": transitions,
        "transition_head": head,
        "hmac": "",
    }
    if active_bindings is not None:
        state["active_bindings"] = dict(sorted(active_bindings.items()))
    if authority_time_floor is not None:
        state["authority_time_floor"] = authority_time_floor
    unsigned_state = dict(state)
    unsigned_state.pop("hmac")
    state["hmac"] = authority.state_mac(unsigned_state)
    checkpoint: dict[str, object] = {
        "schema": "angerona.detection-promotion-checkpoint.v1",
        "serial": serial,
        "transition_head": head,
        "state_hmac": state["hmac"],
        "hmac": "",
    }
    if authority_time_floor is not None:
        checkpoint["authority_time_floor"] = authority_time_floor
    unsigned_checkpoint = dict(checkpoint)
    unsigned_checkpoint.pop("hmac")
    checkpoint["hmac"] = authority.state_mac(
        unsigned_checkpoint, checkpoint=True
    )
    anchor: dict[str, object] = {
        "schema": "angerona.detection-promotion-monotonic-anchor.v1",
        "serial": serial,
        "transition_head": head,
        "state_hmac": state["hmac"],
        "hmac": "",
    }
    if authority_time_floor is not None:
        anchor["authority_time_floor"] = authority_time_floor
    unsigned_anchor = dict(anchor)
    unsigned_anchor.pop("hmac")
    anchor["hmac"] = authority.state_mac(unsigned_anchor, anchor=True)
    state_path.write_bytes(_canonical(state))
    state_path.with_suffix(state_path.suffix + ".checkpoint").write_bytes(
        _canonical(checkpoint)
    )
    state_path.with_suffix(state_path.suffix + ".monotonic-anchor").write_bytes(
        _canonical(anchor)
    )


def _transition(
    serial: int,
    package_id: str,
    target_digest: str,
    *,
    previous_digest: str | None = None,
) -> dict[str, object]:
    return {
        "serial": serial,
        "receipt_id": f"legacy-receipt-{serial}",
        "action": "promote",
        "package_id": package_id,
        "previous_digest": previous_digest,
        "target_digest": target_digest,
        "authorized_at": 1001.0,
    }


def _migration_components(tmp_path):
    clock = _Clock()
    capability = object()
    registry = DetectionPackageRegistry(
        tmp_path / "registry",
        require_signed=False,
        transition_authority=capability,
    )
    quality = DetectionQualityStore(
        tmp_path / "quality.jsonl",
        key=b"q" * 32,
        clock=clock,
    )
    authority = PromotionAuthority(b"p" * 32, clock=clock)
    return clock, capability, registry, quality, authority


def test_authenticated_v2_state_migrates_by_advancing_anchor_and_full_binding(tmp_path):
    clock, capability, registry, quality, authority = _migration_components(tmp_path)
    document = _document("org.angerona.migrate-a", "1.0.0", "migrate")
    source = tmp_path / "migrate.json"
    source.write_text(json.dumps(document), encoding="utf-8")
    assert registry.stage(source).ok
    assert registry.activate(
        document["id"], document["digest"], transition_capability=capability
    ).ok
    state_path = registry.root / "promotion-state.json"
    _write_authenticated_state(
        state_path,
        authority,
        schema="angerona.detection-promotion-state.v2",
        serial=1,
        transitions=[_transition(1, document["id"], document["digest"])],
    )

    coordinator = DetectionPromotionCoordinator(
        registry,
        quality,
        authority,
        clock=clock,
        state_path=state_path,
        transition_capability=capability,
    )
    migrated = json.loads(state_path.read_text(encoding="utf-8"))
    anchor = json.loads(coordinator.anchor_path.read_text(encoding="utf-8"))
    assert migrated["schema"] == "angerona.detection-promotion-state.v3"
    assert migrated["serial"] == anchor["serial"] == 2
    assert migrated["active_bindings"] == {document["id"]: document["digest"]}
    assert coordinator.authoritative_runtime_bindings() == (
        ((document["id"], document["digest"]),),
        2,
    )


def test_authenticated_v2_truncated_history_fails_closed_migration(tmp_path):
    clock, capability, registry, quality, authority = _migration_components(tmp_path)
    document = _document("org.angerona.migrate-truncated", "1.0.0", "truncated")
    source = tmp_path / "truncated.json"
    source.write_text(json.dumps(document), encoding="utf-8")
    assert registry.stage(source).ok
    assert registry.activate(
        document["id"], document["digest"], transition_capability=capability
    ).ok
    transitions = [
        _transition(serial, document["id"], document["digest"])
        for serial in range(2, 514)
    ]
    state_path = registry.root / "promotion-state.json"
    _write_authenticated_state(
        state_path,
        authority,
        schema="angerona.detection-promotion-state.v2",
        serial=513,
        transitions=transitions,
        prior_head="1" * 64,
    )
    with pytest.raises(PromotionError, match="insufficient"):
        DetectionPromotionCoordinator(
            registry,
            quality,
            authority,
            clock=clock,
            state_path=state_path,
            transition_capability=capability,
        )


def test_authenticated_v2_registry_divergence_fails_closed_migration(tmp_path):
    clock, capability, registry, quality, authority = _migration_components(tmp_path)
    first = _document("org.angerona.migrate-diverge", "1.0.0", "diverge")
    second = _document("org.angerona.migrate-diverge", "2.0.0", "diverge")
    for name, document in (("first", first), ("second", second)):
        source = tmp_path / f"{name}.json"
        source.write_text(json.dumps(document), encoding="utf-8")
        assert registry.stage(source).ok
    assert registry.activate(
        second["id"], second["digest"], transition_capability=capability
    ).ok
    state_path = registry.root / "promotion-state.json"
    _write_authenticated_state(
        state_path,
        authority,
        schema="angerona.detection-promotion-state.v2",
        serial=1,
        transitions=[_transition(1, first["id"], first["digest"])],
    )
    with pytest.raises(PromotionError, match="cannot prove"):
        DetectionPromotionCoordinator(
            registry,
            quality,
            authority,
            clock=clock,
            state_path=state_path,
            transition_capability=capability,
        )


def test_129th_binding_is_rejected_before_state_registry_or_runtime_change(tmp_path):
    clock = _Clock()
    capability = object()
    registry = DetectionPackageRegistry(
        tmp_path / "registry",
        require_signed=False,
        transition_authority=capability,
    )
    bindings: dict[str, str] = {}
    for index in range(128):
        document = _document(
            f"org.angerona.capacity-{index:03d}",
            "1.0.0",
            f"capacity-{index:03d}",
        )
        source = tmp_path / f"capacity-{index:03d}.json"
        source.write_text(json.dumps(document), encoding="utf-8")
        assert registry.stage(source).ok
        assert registry.activate(
            document["id"],
            document["digest"],
            transition_capability=capability,
        ).ok
        bindings[document["id"]] = document["digest"]

    input_authority = QualityInputAuthority(b"i" * 32, clock=clock)
    quality = DetectionQualityStore(
        tmp_path / "quality.jsonl",
        key=b"q" * 32,
        input_authority=input_authority,
        clock=clock,
    )
    policy = PromotionPolicy()
    authority = PromotionAuthority(b"p" * 32, clock=clock)
    state_path = registry.root / "promotion-state.json"
    _write_authenticated_state(
        state_path,
        authority,
        schema="angerona.detection-promotion-state.v3",
        serial=128,
        transitions=[],
        active_bindings=bindings,
        authority_time_floor=1002.0,
    )
    coordinator = DetectionPromotionCoordinator(
        registry,
        quality,
        authority,
        policy,
        clock=clock,
        state_path=state_path,
        transition_capability=capability,
    )
    runtime = DetectionRuntimeEngine()
    runtime.sync_active_set_from_registry(
        registry,
        expected_bindings=bindings,
        activation_epoch=128,
    )
    service = DetectionForgeService(
        registry=registry,
        runtime=runtime,
        quality_store=quality,
        promotion=coordinator,
    )

    candidate_document = _document(
        "org.angerona.capacity-128", "1.0.0", "capacity-new"
    )
    candidate = DetectionPackage(candidate_document)
    candidate_path = tmp_path / "capacity-128.json"
    candidate_path.write_text(json.dumps(candidate_document), encoding="utf-8")
    assert registry.stage(candidate_path).ok
    cohort = capture_replay_cohort(
        [
            {
                "event_id": "capacity-hit",
                "revision": 1,
                "event": {"cmdline": "tool capacity-new"},
                "label": True,
                "label_source": "curator",
            },
            {
                "event_id": "capacity-miss",
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
        active=None,
        candidate=candidate,
        evaluated_at=1001.0,
    )
    tuning = digest_tuning({"capacity": 129})
    coverage = ("process.creation",)
    attestation = input_authority.issue(
        comparison,
        package_id=candidate.package_id,
        signer="analyst-1",
        policy_digest=policy.digest,
        tuning_digest=tuning,
        resource_coverage=coverage,
    )
    receipt = quality.append_evaluation(
        comparison,
        package_id=candidate.package_id,
        signer="analyst-1",
        policy_digest=policy.digest,
        tuning_digest=tuning,
        resource_coverage=coverage,
        input_attestation=attestation,
    )
    approval = coordinator.issue_promotion_receipt(
        receipt,
        signer="analyst-1",
        tuning_digest=tuning,
        resource_coverage=coverage,
    )

    state_before = state_path.read_bytes()
    registry_before = registry.inventory()
    runtime_before = runtime.snapshot()
    result = service.promote(approval)
    assert not result.ok and "128-rule" in result.errors[0]
    assert state_path.read_bytes() == state_before
    assert registry.inventory() == registry_before
    assert runtime.snapshot() == runtime_before


def _promote(
    *,
    tmp_path,
    service,
    coordinator,
    quality,
    input_authority,
    policy,
    active: DetectionPackage | None,
    candidate: DetectionPackage,
):
    marker = candidate.document["logic"]["detection"]["selection"]["cmdline|contains"]
    cohort = capture_replay_cohort(
        [
            {
                "event_id": f"{candidate.package_id}-hit",
                "revision": 1,
                "event": {"cmdline": f"tool {marker}"},
                "label": True,
                "label_source": "curator",
            },
            {
                "event_id": f"{candidate.package_id}-miss",
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
    tuning = digest_tuning({
        "package": candidate.package_id,
        "version": candidate.document["version"],
    })
    coverage = ("process.creation",)
    attestation = input_authority.issue(
        comparison,
        package_id=candidate.package_id,
        signer="analyst-1",
        policy_digest=policy.digest,
        tuning_digest=tuning,
        resource_coverage=coverage,
    )
    quality_receipt = quality.append_evaluation(
        comparison,
        package_id=candidate.package_id,
        signer="analyst-1",
        policy_digest=policy.digest,
        tuning_digest=tuning,
        resource_coverage=coverage,
        input_attestation=attestation,
    )
    approval = coordinator.issue_promotion_receipt(
        quality_receipt,
        signer="analyst-1",
        tuning_digest=tuning,
        resource_coverage=coverage,
    )
    result = service.promote(approval)
    assert result.ok, result.errors
    return approval


def _assert_alpha_and_bravo_fire(
    runtime: DetectionRuntimeEngine,
    findings: list,
    *,
    expected_digests: set[str],
    suffix: str,
) -> None:
    findings.clear()
    for marker in ("alpha", "bravo"):
        assert runtime.submit(
            Event(
                module="Process Monitor",
                message="process creation",
                severity=Severity.MEDIUM,
                ts=100.0,
                details={
                    "event_id": f"{suffix}-{marker}",
                    "cmdline": f"tool {marker}",
                },
            ),
            include_shadow=False,
        )
    runtime.process(max_shadow=0)
    assert {finding.package_digest for finding in findings} == expected_digests


def test_full_governed_active_set_survives_second_package_upgrade_rollback_and_restart(
    tmp_path,
):
    clock = _Clock()
    capability = object()
    registry = DetectionPackageRegistry(
        tmp_path / "registry",
        require_signed=False,
        transition_authority=capability,
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
        transition_capability=capability,
    )
    findings: list = []
    runtime = DetectionRuntimeEngine(active_sink=findings.append)
    service = DetectionForgeService(
        registry=registry,
        runtime=runtime,
        quality_store=quality,
        promotion=coordinator,
    )

    documents = {
        "a1": _document("org.angerona.cycle34-a", "1.0.0", "alpha"),
        "b1": _document("org.angerona.cycle34-b", "1.0.0", "bravo"),
        "b2": _document("org.angerona.cycle34-b", "2.0.0", "bravo"),
        "c1": _document("org.angerona.cycle34-c", "1.0.0", "charlie"),
    }
    packages = {name: DetectionPackage(document) for name, document in documents.items()}
    for name, document in documents.items():
        source = tmp_path / f"{name}.json"
        source.write_text(json.dumps(document), encoding="utf-8")
        assert registry.stage(source).ok

    first_approval = _promote(
        tmp_path=tmp_path,
        service=service,
        coordinator=coordinator,
        quality=quality,
        input_authority=input_authority,
        policy=policy,
        active=None,
        candidate=packages["a1"],
    )
    _promote(
        tmp_path=tmp_path,
        service=service,
        coordinator=coordinator,
        quality=quality,
        input_authority=input_authority,
        policy=policy,
        active=None,
        candidate=packages["b1"],
    )
    expected_a_b1 = {
        documents["a1"]["digest"],
        documents["b1"]["digest"],
    }
    assert set(runtime.snapshot().active_digests) == expected_a_b1
    _assert_alpha_and_bravo_fire(
        runtime,
        findings,
        expected_digests=expected_a_b1,
        suffix="initial",
    )

    _promote(
        tmp_path=tmp_path,
        service=service,
        coordinator=coordinator,
        quality=quality,
        input_authority=input_authority,
        policy=policy,
        active=packages["b1"],
        candidate=packages["b2"],
    )
    expected_a_b2 = {
        documents["a1"]["digest"],
        documents["b2"]["digest"],
    }
    assert set(runtime.snapshot().active_digests) == expected_a_b2
    _assert_alpha_and_bravo_fire(
        runtime,
        findings,
        expected_digests=expected_a_b2,
        suffix="upgrade",
    )

    rollback = coordinator.issue_rollback_receipt(
        package_id=packages["b2"].package_id,
        signer="analyst-1",
        tuning_digest=digest_tuning({"rollback": "b2-to-b1"}),
        resource_coverage=("process.creation",),
    )
    assert service.rollback(rollback).ok
    assert set(runtime.snapshot().active_digests) == expected_a_b1
    _assert_alpha_and_bravo_fire(
        runtime,
        findings,
        expected_digests=expected_a_b1,
        suffix="rollback",
    )

    restarted_coordinator = DetectionPromotionCoordinator(
        registry,
        quality,
        PromotionAuthority(b"p" * 32, clock=clock),
        policy,
        state_path=coordinator.state_path,
        clock=clock,
        transition_capability=capability,
    )
    bindings, epoch = restarted_coordinator.authoritative_runtime_bindings()
    restarted_runtime = DetectionRuntimeEngine()
    assert set(restarted_runtime.sync_active_set_from_registry(
        registry,
        expected_bindings=dict(bindings),
        activation_epoch=epoch,
    )) == expected_a_b1
    restarted_service = DetectionForgeService(
        registry=registry,
        runtime=restarted_runtime,
        quality_store=quality,
        promotion=restarted_coordinator,
    )

    # Missing governed content is removed through the authenticated quarantine
    # transition while its still-valid sibling remains authoritative.  The
    # original receipt stays one-use throughout that convergence.
    assert registry.retire(
        packages["a1"].package_id,
        documents["a1"]["digest"],
        transition_capability=capability,
    ).ok
    failed = restarted_service.promote(first_approval)
    assert not failed.ok and failed.state == "rejected"
    assert failed.errors == ("promotion receipt was already consumed",)
    assert restarted_runtime.snapshot().active_digests == (
        documents["b1"]["digest"],
    )
    inventory = registry.inventory()
    assert inventory[packages["a1"].package_id][documents["a1"]["digest"]][
        "state"
    ] == "quarantined"
    bindings, _epoch = restarted_coordinator.authoritative_runtime_bindings()
    assert dict(bindings) == {
        packages["b1"].package_id: documents["b1"]["digest"],
    }

    # Inject an unledgered C with the internal test capability. Full-set
    # comparison still rejects the extra active ID and clears the whole runtime.
    assert registry.activate(
        packages["c1"].package_id,
        documents["c1"]["digest"],
        transition_capability=capability,
    ).ok
    failed = restarted_service.promote(first_approval)
    assert not failed.ok and failed.state == "runtime-fail-closed"
    assert restarted_runtime.snapshot().active_digests == ()
