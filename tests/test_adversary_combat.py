from __future__ import annotations

import queue
import time
from types import SimpleNamespace

from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.modules.adversary_combat import AdversaryCombat
from angerona.modules.file_integrity import _combat_intervals
from angerona.shark.aar_report import evaluate


def _module(tmp_path, **overrides) -> tuple[AdversaryCombat, EventBus]:
    values = {
        "data_dir": tmp_path,
        "adversary_combat_enabled": True,
        "adversary_combat_mode": "maximum",
        "adversary_combat_min_severity": "LOW",
        "adversary_combat_block_network": False,
        "adversary_combat_quarantine_files": True,
        "adversary_combat_process_action": "terminate",
        "adversary_combat_isolate_host": False,
        "adversary_combat_activate_honeypots": False,
        "adversary_combat_isolation_threshold": 3,
    }
    values.update(overrides)
    manager = SimpleNamespace(config=SimpleNamespace(**values), modules={})
    bus = EventBus()
    module = AdversaryCombat(tmp_path)
    module.bind(bus)
    module.bind_manager(manager)
    manager.modules[module.name] = module
    return module, bus


def test_maximum_policy_is_armed_without_per_incident_approval(tmp_path, monkeypatch):
    for key in tuple(__import__("os").environ):
        if key.startswith("ANGERONA_ADVERSARY_COMBAT_"):
            monkeypatch.delenv(key, raising=False)
    module, _bus = _module(tmp_path)

    policy = module.policy()

    assert policy.enabled is True
    assert policy.mode == "maximum"
    assert policy.min_severity == Severity.LOW
    assert policy.process_action == "terminate"


def test_self_test_does_not_claim_a_stopped_worker_is_armed(tmp_path):
    module, _bus = _module(tmp_path)

    ok, detail = module.self_test()

    assert ok is False
    assert "status=stopped" in detail
    assert "armed" not in detail.casefold()


def test_saturated_queue_releases_dedup_and_emits_signed_soar_failure(tmp_path):
    module, bus = _module(tmp_path)
    bus.arm(BusAuthority(b"q" * 32))
    module.status = "running"
    module._queue = queue.Queue(maxsize=1)
    module._queue.put_nowait(Event("filler", "filler", Severity.LOW))
    request_id = "a" * 32
    event = Event(
        "SOAR Operator Request",
        "exact request",
        Severity.HIGH,
        time.time(),
        {
            "active_attack": True,
            "queue_request_id": request_id,
            "response_authorized": True,
            "response_contract": {
                "version": 1,
                "actions": ["activate_honeypots"],
                "targets": {"deception": "Smart Deception"},
            },
        },
    )
    bus.publish(event)
    signed_request = bus.recent(1)[0]

    module._submit(signed_request)

    identity = f"soar:{request_id}"
    assert identity not in module._seen
    receipt = bus.recent(1)[0]
    assert receipt.module == "Adversary Combat"
    assert receipt.details["queue_request_id"] == request_id
    assert receipt.details["action_succeeded"] is False
    assert receipt.details["failure_reason"] == "combat_queue_saturated"
    assert bus.verify(receipt) is True

    module._queue.get_nowait()
    module._submit(signed_request)
    assert module._queue.get_nowait() is signed_request
    assert identity in module._seen


def test_file_quarantine_emits_success_and_undo_restores(tmp_path):
    module, bus = _module(tmp_path)
    emitted = []
    bus.subscribe(emitted.append)
    artifact = tmp_path / "hostile.bin"
    artifact.write_bytes(b"test")
    event = Event(
        "Detector",
        "confirmed hostile artifact",
        Severity.HIGH,
        time.time(),
        {
            "path": str(artifact),
            "active_attack": True,
            "response_authorized": True,
            "response_contract": {
                "version": 1,
                "actions": ["quarantine_file"],
                "targets": {"path": str(artifact)},
            },
        },
    )

    module._handle(event)

    assert not artifact.exists()
    actions = module.list_actions()
    quarantine = next(item for item in actions if item["action"] == "quarantine_file")
    assert quarantine["reversible"] is True
    assert any(
        item.module == "Adversary Combat" and item.details.get("mitigated") is True
        for item in emitted
    )

    result = module.undo_action(quarantine["action_id"])

    assert result["ok"] is True
    assert artifact.read_bytes() == b"test"
    assert module.list_actions()[0]["undone"] is True


def test_critical_maximum_event_isolates_host_with_undo_receipt(tmp_path, monkeypatch):
    module, _bus = _module(
        tmp_path,
        adversary_combat_quarantine_files=False,
        adversary_combat_isolate_host=True,
    )
    calls = []
    active_rules: set[str] = set()

    def firewall(arguments):
        calls.append(tuple(arguments))
        name = next(value[5:] for value in arguments if value.startswith("name="))
        if arguments[:2] == ["add", "rule"]:
            active_rules.add(name)
        elif arguments[:2] == ["delete", "rule"]:
            active_rules.discard(name)
        return True

    monkeypatch.setattr(
        module,
        "_run_firewall",
        firewall,
    )
    monkeypatch.setattr(module, "_firewall_rule_exists", active_rules.__contains__)
    event = Event(
        "EDR",
        "critical active attack",
        Severity.CRITICAL,
        time.time(),
        {
            "active_attack": True,
            "response_authorized": True,
            "response_contract": {
                "version": 1,
                "actions": ["isolate_host"],
                "targets": {"host": "local"},
            },
        },
    )

    module._handle(event)

    isolation = next(
        item for item in module.list_actions() if item["action"] == "isolate_host"
    )
    assert len(isolation["details"]["rules"]) == 2
    assert isolation["reversible"] is True
    assert module.undo_action(isolation["action_id"])["ok"] is True
    assert any(call[:2] == ("delete", "rule") for call in calls)


def test_shark_network_evidence_and_combat_action_correlate_exactly():
    started = time.time()
    history = {
        "run_id": "shark-network-proof",
        "steps": [{
            "stage": "Exfiltration",
            "technique": "T1041 held connection",
            "description": "dummy marker",
            "ts_start": started,
            "ts_end": started + 1,
            "pid": 4242,
            "remote_ips": ["203.0.113.10"],
            "remote_ports": [443],
            "artifact_paths": [],
        }],
    }
    detection = Event(
        "Network Monitor",
        "first contact",
        Severity.MEDIUM,
        started + 0.2,
        {
            "pid": 4242,
            "raddr": "203.0.113.10:443",
            "evidence_type": "native_analytic_detection",
            "detector_verdict": "positive",
        },
    )
    response = Event(
        "Adversary Combat",
        "remote blocked",
        Severity.HIGH,
        started + 0.3,
        {"trigger_ts": detection.ts, "mitigated": True},
    )

    verdict = evaluate(history, [detection, response])[0]

    assert verdict.catch is detection
    assert verdict.remediation is response


def test_maximum_combat_uses_realtime_fim_cadence(monkeypatch):
    monkeypatch.setenv("ANGERONA_ADVERSARY_COMBAT_ENABLED", "1")
    monkeypatch.setenv("ANGERONA_ADVERSARY_COMBAT_MODE", "maximum")

    driver_seconds, file_seconds = _combat_intervals()

    assert driver_seconds <= 0.5
    assert file_seconds <= 1.0
