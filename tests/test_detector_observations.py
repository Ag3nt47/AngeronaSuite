from __future__ import annotations

import hashlib
import io
import random
import time
import zipfile
from types import SimpleNamespace

import pytest

from angerona.core.eventbus import Event, EventBus, Severity
from angerona.modules import ransomware_heuristics as ransomware
from angerona.modules.network_protocol_decoder import NetworkProtocolDecoderModule


def _sample(data: bytes) -> ransomware._ContentSample:
    entropy = ransomware._shannon_entropy(data)
    return ransomware._ContentSample(
        entropy, hashlib.sha256(data).hexdigest(), len(data), ((0, len(data)),),
        True, entropy, float(entropy >= ransomware.ENTROPY_THRESHOLD), data[:32],
    )


def _state_module(tmp_path):
    module = ransomware.RansomwareHeuristicsModule()
    module._change_state_root = tmp_path / "state"
    module._load_change_state()
    bus = EventBus()
    module.bind(bus)
    return module, bus


def _storm(module, root, now):
    names = {f"report-{i}.txt" for i in range(ransomware.RENAME_THRESHOLD)}
    module._dir_snapshot[module._directory_key(root)] = dict.fromkeys(names, now - 1)
    module._detect_renames_from_snapshot(
        root, {name + ".locked": now for name in names}, now
    )
    module._check_rename_rate(now)


def test_static_compressed_document_is_sampled_without_active_threat(tmp_path):
    root = tmp_path / "Documents"
    root.mkdir()
    content = io.BytesIO()
    with zipfile.ZipFile(content, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("worksheet.bin", random.Random(42).randbytes(32768))
    (root / "workbook.xlsx").write_bytes(content.getvalue())
    module, bus = _state_module(tmp_path)
    module._begin_change_cycle()
    now = time.time()
    candidates, _, coverage = module._scan_root(root, now)
    assert len(candidates) == 1
    assert coverage["content_analyzed"] == 1
    assert module._evaluate_entropy(candidates, now) == 0
    observation = bus.recent(1)[0]
    assert observation.details["entropy"] >= ransomware.ENTROPY_THRESHOLD
    assert observation.severity == Severity.INFO
    assert observation.details["active_attack"] is False
    assert observation.details["disposition"] == "observation"
    assert "response_contract" not in observation.details
    # An unrelated static compressed file in the very same directory must not
    # turn a later rename burst into host-isolation authority.
    _storm(module, root, now)
    storm = bus.recent(1)[0]
    assert storm.severity == Severity.HIGH
    assert storm.details["entropy_corroborated"] is False
    assert "isolate_host" not in storm.details["response_contract"]["actions"]


def test_authenticated_ordinary_edit_and_delete_preserve_observations(tmp_path):
    module, bus = _state_module(tmp_path)
    path = str(tmp_path / "notes.txt")
    identity = ("posix", 1, 10)
    module._begin_change_cycle()
    assert module._record_change_observation(path, identity, 4096, 1, _sample(b"A" * 4096)) == "new"
    module._commit_change_cycle(complete=True)
    module._begin_change_cycle()
    assert module._record_change_observation(path, identity, 4096, 2, _sample(b"B" * 4096)) == "changed"
    module._commit_change_cycle(complete=True)
    module._begin_change_cycle()
    module._commit_change_cycle(complete=True)
    events = [event for event in bus.recent(20) if "transition" in event.details]
    assert {event.details["transition"] for event in events} == {"changed", "missing"}
    assert all(event.details["disposition"] == "observation" for event in events)
    assert all(event.details["active_attack"] is False for event in events)
    assert all("response_contract" not in event.details for event in events)
    assert module._change_receipts == {}
    assert module._changed_entropy == {}


@pytest.mark.parametrize("changed,related", [(False, True), (True, False), (True, True)])
def test_storm_requires_changed_entropy_on_actual_rename_pair(tmp_path, monkeypatch, changed, related):
    monkeypatch.setattr(ransomware.time, "time", lambda: 1000.0)
    module, bus = _state_module(tmp_path)
    name = "report-0.txt" if related else "music.mp3"
    old_path = str(tmp_path / name)
    new_path = str(tmp_path / (name + ".locked")) if related else old_path
    old_content = b"A" * 4096 if changed else bytes(range(256)) * 16
    new_content = bytes(range(256)) * 16
    identity = ("posix", 1, 10)
    module._begin_change_cycle()
    module._record_change_observation(old_path, identity, 4096, 1, _sample(old_content))
    module._commit_change_cycle(complete=True)
    module._begin_change_cycle()
    module._record_change_observation(new_path, identity, 4096, 2, _sample(new_content))
    _storm(module, tmp_path, 1000.0)
    event = bus.recent(1)[0]
    assert event.details["entropy_corroborated"] is (changed and related)
    assert ("isolate_host" in event.details["response_contract"]["actions"]) is (changed and related)
    assert event.severity == (Severity.CRITICAL if changed and related else Severity.HIGH)


@pytest.mark.parametrize("details", [
    {}, {"qname": "kq3v9z7x1p4m8n2b5w0c.example.com"},
    {"protocol": "dns", "host": "backgroundtaskhost.exe"},
    {"event_type": "dns_query", "qname": "x" * 10000},
    {"event_type": "dns_query", "qname": {"nested": "bad.example"}},
    {"event_type": "dns_query", "qname": "prefix bad.example suffix"},
    {"event_type": "dns_query", "qname": "bad.example.."},
    {"event_type": "dns_query", "qname": "a" * 64 + ".example"},
])
def test_dns_prose_and_untyped_or_unbounded_fields_are_not_queries(details):
    module = NetworkProtocolDecoderModule()
    bus = EventBus()
    module.bind(bus)
    module._on_event(Event(
        "Process Monitor", "DNS resolve failed for codex-command-runner-0.153.0.exe",
        Severity.HIGH, details=details,
    ))
    assert module.stats()["dns_seen"] == 0
    assert not bus.recent(10)


@pytest.mark.parametrize("details", [
    {"protocol": "dns", "qname": "kq3v9z7x1p4m8n2b5w0c.example.com."},
    {"event_type": "dns_query", "query_name": "kq3v9z7x1p4m8n2b5w0c.example.com"},
])
def test_typed_dns_lexical_signal_is_observation(details):
    module = NetworkProtocolDecoderModule()
    bus = EventBus()
    module.bind(bus)
    module._on_event(Event("DNS Sensor", "DNS query observed", Severity.INFO, details=details))
    assert module.stats()["dns_seen"] == 1
    event = bus.recent(1)[0]
    assert event.details["suspicious"] is True
    assert event.severity == Severity.MEDIUM
    assert event.details["active_attack"] is False
    assert event.details["disposition"] == "observation"
    assert "response_contract" not in event.details


@pytest.mark.parametrize("process_name", ["ChatGPT.exe", "msedgewebview2.exe", "unknown.exe"])
def test_rwx_observation_does_not_depend_on_process_name(process_name, monkeypatch):
    from angerona.modules.mem_inject_scanner import MemInjectScannerModule, PAGE_EXECUTE_READWRITE

    module = MemInjectScannerModule()
    bus = EventBus()
    module.bind(bus)
    monkeypatch.setattr(module, "_enrich_process", lambda _pid: {})
    module._alert(42, process_name, [(0x1000, 8192, PAGE_EXECUTE_READWRITE)])
    event = bus.recent(1)[0]
    assert event.severity == Severity.MEDIUM
    assert event.details["active_attack"] is False
    assert event.details["disposition"] == "observation"
    assert "response_contract" not in event.details


def test_cadence_observation_can_promote_when_intelligence_arrives(monkeypatch):
    from angerona.modules import beacon_detector

    state = {"now": 1000.0, "present": True, "intel": False}
    monkeypatch.setattr(beacon_detector.psutil, "Process", lambda _pid: SimpleNamespace(
        name=lambda: "MpDefenderCoreService.exe", create_time=lambda: 900.0,
    ))
    monkeypatch.setattr(beacon_detector, "is_ip_flagged", lambda _ip: state["intel"])
    monkeypatch.setattr(beacon_detector.time, "time", lambda: state["now"])
    monkeypatch.setattr(beacon_detector, "list_connections", lambda: [
        {"pid": 42, "status": "ESTABLISHED", "raddr": "8.8.8.8:443"}
    ] if state["present"] else [])
    module = beacon_detector.BeaconDetectorModule()
    bus = EventBus()
    module.bind(bus)
    for callback in range(6):
        state.update(now=1000.0 + callback * 60, present=True, intel=callback >= 4)
        module._poll_once()
        state["present"] = False
        module._poll_once()
    events = bus.recent(10)
    assert len(events) == 2
    observation = next(event for event in events if event.severity == Severity.MEDIUM)
    corroborated = next(event for event in events if event.severity == Severity.HIGH)
    assert observation.details["active_attack"] is False
    assert "response_contract" not in observation.details
    assert corroborated.details["active_attack"] is True
    assert corroborated.details["response_contract"]["targets"]["remote_ips"] == ["8.8.8.8"]
    assert corroborated.details["response_contract"]["targets"]["process_create_time"] == 900.0


def test_lattice_does_not_elevate_calibrated_observations_on_same_process():
    from angerona.modules.evidence_lattice import EvidenceLatticeModule

    module = EvidenceLatticeModule()
    bus = EventBus()
    module.bind(bus)
    sources = (
        ("Memory Injection Scanner", "rwx-memory-indicator-alert-only"),
        ("C2 Beacon Detector", "cadence-indicator-alert-only"),
        ("Network Protocol Deep Decoder", "dns-lexical-observation"),
    )
    for name, policy in sources:
        module._on_event(Event(name, "Uncorroborated observation", Severity.MEDIUM, details={
            "pid": 42, "process_create_time": 900.0, "disposition": "observation",
            "active_attack": False, "detector_policy": policy,
            "threat_intel_corroborated": False,
        }))
    assert not bus.recent(10)
    assert module.lattice.counts() == (0, 0)


def test_lattice_observation_cannot_complete_otherwise_eligible_evidence():
    from angerona.modules.evidence_lattice import EvidenceLatticeModule

    module = EvidenceLatticeModule()
    bus = EventBus()
    module.bind(bus)
    details = {"pid": 42, "process_create_time": 900.0}
    for name in ("Memory Integrity Sensor", "Network Packet Sensor"):
        module._on_event(Event(name, "Independent detector evidence", Severity.MEDIUM, details=details))
    module._on_event(Event("Process Monitor", "Calibrated observation", Severity.MEDIUM, details={
        **details, "disposition": "observation", "active_attack": False,
    }))
    assert not bus.recent(10)
    # Eligible independent evidence still reaches the existing correlation and
    # exact process-generation contract after the observation was excluded.
    module._on_event(Event("Process Monitor", "Independent detector evidence", Severity.MEDIUM, details=details))
    finding = bus.recent(1)[0]
    assert finding.severity == Severity.HIGH
    assert finding.details["response_contract"]["targets"]["pid"] == 42
    assert finding.details["response_contract"]["targets"]["process_create_time"] == 900.0
