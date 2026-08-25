from __future__ import annotations

from types import SimpleNamespace

from angerona.core.eventbus import Event, EventBus, Severity
from angerona.core.response_contract import (
    authorize_response,
    process_and_remote_response,
    process_response,
)


def _latest(bus: EventBus) -> Event:
    return bus.recent(1)[-1]


def test_response_builder_requires_exact_typed_targets(tmp_path) -> None:
    assert process_response("42", 10.0) == {}
    assert process_response(42, "10.0") == {}
    assert process_response(True, 10.0) == {}
    assert process_response(42, float("nan")) == {}
    assert process_and_remote_response(42, 10.0, "example.test") == {}
    assert process_and_remote_response(42, None, "8.8.8.8") == {
        "response_authorized": True,
        "response_contract": {
            "version": 1,
            "actions": ["block_remote_ip"],
            "targets": {"remote_ips": ["8.8.8.8"]},
        },
    }
    assert authorize_response(("quarantine_file",), path="relative.bin") == {}

    target = tmp_path / "artifact.bin"
    response = authorize_response(("quarantine_file",), path=target)
    assert response["response_contract"]["targets"] == {
        "path": str(target.resolve())
    }


def test_semantic_contract_is_accepted_by_combat_consumer() -> None:
    from angerona.modules.adversary_combat import AdversaryCombat

    process = process_response(42, 10.0)
    process_event = Event(
        "semantic",
        "confirmed process threat",
        Severity.CRITICAL,
        details={"pid": 42, "process_create_time": 10.0, **process},
    )
    assert AdversaryCombat._response_actions(process_event) == frozenset({
        "suspend_process",
        "terminate_process",
        "activate_honeypots",
    })

    peer = authorize_response(("block_remote_ip",), remote_ips=("1.1.1.1",))
    peer_event = Event(
        "semantic",
        "corroborated peer",
        Severity.HIGH,
        details={"remote_ip": "1.1.1.1", **peer},
    )
    assert AdversaryCombat._response_actions(peer_event) == frozenset({
        "block_remote_ip"
    })


def test_lsass_guard_authorizes_one_exact_process(monkeypatch) -> None:
    from angerona.modules import lsass_guard

    process = SimpleNamespace(info={
        "pid": 4201,
        "name": "procdump64.exe",
        "exe": r"C:\Tools\procdump64.exe",
        "cmdline": ["procdump64.exe", "-ma", "lsass.exe", "out.dmp"],
        "create_time": 1234.5,
    })
    monkeypatch.setattr(
        lsass_guard,
        "psutil",
        SimpleNamespace(process_iter=lambda _attrs: [process]),
    )
    bus = EventBus()
    module = lsass_guard.LsassGuardModule()
    module.bind(bus)
    module.sleep = lambda _seconds: module.stop()
    module.run()

    details = _latest(bus).details
    assert details["active_attack"] is True
    assert details["response_contract"]["targets"] == {
        "pid": 4201,
        "process_create_time": 1234.5,
        "deception": "Smart Deception",
    }


def test_lsass_text_in_unrelated_process_is_alert_only(monkeypatch) -> None:
    from angerona.modules import lsass_guard

    process = SimpleNamespace(info={
        "pid": 4251,
        "name": "python.exe",
        "exe": r"C:\Python\python.exe",
        "cmdline": ["python.exe", "-c", "print('mimikatz lsass.dmp')"],
        "create_time": 1234.6,
    })
    monkeypatch.setattr(
        lsass_guard,
        "psutil",
        SimpleNamespace(process_iter=lambda _attrs: [process]),
    )
    bus = EventBus()
    module = lsass_guard.LsassGuardModule()
    module.bind(bus)
    module.sleep = lambda _seconds: module.stop()
    module.run()

    details = _latest(bus).details
    assert details["detector_policy"] == "semantic-indicator-alert-only"
    assert "response_contract" not in details


def test_procdump_output_named_lsass_does_not_authorize_response(monkeypatch) -> None:
    from angerona.modules import lsass_guard

    process = SimpleNamespace(info={
        "pid": 4253,
        "name": "procdump64.exe",
        "exe": r"C:\Tools\procdump64.exe",
        "cmdline": [
            "procdump64.exe", "-ma", "notepad.exe", r"C:\reports\lsass.exe",
        ],
        "create_time": 1234.7,
    })
    monkeypatch.setattr(
        lsass_guard,
        "psutil",
        SimpleNamespace(process_iter=lambda _attrs: [process]),
    )
    bus = EventBus()
    module = lsass_guard.LsassGuardModule()
    module.bind(bus)
    module.sleep = lambda _seconds: module.stop()
    module.run()

    details = _latest(bus).details
    assert details["detector_policy"] == "semantic-indicator-alert-only"
    assert "response_contract" not in details


def test_rundll32_requires_canonical_comsvcs_export_role(monkeypatch) -> None:
    from angerona.modules import lsass_guard

    class Process:
        def __init__(self, _pid):
            pass

        @staticmethod
        def name() -> str:
            return "lsass.exe"

    monkeypatch.setattr(
        lsass_guard,
        "psutil",
        SimpleNamespace(Process=Process),
    )
    system_root = r"C:\Windows\System32"
    assert lsass_guard._lsass_response_scope(
        "rundll32.exe",
        system_root + r"\rundll32.exe",
        [
            "rundll32.exe",
            r"C:\notes\comsvcs.txt",
            r"C:\notes\minidump.txt",
            "500",
        ],
    ) is None


def test_shadowcopy_guard_authorizes_exact_tamper_process(monkeypatch) -> None:
    from angerona.modules import shadowcopy_guard

    process = SimpleNamespace(info={
        "pid": 4202,
        "name": "vssadmin.exe",
        "exe": r"C:\Windows\System32\vssadmin.exe",
        "cmdline": ["vssadmin.exe", "delete", "shadows", "/all"],
        "create_time": 2345.6,
    })

    class Process:
        def __init__(self, _pid):
            pass

        @staticmethod
        def ppid() -> int:
            return 4000

    monkeypatch.setattr(
        shadowcopy_guard,
        "psutil",
        SimpleNamespace(process_iter=lambda _attrs: [process], Process=Process),
    )
    monkeypatch.setattr(
        shadowcopy_guard,
        "_trusted_system_utility",
        lambda _name, _exe: "vssadmin.exe",
    )
    bus = EventBus()
    module = shadowcopy_guard.ShadowCopyGuardModule()
    module.bind(bus)
    module.sleep = lambda _seconds: module.stop()
    module.run()

    details = _latest(bus).details
    assert details["active_attack"] is True
    assert details["response_contract"]["targets"] == {
        "pid": 4202,
        "process_create_time": 2345.6,
        "host": "local",
        "deception": "Smart Deception",
    }


def test_shadowcopy_text_in_command_shell_is_alert_only(monkeypatch) -> None:
    from angerona.modules import shadowcopy_guard

    process = SimpleNamespace(info={
        "pid": 4252,
        "name": "cmd.exe",
        "exe": r"C:\Windows\System32\cmd.exe",
        "cmdline": ["cmd.exe", "/c", "echo vssadmin delete shadows /all"],
        "create_time": 2345.7,
    })

    class Process:
        def __init__(self, _pid):
            pass

        @staticmethod
        def ppid() -> int:
            return 4000

    monkeypatch.setattr(
        shadowcopy_guard,
        "psutil",
        SimpleNamespace(process_iter=lambda _attrs: [process], Process=Process),
    )
    bus = EventBus()
    module = shadowcopy_guard.ShadowCopyGuardModule()
    module.bind(bus)
    module.sleep = lambda _seconds: module.stop()
    module.run()

    details = _latest(bus).details
    assert details["detector_policy"] == "semantic-indicator-alert-only"
    assert "response_contract" not in details


def test_vssadmin_list_argument_containing_delete_is_alert_only(monkeypatch) -> None:
    from angerona.modules import shadowcopy_guard

    process = SimpleNamespace(info={
        "pid": 4254,
        "name": "vssadmin.exe",
        "exe": r"C:\Windows\System32\vssadmin.exe",
        "cmdline": ["vssadmin.exe", "list", "shadows", r"/for=C:\delete"],
        "create_time": 2345.8,
    })

    class Process:
        def __init__(self, _pid):
            pass

        @staticmethod
        def ppid() -> int:
            return 4000

    monkeypatch.setattr(
        shadowcopy_guard,
        "psutil",
        SimpleNamespace(process_iter=lambda _attrs: [process], Process=Process),
    )
    monkeypatch.setattr(
        shadowcopy_guard,
        "_trusted_system_utility",
        lambda _name, _exe: "vssadmin.exe",
    )
    bus = EventBus()
    module = shadowcopy_guard.ShadowCopyGuardModule()
    module.bind(bus)
    module.sleep = lambda _seconds: module.stop()
    module.run()

    details = _latest(bus).details
    assert details["detector_policy"] == "semantic-indicator-alert-only"
    assert "response_contract" not in details


def test_recovery_response_parser_requires_command_roles() -> None:
    from angerona.modules.shadowcopy_guard import _recovery_argv_is_destructive

    assert _recovery_argv_is_destructive(
        "bcdedit.exe",
        ["bcdedit.exe", "/set", "{default}", "recoveryenabled", "no"],
    ) is True
    assert _recovery_argv_is_destructive(
        "bcdedit.exe",
        ["bcdedit.exe", "/enum", "all", "recoveryenabled", "no"],
    ) is False
    assert _recovery_argv_is_destructive(
        "powershell.exe",
        ["powershell.exe", "-command", "write-host disable-computerrestore"],
    ) is False


def test_beacon_detector_binds_process_and_literal_peer(monkeypatch) -> None:
    from angerona.modules import beacon_detector

    state = {"now": 1000.0, "present": True}
    row = {
        "pid": 4203,
        "status": "ESTABLISHED",
        "raddr": "8.8.8.8:443",
    }

    class Process:
        def __init__(self, _pid):
            pass

        @staticmethod
        def name() -> str:
            return "payload.exe"

        @staticmethod
        def create_time() -> float:
            return 3456.7

    monkeypatch.setattr(
        beacon_detector, "list_connections",
        lambda: [row] if state["present"] else [],
    )
    monkeypatch.setattr(beacon_detector.psutil, "Process", Process)
    monkeypatch.setattr(beacon_detector, "is_ip_flagged", lambda _ip: True)
    monkeypatch.setattr(beacon_detector.time, "time", lambda: state["now"])
    bus = EventBus()
    module = beacon_detector.BeaconDetectorModule()
    module.bind(bus)

    for callback in range(4):
        state.update(now=1000.0 + callback * 60.0, present=True)
        module._poll_once()
        state["present"] = False
        module._poll_once()

    details = _latest(bus).details
    assert details["active_attack"] is True
    assert details["response_contract"]["targets"] == {
        "pid": 4203,
        "process_create_time": 3456.7,
        "remote_ips": ["8.8.8.8"],
        "deception": "Smart Deception",
    }


def test_beacon_cadence_without_threat_intel_is_alert_only(monkeypatch) -> None:
    from angerona.modules import beacon_detector

    state = {"now": 1000.0, "present": True}

    class Process:
        def __init__(self, _pid):
            pass

        @staticmethod
        def name() -> str:
            return "updater.exe"

        @staticmethod
        def create_time() -> float:
            return 3456.8

    monkeypatch.setattr(beacon_detector.psutil, "Process", Process)
    monkeypatch.setattr(beacon_detector, "is_ip_flagged", lambda _ip: False)
    monkeypatch.setattr(beacon_detector.time, "time", lambda: state["now"])
    monkeypatch.setattr(
        beacon_detector,
        "list_connections",
        lambda: [{
            "pid": 4204,
            "status": "ESTABLISHED",
            "raddr": "8.8.8.8:443",
        }] if state["present"] else [],
    )
    bus = EventBus()
    module = beacon_detector.BeaconDetectorModule()
    module.bind(bus)
    for callback in range(4):
        state.update(now=1000.0 + callback * 60.0, present=True)
        module._poll_once()
        state["present"] = False
        module._poll_once()

    details = _latest(bus).details
    assert details["detector_policy"] == "cadence-indicator-alert-only"
    assert "response_contract" not in details


def test_beacon_cadence_never_combines_same_name_processes(monkeypatch) -> None:
    from angerona.modules import beacon_detector

    state = {"now": 1000.0, "pid": 4301, "present": True}

    class Process:
        def __init__(self, pid):
            self.pid = pid

        @staticmethod
        def name() -> str:
            return "worker.exe"

        def create_time(self) -> float:
            return 100.0 + self.pid

    monkeypatch.setattr(beacon_detector.psutil, "Process", Process)
    monkeypatch.setattr(beacon_detector.time, "time", lambda: state["now"])
    monkeypatch.setattr(
        beacon_detector,
        "list_connections",
        lambda: [{
            "pid": state["pid"],
            "status": "ESTABLISHED",
            "raddr": "8.8.4.4:443",
        }] if state["present"] else [],
    )
    bus = EventBus()
    module = beacon_detector.BeaconDetectorModule()
    module.bind(bus)

    # Four combined callbacks would cross the threshold in the vulnerable
    # name/IP implementation, but each exact process has only two.
    for index, pid in enumerate((4301, 4302, 4301, 4302)):
        state.update(now=1000.0 + index * 60.0, pid=pid, present=True)
        module._poll_once()
        state["present"] = False
        module._poll_once()
    assert not bus.recent(10)

    # Two more callbacks for PID 4301 complete only that process's cadence.
    for index in (4, 6):
        state.update(now=1000.0 + index * 60.0, pid=4301, present=True)
        module._poll_once()
        state["present"] = False
        module._poll_once()
    assert _latest(bus).details["pid"] == 4301


def test_memory_injection_indicator_is_alert_only(monkeypatch) -> None:
    from angerona.modules.mem_inject_scanner import (
        MemInjectScannerModule,
        PAGE_EXECUTE_READWRITE,
    )

    module = MemInjectScannerModule()
    bus = EventBus()
    module.bind(bus)
    monkeypatch.setattr(module, "_enrich_process", lambda _pid: {
        "exe": r"C:\Users\analyst\payload.exe",
        "process_create_time": 4567.8,
    })
    module._alert(4204, "payload.exe", [(0x1000, 8192, PAGE_EXECUTE_READWRITE)])

    details = _latest(bus).details
    assert details["active_attack"] is True
    assert details["process_create_time"] == 4567.8
    assert details["detector_policy"] == "rwx-memory-indicator-alert-only"
    assert "response_contract" not in details


def test_ransomware_storm_authorizes_maximum_isolation_and_deception(tmp_path) -> None:
    from angerona.modules.ransomware_heuristics import (
        RENAME_THRESHOLD,
        RansomwareHeuristicsModule,
    )

    module = RansomwareHeuristicsModule()
    bus = EventBus()
    module.bind(bus)
    watched = str(tmp_path.resolve())
    module._rename_times.extend([(1000.0, watched)] * RENAME_THRESHOLD)
    module._flagged[str(tmp_path / "report.docx.locked")] = 1000.0
    module._check_rename_rate(1000.0)

    details = _latest(bus).details
    assert details["active_attack"] is True
    assert details["response_contract"] == {
        "version": 1,
        "actions": ["isolate_host", "activate_honeypots"],
        "targets": {"host": "local", "deception": "Smart Deception"},
    }


def test_unpaired_file_churn_cannot_create_ransomware_isolation_authority(tmp_path) -> None:
    from angerona.modules.ransomware_heuristics import (
        RENAME_THRESHOLD,
        RansomwareHeuristicsModule,
        _rename_pair_count,
    )

    assert _rename_pair_count(
        {f"old-{index}.txt" for index in range(RENAME_THRESHOLD)},
        {f"unrelated-{index}.bin" for index in range(RENAME_THRESHOLD)},
    ) == 0

    module = RansomwareHeuristicsModule()
    bus = EventBus()
    module.bind(bus)
    module._rename_times.extend([
        (1000.0, str(tmp_path.resolve()))
    ] * RENAME_THRESHOLD)
    module._check_rename_rate(1000.0)
    details = _latest(bus).details
    assert details["entropy_corroborated"] is False
    assert details["response_contract"] == {
        "version": 1,
        "actions": ["activate_honeypots"],
        "targets": {"deception": "Smart Deception"},
    }


def test_ransomware_never_cross_correlates_watched_directories(tmp_path) -> None:
    from angerona.modules.ransomware_heuristics import (
        RENAME_THRESHOLD,
        RansomwareHeuristicsModule,
    )

    entropy_dir = tmp_path / "entropy"
    rename_dir = tmp_path / "renames"
    entropy_dir.mkdir()
    rename_dir.mkdir()
    module = RansomwareHeuristicsModule()
    bus = EventBus()
    module.bind(bus)
    module._flagged[str(entropy_dir / "encrypted.bin")] = 1000.0
    module._rename_times.extend([
        (1000.0, str(rename_dir.resolve()))
    ] * RENAME_THRESHOLD)
    module._check_rename_rate(1000.0)

    details = _latest(bus).details
    assert details["entropy_corroborated"] is False
    assert details["response_contract"]["actions"] == ["activate_honeypots"]


def test_evidence_lattice_authorizes_only_exact_ip(monkeypatch) -> None:
    from angerona.modules.evidence_lattice import EvidenceFinding, EvidenceLatticeModule

    module = EvidenceLatticeModule()
    bus = EventBus()
    module.bind(bus)
    monkeypatch.setattr(module.lattice, "ingest", lambda _event: EvidenceFinding(
        entity_type="ip",
        entity="1.1.1.1",
        modules=("Memory Scanner", "Network Monitor", "Process Monitor"),
        domains=("memory", "network", "process"),
        confidence=95,
        signal_count=3,
    ))
    module._on_event(Event("source", "weak", Severity.MEDIUM))

    details = _latest(bus).details
    assert details["remote_ip"] == "1.1.1.1"
    assert details["response_contract"] == {
        "version": 1,
        "actions": ["block_remote_ip"],
        "targets": {"remote_ips": ["1.1.1.1"]},
    }


def test_evidence_lattice_never_rebinds_pid_by_live_lookup() -> None:
    from angerona.modules.evidence_lattice import EvidenceLatticeModule

    module = EvidenceLatticeModule()
    bus = EventBus()
    module.bind(bus)
    for name in ("Process Monitor", "Memory Injection Scanner", "Network Monitor"):
        module._on_event(Event(
            name,
            "weak corroborating signal",
            Severity.MEDIUM,
            details={"pid": 4210},
        ))

    details = _latest(bus).details
    assert details["entity"] == "4210"
    assert details["process_create_time"] is None
    assert "response_contract" not in details


def test_evidence_lattice_requires_same_process_birth_across_signals() -> None:
    from angerona.modules.evidence_lattice import EvidenceLatticeModule

    module = EvidenceLatticeModule()
    bus = EventBus()
    module.bind(bus)
    for name in ("Process Monitor", "Memory Injection Scanner", "Network Monitor"):
        module._on_event(Event(
            name,
            "weak corroborating signal",
            Severity.MEDIUM,
            details={"pid": 4211, "process_create_time": 5678.9},
        ))

    details = _latest(bus).details
    assert details["response_contract"]["targets"] == {
        "pid": 4211,
        "process_create_time": 5678.9,
        "deception": "Smart Deception",
    }
