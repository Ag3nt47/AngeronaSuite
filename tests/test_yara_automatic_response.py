from __future__ import annotations

import copy
import hashlib
import os
import threading
import time
import zipfile
from collections import deque
from dataclasses import replace
from pathlib import Path
from types import MappingProxyType, SimpleNamespace

import psutil
import pytest
import yara_x

from angerona.core import breach_state
from angerona.core.config import Config
from angerona.core.eventbus import BusAuthority, EventBus
from angerona.core.module_base import BaseModule
from angerona.core.module_contract import build_capability_contract
from angerona.core.module_manager import ModuleManager
from angerona.core.practice_scope import register_artifact, unregister_run
from angerona.core.storage import FlightRecorder
from angerona.modules import process_monitor, purple_guard, yara_scanner
from angerona.modules.adversary_combat import AdversaryCombat
from angerona.modules.process_monitor import ProcessMonitorModule
from angerona.modules.yara_scanner import YaraScannerModule
from angerona.telemetry.sensors import ProcessSnapshot


MARKER = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE :: inert local drill"


def _wait_for(predicate, *, description, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(0.01)
    raise AssertionError(description)


@pytest.fixture
def controlled_runtime(tmp_path, monkeypatch, request):
    """Real producers and issuer custody; ambient host mutation stays held."""
    root = tmp_path / "state"
    root.mkdir()
    idle_root = tmp_path / "empty-watch-root"
    idle_root.mkdir()
    repository = next(parent for parent in Path(__file__).resolve().parents
                      if (parent / "rules.yar").is_file()
                      and (parent / "pyproject.toml").is_file())
    monkeypatch.setenv("ANGERONA_DATA", str(root))
    monkeypatch.setenv("ANGERONA_YARA_RULES", str(repository / "rules.yar"))
    monkeypatch.setenv("ANGERONA_ADVERSARY_COMBAT_ENABLED", "1")
    monkeypatch.setenv("ANGERONA_ADVERSARY_COMBAT_MODE", "maximum")
    monkeypatch.setattr(BusAuthority, "_key_path", staticmethod(lambda: root / "bus.key"))
    monkeypatch.setattr(breach_state, "protect_authority", lambda: (
        False, "Explicit Source Observe fixture; no installed host authority"))
    # These YARA cases own a file corpus. Keep ambient process churn out of
    # their input while the actual monitor and validation lease prove readiness.
    owner = psutil.Process(os.getpid())
    image = owner.exe()
    row = MappingProxyType(dict(pid=owner.pid, name=Path(image).name, exe=image,
                               create_time=owner.create_time(), ppid=None, username=None, cmdline=()))
    fresh_inventory_requested = threading.Event()

    def owned_process_snapshot(max_age=None):
        receipt = ProcessSnapshot((row,), time.time(), complete=True, enumerated=1, skipped=0)
        if max_age == 0.0:
            fresh_inventory_requested.set()
        return receipt

    monkeypatch.setattr(psutil, "pids", lambda: [owner.pid])
    monkeypatch.setattr(process_monitor, "process_snapshot", owned_process_snapshot)
    # Isolate actual traversal input, not native factories, scans or readiness.
    roots = {"current": (idle_root,)}
    monkeypatch.setattr(yara_scanner, "scan_roots", lambda: roots["current"])
    monkeypatch.setattr(yara_scanner, "data_dir", lambda: root)
    recorder = FlightRecorder(root / "flight-recorder.db")
    bus = EventBus(ring_size=4096)
    bus.arm(recorder.authority)
    bus.subscribe(recorder.record_bus, delivery_budget_ms=60_000)
    config = Config(
        data_dir=root, ugcap_enabled=False, adversary_combat_enabled=True,
        adversary_combat_mode="maximum", adversary_combat_min_severity="LOW",
        adversary_combat_quarantine_files=True, adversary_combat_block_network=False,
        adversary_combat_process_action="none", adversary_combat_isolate_host=False,
        adversary_combat_activate_honeypots=False,
    )
    manager = ModuleManager(bus, config, recorder=recorder)
    guard = purple_guard.PurpleGuard(root)
    process = ProcessMonitorModule()
    detector = YaraScannerModule()
    combat = AdversaryCombat(root)
    sources = (detector, guard, process)
    for module in (*sources, combat):
        module.bind(bus)
        module._angerona_origin = "builtin"
        module._angerona_trust = "release"
        module._angerona_contract = build_capability_contract(
            module, capability_id="angerona.builtin." + type(module).__module__.rsplit(".", 1)[-1],
            origin="builtin", trust="release", publisher="Angerona")
        manager.modules[module.name] = module
        binder = getattr(module, "bind_manager", None)
        if callable(binder):
            binder(manager)
        binder = getattr(module, "bind_recorder", None)
        if callable(binder):
            binder(recorder)
    events = deque(maxlen=512)
    events_lock = threading.Lock()

    def capture(event):
        if event.module in {detector.name, combat.name}:
            with events_lock:
                events.append(event)

    names = {
        "test_real_scan_drives_signed_containment_and_undo": "yara-native-proof",
        "test_live_worker_responds_automatically_without_ollama_or_manual_dispatch": "yara-automatic-worker",
        "test_registered_driver_probe_uses_actual_bundled_signature": "driver-probe",
    }
    run_id = names.get(request.node.originalname, "yara-control-" + hashlib.sha256(
        request.node.nodeid.encode("utf-8")).hexdigest()[:16])
    ctx = SimpleNamespace(
        root=root, target=guard.sandbox, detector=detector, guard=guard,
        process=process, combat=combat, config=config, manager=manager,
        bus=bus, recorder=recorder, lease=None, run_id=run_id,
        source_threads=(), sources_retired=False, controls={},
    )

    def captured():
        with events_lock:
            return tuple(events)

    def drain():
        _wait_for(lambda: combat.response_snapshot()["queue_pending"] == 0,
                  description="owned Combat queue did not drain")

    def create_control(kind, *, step_id="native-signature"):
        declaration = purple_guard.RedTeamValidationLease.create_yara_control(
            ctx.lease, run_id=run_id, step_id=step_id,
            scanner_enrollment=detector.control_enrollment(), control_kind=kind)
        path = Path(declaration["path"])
        assert path.parent == ctx.target and path.name.startswith("_angerona_yara_control_")
        original = path.read_bytes()
        assert hashlib.sha256(original).hexdigest() == declaration["identity"]["sha256"]
        ctx.controls[str(path)] = (declaration, original)
        return declaration, path, original

    def begin_scan():
        roots["current"] = (ctx.target,)

    def detection(path):
        return next((event for event in captured()
                     if event.module == detector.name
                     and event.details.get("artifact_path") == str(path)
                     and event.details.get("detector_verdict") == "positive"), None)

    def response(event):
        return next((row for row in captured()
                     if row.module == combat.name and bus.verify(row)
                     and row.details.get("trigger_module") == event.module
                     and row.details.get("trigger_ts") == event.ts
                     and row.details.get("trigger_event_digest") == event.hmac_sig
                     and row.details.get("postcondition_verified") is True), None)

    def stop_sources():
        roots["current"] = (idle_root,)
        for module in sources:
            module.stop()
        for thread in ctx.source_threads:
            thread.join(10)
            assert not thread.is_alive(), "owned source worker did not retire"
        if ctx.lease is not None:
            purple_guard.RedTeamValidationLease.release(ctx.lease)
        ctx.sources_retired = True
        drain()

    def undo_exact(action_id):
        stop_sources()
        assert combat.status == "running" and not combat.stopping
        action = next(row for row in combat.list_actions() if row["action_id"] == action_id)
        assert action["action"] == "quarantine_file" and action["status"] == "applied"
        declaration, original = ctx.controls[action["target"]]
        assert action["target"] == declaration["path"]
        assert action["details"]["sha256"] == hashlib.sha256(original).hexdigest()
        owner = threading.get_ident()

        def this_manual_call_only():
            accepted = (threading.get_ident() == owner and ctx.sources_retired
                        and all(not thread.is_alive() for thread in ctx.source_threads)
                        and combat.response_snapshot()["queue_pending"] == 0)
            return accepted, "Scoped installed-authority fixture for one exact owned Undo"

        # All producer threads are retired and the private bus is drained.
        # Other threads retain held host authority throughout this sync call.
        with monkeypatch.context() as patch:
            patch.setattr(breach_state, "protect_authority", this_manual_call_only)
            return combat.undo_action(action_id)

    ctx.captured = captured
    ctx.drain = drain
    ctx.create_control = create_control
    ctx.begin_scan = begin_scan
    ctx.detection = detection
    ctx.response = response
    ctx.stop_sources = stop_sources
    ctx.undo_exact = undo_exact
    try:
        detector.start()
        combat.start()
        _wait_for(lambda: BaseModule.operational_snapshot(detector).get("first_cycle_complete"),
                  description="real YARA worker did not complete its initial cycle")
        ctx.lease = purple_guard.acquire_redteam_validation_lease(
            manager, bus, recorder, root, ctx.target, timeout=8)
        assert fresh_inventory_requested.is_set()
        ctx.source_threads = tuple(module._thread for module in sources)
        purple_guard.RedTeamValidationLease.consume_for_run(
            ctx.lease, run_id=run_id, target=ctx.target, data_root=root)
        _wait_for(detector.control_enrollment,
                  description="real YARA owner did not establish control enrollment")
        for module in sources:
            state = BaseModule.operational_snapshot(module)
            assert state["status"] == "running" and state["thread_alive"] is True
            assert state["first_cycle_complete"] is True
        _wait_for(lambda: combat.response_snapshot()["canary_ready"],
                  description="real Combat canary worker did not initialize")
        assert combat.response_snapshot()["ready"] is False
        assert combat.response_snapshot()["host_authority_verified"] is False
        # Register after Combat's admission subscriber so observing an event
        # also proves its queue admission turn has already completed.
        bus.subscribe(capture)
        yield ctx
    finally:
        try:
            # Snapshot exact thread objects even when setup failed partway.
            ctx.source_threads = tuple(module._thread for module in sources
                                       if module._thread is not None)
            stop_sources()
        finally:
            combat_thread = combat._thread
            combat.stop()
            if combat_thread is not None:
                combat_thread.join(10)
                assert not combat_thread.is_alive(), "owned Combat worker did not retire"
            bus.unsubscribe(capture)
            bus.unsubscribe(recorder.record_bus)
            recorder.close()
            unregister_run(run_id)


def _setup(tmp_path):
    bus = EventBus()
    bus.arm(BusAuthority(b"s" * 32))
    detector = YaraScannerModule()
    detector.bind(bus)
    scanner = detector._make_scanner(yara_x.compile(
        'rule EICAR_Test_File { strings: $a = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" condition: $a }'
    ))
    combat = AdversaryCombat(tmp_path / "state")
    combat.bind(bus)
    config = SimpleNamespace(
        data_dir=tmp_path / "state", adversary_combat_enabled=True,
        adversary_combat_mode="maximum", adversary_combat_min_severity="LOW",
        adversary_combat_quarantine_files=True, adversary_combat_block_network=False,
        adversary_combat_process_action="none", adversary_combat_isolate_host=False,
        adversary_combat_activate_honeypots=False,
    )
    combat.bind_manager(SimpleNamespace(
        bus=bus, config=config, modules={combat.name: combat},
    ))
    return bus, detector, scanner, combat


def _windows_cache_tokens(monkeypatch, usn):
    """Exercise Windows cache policy without replacing real descriptors or YARA."""
    from angerona.modules import yara_scanner
    from angerona.modules.file_integrity import FileIntegrityModule

    # Keep pathlib's and the rest of the process's actual OS module unchanged.
    monkeypatch.setattr(yara_scanner, "os", SimpleNamespace(**dict(vars(os), name="nt")))
    monkeypatch.setattr(FileIntegrityModule, "_handle_change_token", staticmethod(lambda _fd: 123))
    monkeypatch.setattr(FileIntegrityModule, "_handle_usn", staticmethod(usn))


class _CountedNativeScanner:
    def __init__(self, scanner, after_scan=None):
        self._scanner = scanner
        self._after_scan = after_scan
        self.calls = 0

    def scan(self, content):
        self.calls += 1
        result = self._scanner.scan(content)
        if self._after_scan is not None:
            self._after_scan()
        return result


@pytest.mark.parametrize("archive", [False, True])
def test_real_scan_drives_signed_containment_and_undo(controlled_runtime, monkeypatch, archive):
    ctx = controlled_runtime
    bus, detector, combat = ctx.bus, ctx.detector, ctx.combat
    declaration, path, original = ctx.create_control("archive" if archive else "text")
    if not archive:
        assert original == MARKER
    else:
        assert declaration["archive_member"] == "../never-extracted.txt"
    started = time.time()
    ctx.begin_scan()
    event = _wait_for(lambda: ctx.detection(path), description="actual YARA control scan did not publish")
    assert bus.verify(event) and detector.verify_detection_event(event)
    assert event.details["observed_content_sha256"] == hashlib.sha256(original).hexdigest()
    assert event.details["rule"] == declaration["rule"]
    assert event.details["scan_complete"] is True
    response = _wait_for(lambda: ctx.response(event), description="actual worker did not commit quarantine")
    assert not path.exists()
    assert response.details["postcondition_verified"] is True
    assert response.details["actions"] == ["quarantine_file"]
    assert combat.response_snapshot()["host_authority_verified"] is False
    from angerona.shark.aar_report import evaluate, _live_combat_action_verifier
    history = {"run_id": ctx.run_id, "kind": "shark", "steps": [{
        "stage": "Initial Access", "ts_start": started, "ts_end": time.time(),
        "technique": "signature probe", "description": "native inert file scan",
        "plan_step_id": declaration["step_id"],
        "ok": True, "artifact_paths": [str(path)],
    }]}
    response_events = ctx.captured()

    def verdict_for_current_journal():
        return evaluate(
            history, response_events, require_authenticated=True,
            event_verifier=bus.verify,
            native_verifier=lambda row, _step: detector.verify_detection_event(row),
            combat_verifier=_live_combat_action_verifier(
                combat._manager, bus, combat.data_root.resolve(), red_team=False,
            ),
        )[0]

    verdict = verdict_for_current_journal()
    assert verdict.native_catch is not None and verdict.target_containment_verified
    assert verdict.native_catch.module == detector.name
    assert verdict.native_catch.hmac_sig == event.hmac_sig
    action = next(row for row in combat.list_actions() if row["target"] == str(path))
    if archive:
        append_phase = combat._append_undo_phase

        def fail_terminal_undo(phase, *args, **kwargs):
            if phase == "undo_commit":
                raise OSError("simulated terminal journal failure")
            return append_phase(phase, *args, **kwargs)

        monkeypatch.setattr(combat, "_append_undo_phase", fail_terminal_undo)
        assert ctx.undo_exact(action["action_id"])["ok"] is False
    else:
        assert ctx.undo_exact(action["action_id"])["ok"] is True
    assert path.read_bytes() == original
    assert not verdict_for_current_journal().target_containment_verified
    assert not (ctx.target.parent / "never-extracted.txt").exists()


def test_changed_target_is_not_quarantined_on_stale_content(tmp_path):
    bus, detector, scanner, combat = _setup(tmp_path)
    path = tmp_path / "probe.txt"
    path.write_bytes(MARKER)
    register_artifact(path, "yara-stale-proof", kind="shark")
    try:
        assert detector._scan_file(scanner, path) == "scanned", detector.last_error
        event = bus.recent(1)[0]
        path.write_bytes(b"replacement document")
        combat._handle(event)
        assert path.read_bytes() == b"replacement document"
        assert not combat.list_actions()
    finally:
        unregister_run("yara-stale-proof")


def test_live_worker_responds_automatically_without_ollama_or_manual_dispatch(controlled_runtime, monkeypatch):
    ctx = controlled_runtime
    bus, detector, combat = ctx.bus, ctx.detector, ctx.combat
    commit_entered = threading.Event()
    release_commit = threading.Event()
    commit = combat._commit_after_mutation

    def held_commit(action, **kwargs):
        commit_entered.set()
        assert release_commit.wait(10), "test did not release the durable commit"
        return commit(action, **kwargs)

    monkeypatch.setattr(combat, "_commit_after_mutation", held_commit)

    def verified_response():
        return any(
            event.module == combat.name and bus.verify(event)
            and event.details.get("postcondition_verified") is True
            and "quarantine_file" in event.details.get("actions", [])
            for event in ctx.captured()
        )

    _declaration, path, original = ctx.create_control("text")
    assert original == MARKER
    try:
        assert combat.response_snapshot()["canary_ready"], combat.response_snapshot()
        assert combat.response_snapshot()["ready"] is False
        assert combat.response_snapshot()["host_authority_verified"] is False
        ctx.begin_scan()
        event = _wait_for(lambda: ctx.detection(path), description="real automatic YARA scan did not publish")
        assert bus.verify(event) and detector.verify_detection_event(event)
        assert event.details["observed_content_sha256"] == hashlib.sha256(MARKER).hexdigest()
        assert commit_entered.wait(10), combat.response_snapshot()
        # No _handle/_submit call: the actual subscribed worker owns this action.
        assert not path.exists(), combat.response_snapshot()
        # Moving the file precedes the durable receipt. Do not race that receipt
        # or mistake an in-flight journal intent for the completed response.
        assert not verified_response()
        release_commit.set()
        deadline = time.monotonic() + 10
        while not verified_response() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert verified_response(), combat.response_snapshot()
        action = combat.list_actions()[0]
        assert action["status"] == "applied"
        assert action["details"]["postcondition_verified"] is True
        assert ctx.undo_exact(action["action_id"])["ok"]
        assert path.read_bytes() == MARKER
    finally:
        release_commit.set()


def test_keyword_in_document_is_detected_without_destructive_authority(tmp_path):
    bus, detector, scanner, _combat = _setup(tmp_path)
    path = tmp_path / "security-notes.txt"
    path.write_bytes(MARKER)
    assert detector._scan_file(scanner, path) == "scanned", detector.last_error
    assert bus.recent(1)[0].details["response_authorized"] is False


def test_bus_resigning_does_not_forge_native_producer_receipt(tmp_path):
    bus, detector, scanner, _combat = _setup(tmp_path)
    path = tmp_path / "sample.txt"
    path.write_bytes(MARKER)
    assert detector._scan_file(scanner, path) == "scanned", detector.last_error
    real = bus.recent(1)[0]
    forged = replace(real, details=copy.deepcopy(real.details))
    forged.details["path"] = str(tmp_path / "other.txt")
    bus.publish(forged)
    assert bus.verify(bus.recent(1)[0])
    assert not detector.verify_detection_event(bus.recent(1)[0])
    assert detector.verify_detection_event(real)


def test_unchanged_file_avoids_repeat_content_reads_and_rules_invalidate_cache(tmp_path, monkeypatch):
    _bus, detector, scanner, _combat = _setup(tmp_path)
    usn = [101]
    _windows_cache_tokens(monkeypatch, lambda _fd: usn[0])
    path = tmp_path / "document.txt"
    path.write_bytes(b"ordinary text")
    class Counter:
        calls = 0
        def scan(self, content):
            self.calls += 1
            return scanner.scan(content)
    counted = Counter()
    assert detector._scan_file(counted, path) == "scanned", detector.last_error
    assert detector._scan_file(counted, path) == "scanned", detector.last_error
    assert counted.calls == 1
    other = Counter()
    assert detector._scan_file(other, path) == "scanned", detector.last_error
    assert other.calls == 1
    path.write_bytes(b"changed text")
    usn[0] = 102
    assert detector._scan_file(counted, path) == "scanned", detector.last_error
    assert counted.calls == 2


def test_restoring_mtime_cannot_hide_new_content_from_scan_cache(tmp_path):
    bus, detector, scanner, _combat = _setup(tmp_path)
    path = tmp_path / "document.txt"
    path.write_bytes(b"x" * len(MARKER))
    prior = path.stat()
    assert detector._scan_file(scanner, path) == "scanned"
    path.write_bytes(MARKER)
    os.utime(path, ns=(prior.st_atime_ns, prior.st_mtime_ns))
    assert detector._scan_file(scanner, path) == "scanned", detector.last_error
    assert detector.verify_detection_event(bus.recent(1)[0])


def test_advancing_usn_rescans_restored_mtime_with_constant_change_time(tmp_path, monkeypatch):
    bus, detector, scanner, _combat = _setup(tmp_path)
    usn = [101]
    _windows_cache_tokens(monkeypatch, lambda _fd: usn[0])
    counted = _CountedNativeScanner(scanner)
    path = tmp_path / "constant-change-time.txt"
    path.write_bytes(b"x" * len(MARKER))
    prior = path.stat()

    assert detector._scan_file(counted, path) == "scanned", detector.last_error
    assert counted.calls == 1 and not bus.recent(10)
    assert detector._scan_cache
    path.write_bytes(MARKER)
    os.utime(path, ns=(prior.st_atime_ns, prior.st_mtime_ns))
    usn[0] = 102

    assert detector._scan_file(counted, path) == "scanned", detector.last_error
    assert counted.calls == 2
    events = bus.recent(10)
    assert len(events) == 1
    event = events[0]
    assert bus.verify(event) and detector.verify_detection_event(event)
    assert event.details["observed_content_sha256"] == hashlib.sha256(MARKER).hexdigest()
    assert event.details["rule"] == "EICAR_Test_File"
    assert event.details["scan_complete"] is True
    assert event.details["response_authorized"] is False


@pytest.mark.parametrize("unavailable", [None, 0, -1, True, "101", 101.0, 1 << 63])
def test_unavailable_usn_rescans_restored_mtime_without_cache(
    tmp_path, monkeypatch, unavailable,
):
    bus, detector, scanner, _combat = _setup(tmp_path)
    _windows_cache_tokens(monkeypatch, lambda _fd: unavailable)
    counted = _CountedNativeScanner(scanner)
    path = tmp_path / "unavailable-usn.txt"
    path.write_bytes(b"x" * len(MARKER))
    prior = path.stat()

    assert detector._scan_file(counted, path) == "scanned", detector.last_error
    assert counted.calls == 1 and not detector._scan_cache
    assert not bus.recent(10)
    path.write_bytes(MARKER)
    os.utime(path, ns=(prior.st_atime_ns, prior.st_mtime_ns))

    assert detector._scan_file(counted, path) == "scanned", detector.last_error
    assert counted.calls == 2 and not detector._scan_cache
    events = bus.recent(10)
    assert len(events) == 1
    event = events[0]
    assert bus.verify(event) and detector.verify_detection_event(event)
    assert event.details["observed_content_sha256"] == hashlib.sha256(MARKER).hexdigest()
    assert event.details["rule"] == "EICAR_Test_File"
    assert event.details["scan_complete"] is True
    assert event.details["response_authorized"] is False


def test_unavailable_usn_removes_a_previous_complete_cache_entry(tmp_path, monkeypatch):
    bus, detector, scanner, _combat = _setup(tmp_path)
    usn = [101]
    _windows_cache_tokens(monkeypatch, lambda _fd: usn[0])
    counted = _CountedNativeScanner(scanner)
    path = tmp_path / "lost-usn.txt"
    path.write_bytes(b"ordinary text")

    assert detector._scan_file(counted, path) == "scanned", detector.last_error
    assert counted.calls == 1 and detector._scan_cache
    usn[0] = None
    assert detector._scan_file(counted, path) == "scanned", detector.last_error
    assert counted.calls == 2 and not detector._scan_cache
    assert detector._scan_file(counted, path) == "scanned", detector.last_error
    assert counted.calls == 3 and not detector._scan_cache
    assert not bus.recent(10) and not detector._detection_receipts


@pytest.mark.parametrize("initial,final", [(101, 102), (101, None), (None, 101)])
def test_usn_instability_before_cache_reuse_refuses_scan(
    tmp_path, monkeypatch, initial, final,
):
    bus, detector, scanner, _combat = _setup(tmp_path)
    samples = iter((101, 101, 101, initial, final))
    _windows_cache_tokens(monkeypatch, lambda _fd: next(samples))
    counted = _CountedNativeScanner(scanner)
    path = tmp_path / "unstable-before-scan.txt"
    path.write_bytes(b"x" * len(MARKER))
    prior = path.stat()
    assert detector._scan_file(counted, path) == "scanned", detector.last_error
    assert counted.calls == 1 and detector._scan_cache
    path.write_bytes(MARKER)
    os.utime(path, ns=(prior.st_atime_ns, prior.st_mtime_ns))

    assert detector._scan_file(counted, path) == "failed"
    assert "changed before" in detector.last_error
    assert counted.calls == 1
    assert not bus.recent(10) and not detector._detection_receipts
    assert not detector._scan_cache


@pytest.mark.parametrize(
    "initial,final", [(101, 102), (101, None), (101, 0), (101, "bad"), (None, 101)],
)
def test_usn_instability_during_native_scan_refuses_receipt_and_cache(
    tmp_path, monkeypatch, initial, final,
):
    bus, detector, scanner, _combat = _setup(tmp_path)
    usn = [initial]
    _windows_cache_tokens(monkeypatch, lambda _fd: usn[0])
    counted = _CountedNativeScanner(scanner, lambda: usn.__setitem__(0, final))
    path = tmp_path / "unstable-during-scan.txt"
    path.write_bytes(MARKER)

    assert detector._scan_file(counted, path) == "failed"
    assert "changed during" in detector.last_error
    assert counted.calls == 1
    assert not bus.recent(10) and not detector._detection_receipts
    assert not detector._scan_cache


def test_registered_driver_probe_uses_actual_bundled_signature(controlled_runtime):
    ctx = controlled_runtime
    declaration, path, original = ctx.create_control("driver")
    assert original == b"ANGERONA-BYOVD-DRILL-BENIGN-MARKER :: inert never loaded"
    ctx.begin_scan()
    event = _wait_for(lambda: ctx.detection(path), description="actual bundled driver signature was not scanned")
    assert ctx.bus.verify(event) and ctx.detector.verify_detection_event(event)
    assert event.details["rule"] == declaration["rule"] == "Angerona_BYOVD_Probe"
    assert event.details["observed_content_sha256"] == hashlib.sha256(original).hexdigest()
    _wait_for(lambda: ctx.response(event), description="actual worker did not contain benign driver control")
    assert not path.exists()
    action = next(row for row in ctx.combat.list_actions() if row["target"] == str(path))
    assert ctx.undo_exact(action["action_id"])["ok"]
    assert path.read_bytes() == original


def test_archive_budget_failure_never_caches_complete_coverage(tmp_path, monkeypatch):
    _bus, detector, scanner, _combat = _setup(tmp_path)
    path = tmp_path / "large.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("one", b"abc")
        archive.writestr("two", b"def")
    monkeypatch.setattr("angerona.modules.yara_scanner.MAX_ARCHIVE_MEMBERS", 1)
    assert detector._scan_file(scanner, path) == "failed"
    assert not detector._scan_cache


def test_archive_coverage_failure_preserves_outer_signature(tmp_path, monkeypatch):
    bus, detector, scanner, _combat = _setup(tmp_path)
    path = tmp_path / "too-many.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr("marker", MARKER)
        archive.writestr("padding", b"x")
    monkeypatch.setattr("angerona.modules.yara_scanner.MAX_ARCHIVE_MEMBERS", 1)
    assert detector._scan_file(scanner, path) == "failed"
    assert detector.verify_detection_event(bus.recent(1)[0])
    assert bus.recent(1)[0].details["scan_complete"] is False
    assert not detector._scan_cache


def test_archive_preflight_rejects_many_members_before_zipfile_construction(tmp_path, monkeypatch):
    _bus, detector, scanner, _combat = _setup(tmp_path)
    path = tmp_path / "metadata.zip"
    with zipfile.ZipFile(path, "w") as archive:
        for index in range(129):
            archive.writestr(str(index), b"")
    def forbidden(*_args, **_kwargs):
        raise AssertionError("unbounded ZIP constructor reached")
    monkeypatch.setattr("angerona.modules.yara_scanner.zipfile.ZipFile", forbidden)
    assert detector._scan_file(scanner, path) == "failed"
    assert "inspection bounds" in detector.last_error


def test_symlink_and_hardlink_are_not_read(tmp_path):
    _bus, detector, scanner, _combat = _setup(tmp_path)
    original = tmp_path / "original.txt"
    original.write_bytes(MARKER)
    linked = tmp_path / "hardlink.txt"
    try:
        linked.hardlink_to(original)
    except OSError:
        pytest.skip("filesystem lacks hardlinks")
    assert detector._scan_file(scanner, linked) == "reparse-skipped"
