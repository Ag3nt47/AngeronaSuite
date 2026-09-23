from __future__ import annotations

import copy
import hashlib
import os
import time
import zipfile
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
import yara_x

from angerona.core.eventbus import BusAuthority, EventBus
from angerona.core.practice_scope import register_artifact, unregister_run
from angerona.modules.adversary_combat import AdversaryCombat
from angerona.modules.yara_scanner import YaraScannerModule


MARKER = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE :: inert local drill"


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
    combat.bind_manager(SimpleNamespace(config=config, modules={combat.name: combat}))
    return bus, detector, scanner, combat


@pytest.mark.parametrize("archive", [False, True])
def test_real_scan_drives_signed_containment_and_undo(tmp_path, archive):
    bus, detector, scanner, combat = _setup(tmp_path)
    path = tmp_path / ("probe.zip" if archive else "probe.txt")
    if archive:
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as output:
            output.writestr("../never-extracted.txt", MARKER)
    else:
        path.write_bytes(MARKER)
    original = path.read_bytes()
    register_artifact(path, "yara-native-proof", kind="shark")
    try:
        started = time.time()
        assert detector._scan_file(scanner, path) == "scanned", detector.last_error
        event = bus.recent(1)[0]
        assert bus.verify(event) and detector.verify_detection_event(event)
        assert event.details["observed_content_sha256"] == hashlib.sha256(original).hexdigest()
        combat._handle(event)
        assert not path.exists()
        response = bus.recent(1)[0]
        assert response.details["postcondition_verified"] is True
        assert response.details["actions"] == ["quarantine_file"]
        from angerona.shark.aar_report import evaluate
        history = {"run_id": "yara-native-proof", "kind": "shark", "steps": [{
            "stage": "Initial Access", "ts_start": started, "ts_end": time.time(),
            "technique": "signature probe", "description": "native inert file scan",
            "ok": True, "artifact_paths": [str(path)],
        }]}
        verdict = evaluate(history, bus.recent(50), require_authenticated=True,
                           event_verifier=bus.verify,
                           native_verifier=lambda row, _step: detector.verify_detection_event(row))[0]
        assert verdict.native_catch is not None and verdict.target_containment_verified
        action = combat.list_actions()[0]
        assert combat.undo_action(action["action_id"])["ok"] is True
        assert path.read_bytes() == original
        assert not (tmp_path.parent / "never-extracted.txt").exists()
    finally:
        unregister_run("yara-native-proof")


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


def test_live_worker_responds_automatically_without_ollama_or_manual_dispatch(tmp_path):
    bus, detector, scanner, combat = _setup(tmp_path)
    path = tmp_path / "automatic-probe.txt"
    path.write_bytes(MARKER)
    register_artifact(path, "yara-automatic-worker", kind="shark")
    combat.start()
    try:
        deadline = time.monotonic() + 10
        while not combat.response_snapshot()["ready"] and time.monotonic() < deadline:
            time.sleep(0.02)
        assert combat.response_snapshot()["ready"], combat.response_snapshot()
        assert detector._scan_file(scanner, path) == "scanned", detector.last_error
        while path.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        # No _handle/_submit call: the actual subscribed worker owns this action.
        assert not path.exists(), combat.response_snapshot()
        while not combat.list_actions() and time.monotonic() < deadline:
            time.sleep(0.02)
        action = combat.list_actions()[0]
        assert action["status"] == "applied"
        assert action["details"]["postcondition_verified"] is True
        assert combat.undo_action(action["action_id"])["ok"]
        assert path.read_bytes() == MARKER
    finally:
        combat.stop()
        unregister_run("yara-automatic-worker")


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


def test_unchanged_file_avoids_repeat_content_reads_and_rules_invalidate_cache(tmp_path):
    _bus, detector, scanner, _combat = _setup(tmp_path)
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


def test_registered_driver_probe_uses_actual_bundled_signature(tmp_path):
    bus, detector, _scanner, combat = _setup(tmp_path)
    scanner = detector._make_scanner(detector._compile_rules(Path(__file__).parents[1] / "rules.yar"))
    path = tmp_path / "inert-driver.sys"
    path.write_bytes(b"ANGERONA-BYOVD-DRILL-BENIGN-MARKER :: inert never loaded")
    register_artifact(path, "driver-probe", kind="shark")
    try:
        assert detector._scan_file(scanner, path) == "scanned", detector.last_error
        event = bus.recent(1)[0]
        assert event.details["rule"] == "Angerona_BYOVD_Probe"
        combat._handle(event)
        assert not path.exists()
        assert combat.undo_action(combat.list_actions()[0]["action_id"])["ok"]
    finally:
        unregister_run("driver-probe")


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
