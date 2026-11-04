from __future__ import annotations

from pathlib import Path

import pytest

from angerona.core.eventbus import BusAuthority, EventBus, Severity
from angerona.modules import deception


def _module(tmp_path: Path, monkeypatch) -> deception.DeceptionModule:
    monkeypatch.delenv("ANGERONA_USER_FOLDER_DECEPTION", raising=False)
    monkeypatch.setattr(deception, "_repo_root", lambda: tmp_path)
    module = deception.DeceptionModule()
    module.bind(EventBus())
    return module


def test_active_deception_reports_exact_mutation_delete_visibility(
    tmp_path: Path, monkeypatch
) -> None:
    module = _module(tmp_path, monkeypatch)
    module.stop()

    module.run()

    assert module.health == 70
    assert "mutation/deletion visibility active" in module.health_note
    evidence = module.health_evidence
    assert evidence is not None
    assert "read telemetry is unavailable" in str(evidence["reason"])
    planted = next(
        event
        for event in module._bus.recent(20)
        if event.details.get("coverage") == "file-mutation-and-deletion"
    )
    assert planted.details["read_visibility"] is False
    assert planted.details["evidence_path"] == str(module._base)
    assert "audited reads are not claimed" in planted.message


def test_plain_file_read_is_not_misreported_as_a_canary_detection(
    tmp_path: Path, monkeypatch
) -> None:
    module = _module(tmp_path, monkeypatch)
    module._plant()
    path = Path(next(iter(module._canaries)))
    before = len(module._bus.recent(100))

    assert path.read_text(encoding="utf-8")
    module._check_canaries()

    assert len(module._bus.recent(100)) == before


def test_dynamic_lure_text_does_not_claim_unavailable_read_observation(
    tmp_path: Path, monkeypatch
) -> None:
    module = _module(tmp_path, monkeypatch)
    module._base.mkdir(parents=True)
    monkeypatch.setattr(module, "_plant_fake_registry_cred", lambda _name: None)

    module._restage("credential discovery")

    lure = next(path for path in module._base.iterdir() if path.is_file())
    text = lure.read_text(encoding="utf-8")
    assert "File mutation or deletion is logged" in text
    assert "audited reads require the configured OS audit source" in text
    assert "Any access" not in text


def _live_canary_state(module):
    paths = tuple(Path(path) for path in module._canaries)
    return {
        "base": module._base, "canaries": module._canaries,
        "evidence": module._canary_evidence,
        "enrolled": dict(module._canaries), "snapshots": dict(module._canary_evidence),
        "files": {path: path.read_bytes() for path in paths},
        "identities": {path: (path.stat().st_dev, path.stat().st_ino,
                              path.stat().st_size, path.stat().st_mtime_ns) for path in paths},
    }


def _assert_live_canaries_unchanged(module, before):
    assert module._base is before["base"]
    assert module._canaries is before["canaries"]
    assert module._canary_evidence is before["evidence"]
    assert dict(module._canaries) == before["enrolled"]
    assert dict(module._canary_evidence) == before["snapshots"]
    now = _live_canary_state(module)
    assert now["files"] == before["files"]
    assert now["identities"] == before["identities"]


@pytest.mark.parametrize("mutate_live", [False, True])
def test_disposable_selftest_never_swaps_a_real_running_sensor_generation(
    tmp_path, monkeypatch, mutate_live,
):
    import threading

    module = _module(tmp_path, monkeypatch)
    if mutate_live:
        module._bus.arm(BusAuthority(b"d" * 32))
    ready, step, checked, finish_worker = (threading.Event() for _ in range(4))
    entered, finish_test = threading.Event(), threading.Event()
    real_plant = deception.DeceptionModule._plant
    diagnostic = None
    outcome = []
    sleeps = []

    def controlled_sleep(_seconds):
        sleeps.append(True)
        if len(sleeps) == 1:
            ready.set()
            assert step.wait(5), "Fixture must release the exact sensor generation"
        else:
            checked.set()
            assert finish_worker.wait(5), "Fixture must retire its exact sensor generation"

    def retained_plant(self, **kwargs):
        if threading.current_thread() is diagnostic:
            entered.set()
            assert finish_test.wait(5), "Fixture must release its actual diagnostic call"
            assert self is not module
        return real_plant(self, **kwargs)

    monkeypatch.setattr(module, "sleep", controlled_sleep)
    monkeypatch.setattr(deception.DeceptionModule, "_plant", retained_plant)
    try:
        module.start()
        assert ready.wait(5)
        worker, generation, stop = module._thread, module.lifecycle_generation, module._stop
        assert worker is not None and worker.is_alive()
        before = _live_canary_state(module)
        assert len(before["enrolled"]) == len(deception.CANARY_NAMES)
        prior_events = len(module._bus.recent(100))
        diagnostic = threading.Thread(target=lambda: outcome.append(module.self_test()),
                                      name="inert-deception-selftest")
        diagnostic.start()
        assert entered.wait(5)
        _assert_live_canaries_unchanged(module, before)
        target = module._base / "backup_keys.txt"
        if mutate_live:
            protected = getattr(target.stat(), "st_file_attributes", 0) & 0x06
            with target.open("r+b") as stream:
                stream.write(before["files"][target] + b"\ncontrolled live mutation\n")
                stream.truncate()
            assert getattr(target.stat(), "st_file_attributes", 0) & 0x06 == protected
        step.set()  # The real run() performs its actual canary and feed checks.
        assert checked.wait(5)
        if mutate_live:
            from angerona.core.threat import is_active_threat

            events = module._bus.recent(100)
            assert len(events) == prior_events + 1
            event = events[0]
            assert event.module == module.name and event.severity == Severity.CRITICAL
            assert event.message == f"Canary file TOUCHED: {target}"
            assert event.details == {"path": str(target)}
            assert event.hmac_sig and module._bus.verify(event)
            assert is_active_threat(event)
            assert module._base is before["base"]
            assert module._canaries is before["canaries"]
            assert module._canary_evidence is before["evidence"]
            sampled_mtime, sampled_evidence = module._canary_snapshot(target)
            assert sampled_evidence != before["snapshots"][str(target)]
            assert module._canaries[str(target)] == sampled_mtime
            assert module._canary_evidence[str(target)] == sampled_evidence
            detected = _live_canary_state(module)
            assert detected["files"][target] == before["files"][target] + b"\ncontrolled live mutation\n"
            assert detected["identities"][target][:2] == before["identities"][target][:2]
            for other in before["files"]:
                if other != target:
                    assert detected["files"][other] == before["files"][other]
                    assert detected["identities"][other] == before["identities"][other]
                    assert detected["snapshots"][str(other)] == before["snapshots"][str(other)]
        else:
            _assert_live_canaries_unchanged(module, before)
            assert len(module._bus.recent(100)) == prior_events
            detected = before
        assert (module._thread, module.lifecycle_generation, module._stop) == (worker, generation, stop)
        assert module.health == 70
        finish_test.set()
        diagnostic.join(5)
        assert not diagnostic.is_alive()
        assert outcome == [(True, "disposable secret-free canary lifecycle passed")]
        _assert_live_canaries_unchanged(module, detected)
        assert worker.is_alive() and module.lifecycle_generation == generation
    finally:
        finish_test.set()
        if diagnostic is not None and diagnostic.ident is not None:
            diagnostic.join(5)
            assert not diagnostic.is_alive()
        module.stop()
        step.set()
        finish_worker.set()
        if module._thread is not None:
            module._thread.join(5)
            assert not module._thread.is_alive()


@pytest.mark.parametrize("fault,expected", [
    ("enrollment", "disposable canary enrollment failed: slot1:PermissionError"),
    ("count", "canary count contract failed: expected=3; observed=2"),
    ("path", "canary path contract failed"),
    ("names", "canary names contract failed"),
    ("content", "canary content contract failed: slot1"),
])
def test_disposable_selftest_keeps_real_contract_failures_and_live_evidence(
    tmp_path, monkeypatch, fault, expected,
):
    module = _module(tmp_path, monkeypatch)
    module._plant()
    before = _live_canary_state(module)
    real_plant = deception.DeceptionModule._plant
    real_snapshot = deception.DeceptionModule._canary_snapshot

    def refused_snapshot(path):
        if path.parent != module._base and path.name == deception.CANARY_NAMES[0]:
            raise PermissionError("private fixture path and secret must never be disclosed")
        return real_snapshot(path)

    def faulted_plant(self, **kwargs):
        assert self is not module
        real_plant(self, **kwargs)
        if fault == "count":
            self._canaries.pop(str(self._base / deception.CANARY_NAMES[0]))
        elif fault in {"path", "names"}:
            replacement = (self._base.parent if fault == "path" else self._base) / "unexpected.txt"
            replacement.write_text("# Do not modify — security canary.\n", encoding="utf-8")
            self._canaries.pop(str(self._base / deception.CANARY_NAMES[0]))
            self._enroll_canary(replacement)
        elif fault == "content":
            target = self._base / deception.CANARY_NAMES[0]
            protected = getattr(target.stat(), "st_file_attributes", 0) & 0x06
            with target.open("r+b") as stream:
                stream.write(b"changed private fixture")
                stream.truncate()
            assert getattr(target.stat(), "st_file_attributes", 0) & 0x06 == protected

    if fault == "enrollment":
        monkeypatch.setattr(deception.DeceptionModule, "_canary_snapshot", staticmethod(refused_snapshot))
    monkeypatch.setattr(deception.DeceptionModule, "_plant", faulted_plant)
    assert module.self_test() == (False, expected)
    assert "secret" not in expected and str(tmp_path) not in expected
    _assert_live_canaries_unchanged(module, before)
