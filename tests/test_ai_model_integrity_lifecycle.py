from __future__ import annotations

import hashlib
import json
import os
import threading
from pathlib import Path

import pytest

from angerona.core import module_base
from angerona.core.module_contract import build_capability_contract
from angerona.modules import ai_model_integrity as integrity
from angerona.modules.ai_triage import AITriageModule


def _guard(monkeypatch, tmp_path):
    monkeypatch.setattr(integrity, "_repo_root", lambda: tmp_path)
    module = integrity.AIModelIntegrityGuardModule()
    monkeypatch.setattr(module, "_models_root", lambda: tmp_path)
    return module


def test_cancelled_hash_never_opens_the_model(monkeypatch, tmp_path):
    stop = threading.Event()
    stop.set()
    monkeypatch.setattr(os, "open", lambda *_a, **_k: pytest.fail("cancelled scan opened a file"))
    with pytest.raises(integrity.ModelAttestationCancelled):
        integrity._hash_file(tmp_path / "not-opened", stop_event=stop)


@pytest.mark.parametrize("cancel_at_eof", [False, True])
def test_cancel_during_chunk_read_cannot_return_digest_and_closes_descriptor(
    monkeypatch, tmp_path, cancel_at_eof
):
    model = tmp_path / "inert-blob"
    model.write_bytes(b"inert-model-bytes")
    stop = threading.Event()
    reads = []
    real_read = os.read

    def read(descriptor, count):
        block = real_read(descriptor, count)
        reads.append((descriptor, len(block)))
        if not cancel_at_eof or not block:
            stop.set()
        return block

    monkeypatch.setattr(os, "read", read)
    with pytest.raises(integrity.ModelAttestationCancelled):
        integrity._hash_file(model, chunk=4, stop_event=stop)
    assert reads[-1][1] == (0 if cancel_at_eof else 4)
    if not cancel_at_eof:
        assert len(reads) == 1
    with pytest.raises(OSError):
        os.fstat(reads[0][0])


def test_inventory_hash_uses_captured_generation_token(monkeypatch, tmp_path):
    module = _guard(monkeypatch, tmp_path)
    model = tmp_path / "inert-blob"
    model.write_bytes(b"inert model")
    old_stop = module.generation_stop_event()
    monkeypatch.setattr(module, "_discover_files", lambda: ({"inert-blob": model}, {}))
    real_read = os.read
    seen_tokens = []
    real_hash = integrity._hash_file

    def read(descriptor, count):
        block = real_read(descriptor, count)
        module._stop = threading.Event()  # A later lifecycle owns a new token.
        old_stop.set()
        return block

    def hash_file(path, **kwargs):
        seen_tokens.append(kwargs["stop_event"])
        return real_hash(path, **kwargs)

    monkeypatch.setattr(os, "read", read)
    monkeypatch.setattr(integrity, "_hash_file", hash_file)
    with pytest.raises(integrity.ModelAttestationCancelled):
        module._snapshot_inventory()
    assert seen_tokens == [old_stop]
    assert not module._stop.is_set()


def test_live_scan_reports_pending_and_has_bounded_realistic_deadline(monkeypatch, tmp_path):
    module = _guard(monkeypatch, tmp_path)
    entered = threading.Event()
    release = threading.Event()
    events = []
    monkeypatch.setattr(module, "emit", lambda *args, **kwargs: events.append((args, kwargs)))

    def verify():
        entered.set()
        assert release.wait(2.0)
        return 2, []

    monkeypatch.setattr(module, "_verify_pass", verify)
    module._angerona_contract = build_capability_contract(
        module, capability_id="angerona.modules.ai_model_integrity",
    )
    module.start()
    try:
        assert entered.wait(2.0)
        assert module.health == 70
        assert "verification pending" in module.health_note
        assert not module.first_cycle_complete
        assert module._watchdog_startup_budget_seconds() == 300.0
        assert module._watchdog_work_budget_seconds() == 300.0
        with monkeypatch.context() as scoped:
            scoped.setattr(module_base.time, "monotonic", lambda: module._generation_started_at + 65.0)
            assert not module.operational_snapshot()["watchdog_deadline_missed"]
            scoped.setattr(module_base.time, "monotonic", lambda: module._generation_started_at + 301.0)
            assert module.operational_snapshot()["watchdog_deadline_missed"]
        module.stop()
        release.set()
        module._thread.join(2.0)
        assert not module._thread.is_alive()
        assert not module.first_cycle_complete
        assert module._verified == 0 and module._mismatches == 0
        assert not any("FAILURE" in str(args) or "unavailable" in str(args) for args, _ in events)
    finally:
        module.stop()
        release.set()
        module._thread.join(2.0)


def test_typed_cancellation_is_not_reported_as_tampering(monkeypatch, tmp_path):
    module = _guard(monkeypatch, tmp_path)
    events = []
    monkeypatch.setattr(module, "emit", lambda *args, **kwargs: events.append((args, kwargs)))

    def verify():
        module.stop()
        raise integrity.ModelAttestationCancelled("model attestation interrupted")

    monkeypatch.setattr(module, "_verify_pass", verify)
    module.run()
    assert module._mismatches == 0 and module.last_error == ""
    assert not module.first_cycle_complete
    assert len(events) == 1  # Only the initial informational online event.


def test_stopped_scan_cannot_publish_a_late_cycle(monkeypatch, tmp_path):
    module = _guard(monkeypatch, tmp_path)
    stop = module.generation_stop_event()
    module.stop()
    monkeypatch.setattr(module, "sleep", lambda *_a, **_k: pytest.fail("stopped scan slept"))
    module._wait_for_next_scan(stop)
    assert not module.first_cycle_complete


@pytest.mark.parametrize("phase", ["inventory", "configured-model"])
def test_cancelled_fresh_attestation_cannot_issue_receipt(monkeypatch, tmp_path, phase):
    module = _guard(monkeypatch, tmp_path)
    content = b"inert approved model"
    digest = hashlib.sha256(content).hexdigest()
    blob = tmp_path / "blobs" / f"sha256-{digest}"
    blob.parent.mkdir()
    blob.write_bytes(content)
    manifest = tmp_path / "manifests" / "registry.ollama.ai" / "library" / "fixture" / "latest"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(json.dumps({
        "config": {"digest": f"sha256:{digest}", "size": len(content)}, "layers": [],
    }), encoding="utf-8")
    module._baseline_key_override = b"k" * 32
    module.rebaseline(approved=True)
    monkeypatch.setattr(integrity, "AIModelIntegrityGuardModule", lambda: module)
    real_read = os.read
    stop = module.generation_stop_event()

    def read(descriptor, count):
        block = real_read(descriptor, count)
        module.stop()
        return block

    integrity._ATTESTATION_CACHE.clear()
    if phase == "inventory":
        monkeypatch.setattr(os, "read", read)
    else:
        real_blob_hash = integrity._hash_verified_blob

        def cancel_after_blob(*args, stop_event):
            assert stop_event is stop
            result = real_blob_hash(*args, stop_event=stop_event)
            stop.set()
            return result

        monkeypatch.setattr(integrity, "_hash_verified_blob", cancel_after_blob)
    try:
        with pytest.raises(integrity.ModelAttestationCancelled):
            integrity.require_fresh_model_attestation("fixture", stop_event=stop)
        assert integrity._ATTESTATION_CACHE == {}
    finally:
        integrity._ATTESTATION_CACHE.clear()


@pytest.mark.parametrize("cancel_at_eof", [False, True])
def test_configured_blob_cancellation_cannot_return_digest(monkeypatch, tmp_path, cancel_at_eof):
    blob = tmp_path / "inert-blob"
    payload = b"inert approved bytes"
    blob.write_bytes(payload)
    stop = threading.Event()
    original_open = Path.open
    streams = []

    class CancelledRead:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            self.stream.close()

        def fileno(self):
            return self.stream.fileno()

        def read(self, count):
            block = self.stream.read(count)
            if not cancel_at_eof or not block:
                stop.set()
            return block

    def opened(path, *args, **kwargs):
        stream = original_open(path, *args, **kwargs)
        if path == blob:
            streams.append(stream)
            return CancelledRead(stream)
        return stream

    monkeypatch.setattr(Path, "open", opened)
    with pytest.raises(integrity.ModelAttestationCancelled):
        integrity._hash_verified_blob(blob, tmp_path, len(payload), stop_event=stop)
    assert streams and all(stream.closed for stream in streams)


def test_waiting_for_another_attestation_is_cancellable_before_authority_reads(monkeypatch):
    stop = threading.Event()
    started = threading.Event()
    failures = []
    monkeypatch.setattr(
        integrity, "_approved_model_context", lambda *_a: pytest.fail("cancelled waiter read authority"),
    )

    def wait_for_attestation():
        started.set()
        try:
            integrity.require_fresh_model_attestation("fixture", stop_event=stop)
        except integrity.ModelAttestationCancelled as exc:
            failures.append(exc)

    integrity._ATTESTATION_LOCK.acquire()
    worker = threading.Thread(target=wait_for_attestation)
    try:
        worker.start()
        assert started.wait(2.0)
        stop.set()
        worker.join(2.0)
        assert not worker.is_alive()
        assert len(failures) == 1
    finally:
        stop.set()
        integrity._ATTESTATION_LOCK.release()
        worker.join(2.0)


def test_triage_passes_immutable_stop_token_and_cancellation_never_calls_model(monkeypatch):
    module = AITriageModule()
    old_stop = module.generation_stop_event()
    events = []
    monkeypatch.setattr(module, "emit", lambda *args, **kwargs: events.append((args, kwargs)))

    def cancelled(_model, *, stop_event):
        assert stop_event is old_stop
        module._stop = threading.Event()
        old_stop.set()
        raise integrity.ModelAttestationCancelled("model attestation interrupted")

    monkeypatch.setattr(integrity, "require_fresh_model_attestation", cancelled)
    monkeypatch.setattr(
        "angerona.modules.ai_triage.safe_urlopen",
        lambda *_a, **_k: pytest.fail("cancelled triage reached Ollama"),
    )
    assert module._ask("inert event") is None
    assert module._attestation_receipt is None
    assert module._attestation_error == module.last_error == ""
    assert events == []
    assert module._watchdog_work_budget_seconds() == 300.0


def test_triage_cancelled_inference_does_not_publish_a_cycle(monkeypatch):
    from angerona.core.eventbus import Event, Severity

    module = AITriageModule()
    module._bus = object()
    event = Event("fixture detector", "inert event", Severity.HIGH)
    monkeypatch.setattr(module, "_bind_speculative_consumer", lambda: None)
    monkeypatch.setattr(module, "_consume_speculative_frame", lambda *_a: None)
    monkeypatch.setattr(module, "sleep", lambda *_a, **_k: None)
    monkeypatch.setattr(module, "poll_bus_events", lambda **_k: ([event], False))
    monkeypatch.setattr("angerona.core.threat.is_active_threat", lambda *_a: True)
    monkeypatch.setattr("angerona.modules.behavioral_tuner.get_tuner", lambda: None)

    def stop_during_ask(_prompt):
        module.stop()
        return None

    monkeypatch.setattr(module, "_ask", stop_during_ask)
    module._run_generation()
    assert not module.first_cycle_complete


def test_two_slow_triage_attempts_advance_liveness_only_when_each_finishes(monkeypatch):
    from angerona.core.eventbus import Event, Severity

    module = AITriageModule()
    module._bus = object()
    module.status = "running"
    module._generation_started_at = 1.0
    module._watchdog_deadline_at = 301.0
    module._last_sleep_interval_seconds = 8.0
    module._thread = type("LiveWorker", (), {"is_alive": lambda _self: True})()
    clock = [1.0]
    requests = []
    emitted = []
    sleeps = []
    events = [Event("fixture detector", f"inert event {index}", Severity.HIGH) for index in range(2)]
    monkeypatch.setattr(module_base.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(module, "_bind_speculative_consumer", lambda: None)
    monkeypatch.setattr(module, "_consume_speculative_frame", lambda *_a: None)
    monkeypatch.setattr(module, "poll_bus_events", lambda **_k: (events, False))
    monkeypatch.setattr(module, "emit", lambda *args, **_kwargs: emitted.append(args))
    monkeypatch.setattr("angerona.core.threat.is_active_threat", lambda *_a: True)
    monkeypatch.setattr("angerona.modules.behavioral_tuner.get_tuner", lambda: None)

    def sleep(*_args, **_kwargs):
        sleeps.append(True)
        if len(sleeps) == 2:
            module.stop()

    def slow_attempt(prompt):
        completed = len(requests)
        assert module._cycle_count == completed
        before_deadline = module._watchdog_deadline_at
        clock[0] += 180.0
        assert module._watchdog_deadline_at == before_deadline
        assert not module.operational_snapshot()["watchdog_deadline_missed"]
        requests.append(prompt)
        return "inert completed verdict"

    monkeypatch.setattr(module, "sleep", sleep)
    monkeypatch.setattr(module, "_ask", slow_attempt)
    module._run_generation()
    assert len(requests) == len(emitted) == 2
    assert clock[0] == 361.0  # The whole batch exceeded the 300-second budget.
    assert module._last_cycle_completed_at == 361.0


@pytest.mark.parametrize("fails", [False, True])
def test_triage_discards_transport_result_or_error_after_generation_stop(monkeypatch, fails):
    module = AITriageModule()
    old_stop = module.generation_stop_event()
    emitted = []
    monkeypatch.setattr(module, "_attest_model", lambda: True)
    monkeypatch.setattr(module, "emit", lambda *args, **_kwargs: emitted.append(args))

    class Response:
        headers = {}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def read(self, _limit=-1):
            return b'{"message":{"content":"discard this late result"}}'

    def transport(*_args, **_kwargs):
        old_stop.set()
        module._stop = threading.Event()  # Another generation must not clear the old token.
        if fails:
            raise OSError("inert late timeout")
        return Response()

    monkeypatch.setattr("angerona.modules.ai_triage.safe_urlopen", transport)
    assert module._ask("inert event") is None
    assert module._cb_state == "closed"
    assert module.last_error == ""
    assert emitted == []
