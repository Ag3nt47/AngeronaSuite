"""FIM coverage warnings stay visible without inventing active attacks.

The real producer scans only disposable inputs. The Chill test enters its real
signature/classification poll and captures the final wake boundary; no module
thread, host collector, baseline approval or response action is started.
"""
from copy import deepcopy
from dataclasses import replace
import json
from types import SimpleNamespace

import pytest

from angerona.core.chill_mode import ChillPolicy
from angerona.core.chill_runtime import ChillRuntimeController
from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.core.threat import active_threat_events, event_disposition, is_active_threat
from angerona.modules import file_integrity


@pytest.fixture(autouse=True)
def private_resolution_state(monkeypatch):
    # Genuine finding tests must not consult or change an operator's stores.
    from angerona.core import alert_ack, drill_resolution, process_allowlist
    monkeypatch.setattr(alert_ack, "acked_signatures", lambda: set())
    monkeypatch.setattr(process_allowlist, "policy_snapshot", lambda: ())
    monkeypatch.setattr(process_allowlist, "is_event_allowed", lambda *_a, **_k: False)
    monkeypatch.setattr(drill_resolution, "resolution_snapshot", lambda: {})
    monkeypatch.setattr(drill_resolution, "is_resolved_event", lambda *_a, **_k: False)


def actual_notice(tmp_path, monkeypatch, *, missing_count=1):
    watched = tmp_path / "watched"
    watched.mkdir()
    leaf = watched / "ordinary-policy.txt"
    leaf.write_text("private initial policy", encoding="utf-8")
    roots = [str(watched), *(str(tmp_path / f"missing-{i:02d}") for i in range(missing_count))]
    monkeypatch.setattr(file_integrity, "watch_roots", lambda: roots)
    module = file_integrity.FileIntegrityModule()
    authority = BusAuthority(b"F" * 32)
    bus = EventBus()
    bus.arm(authority)
    module.bind(bus)
    snapshot = module._scan()
    assert module._last_scan_receipt["complete"] is False
    assert len(snapshot) == 1
    module._coverage_suppressed = 4
    module._record_scan_outcome()
    event = bus.recent(1)[0]
    assert event.severity is Severity.HIGH and bus.verify(event)
    return module, bus, event, leaf, snapshot, authority


def controller_boundary(bus, monkeypatch):
    policy = ChillPolicy(clock=lambda: 10.0)
    policy.enable()
    controller = ChillRuntimeController(
        SimpleNamespace(modules={}), bus, SimpleNamespace(runtime_chill_active=True),
        policy=policy, clock=lambda: 10.0, release_models=lambda *_a: None,
    )
    wakes = []
    monkeypatch.setattr(controller, "_begin_wake", lambda count, **kw: wakes.append((count, kw)))
    return controller, wakes


def test_actual_signed_warning_remains_high_health_and_unchanged(tmp_path, monkeypatch):
    module, bus, event, _leaf, _snapshot, authority = actual_notice(tmp_path, monkeypatch)
    original = deepcopy(event)
    assert event.details["blocked_root_count"] == 1
    assert event.details["suppressed_observations"] == 4
    assert event_disposition(event) == "health"
    assert not is_active_threat(event) and active_threat_events([event]) == []
    assert event == original and event.severity is Severity.HIGH
    assert authority.verify(event) and bus.verify(event)
    assert module._baseline == {} and module._baseline_status == "not-loaded"
    module._record_scan_outcome()
    assert len(bus.recent(10)) == 1  # Existing warning cadence is not bypassed.
    assert module._coverage_suppressed == 1


def test_actual_omitted_root_count_and_retained_json_are_recognized(tmp_path, monkeypatch):
    _module, bus, event, *_rest = actual_notice(tmp_path, monkeypatch, missing_count=35)
    assert len(event.details["blocked_roots"]) == 32
    assert event.details["blocked_root_count"] == 35
    assert event.details["omitted_blocked_roots"] == 3
    retained = replace(event, details=json.loads(json.dumps(event.details)))
    assert bus.verify(retained)
    assert event_disposition(retained) == "health" and not is_active_threat(retained)


def test_signed_health_does_not_wake_but_real_file_change_does(tmp_path, monkeypatch):
    authority = BusAuthority(b"G" * 32)
    bus = EventBus()
    bus.arm(authority)
    controller, wakes = controller_boundary(bus, monkeypatch)
    module, source_bus, health, leaf, baseline, _auth = actual_notice(tmp_path, monkeypatch)
    # Publish the genuine producer's envelope on this independently armed bus.
    bus.publish(replace(health, hmac_sig=""))
    controller.poll_once()
    assert wakes == [] and not controller.policy.escalated
    assert controller.policy.awake_until == 0.0

    module.bind(bus)
    module._baseline = dict(baseline)  # Disposable in-memory input, no approval/store.
    leaf.write_text("private changed policy", encoding="utf-8")
    module._evaluate_snapshot(module._scan())
    finding = next(e for e in bus.recent(10) if e.message.startswith("Watched file modified:"))
    assert finding.severity is Severity.HIGH and bus.verify(finding)
    assert event_disposition(finding) == "active" and is_active_threat(finding)
    controller.poll_once()
    assert len(wakes) == 1 and wakes[0][0] == 1 and controller.policy.escalated
    assert controller._wake_thread is None and controller._release_thread is None
    assert source_bus.verify(health)  # The original warning was not rewritten/ACKed.


def test_chill_rejects_modified_signed_details_before_classification(tmp_path, monkeypatch):
    authority = BusAuthority(b"I" * 32)
    bus = EventBus()
    bus.arm(authority)
    controller, wakes = controller_boundary(bus, monkeypatch)
    _module, _source, event, *_rest = actual_notice(tmp_path, monkeypatch)
    bus.publish(replace(event, hmac_sig=""))
    retained = bus.recent(1)[0]
    retained.details["active_attack"] = True
    assert is_active_threat(retained) and not bus.verify(retained)
    controller.poll_once()
    assert wakes == [] and not controller.policy.escalated


@pytest.mark.parametrize("change", [
    "active", "exploitation", "response", "response-contract", "tamper", "target",
    "schema", "unknown-field", "active-int", "response-int", "complete-int",
    "disposition", "count-unit", "count-bool", "count-zero", "count-float",
    "count-huge", "omitted-bool", "omitted-negative", "omitted-mismatch",
    "suppressed-bool", "suppressed-negative", "suppressed-huge", "roots-tuple",
    "roots-empty", "roots-too-many", "root-not-dict", "row-extra", "root-empty",
    "root-too-long", "root-null", "reason-empty", "reason-too-long", "blocking-type",
    "blocking-too-long", "duplicate-root", "missing-field", "wrong-message",
    "different-producer", "critical", "raw-severity-int",
])
def test_spoofs_malformed_and_real_findings_never_borrow_health(tmp_path, monkeypatch, change):
    _module, _bus, event, *_rest = actual_notice(tmp_path, monkeypatch)
    d = deepcopy(event.details)
    kwargs = {"details": d, "hmac_sig": ""}
    if change == "active": d["active_attack"] = True
    elif change == "exploitation": d["active_exploitation"] = True
    elif change == "response": d["response_authorized"] = True
    elif change == "response-contract": d["response_contract"] = {"actions": ["isolate_host"]}
    elif change == "tamper": d["tamper"] = True
    elif change == "target": d["target"] = "actor"
    elif change == "schema": d["schema"] = "unknown.v2"
    elif change == "unknown-field": d["future_evidence"] = "not-reviewed"
    elif change == "active-int": d["active_attack"] = 0
    elif change == "response-int": d["response_authorized"] = 0
    elif change == "complete-int": d["complete"] = 0
    elif change == "disposition": d["disposition"] = "collection"
    elif change == "count-unit": d["count_unit"] = "confirmed attacks"
    elif change == "count-bool": d["blocked_root_count"] = True
    elif change == "count-zero": d["blocked_root_count"] = 0
    elif change == "count-float": d["blocked_root_count"] = 1.0
    elif change == "count-huge": d["blocked_root_count"] = 1 << 1000
    elif change == "omitted-bool": d["omitted_blocked_roots"] = False
    elif change == "omitted-negative": d["omitted_blocked_roots"] = -1
    elif change == "omitted-mismatch": d["omitted_blocked_roots"] = 1
    elif change == "suppressed-bool": d["suppressed_observations"] = True
    elif change == "suppressed-negative": d["suppressed_observations"] = -1
    elif change == "suppressed-huge": d["suppressed_observations"] = 1 << 1000
    elif change == "roots-tuple": d["blocked_roots"] = tuple(d["blocked_roots"])
    elif change == "roots-empty": d["blocked_roots"] = []
    elif change == "roots-too-many": d["blocked_roots"] *= 33
    elif change == "root-not-dict": d["blocked_roots"][0] = "unavailable"
    elif change == "row-extra": d["blocked_roots"][0]["tamper"] = True
    elif change == "root-empty": d["blocked_roots"][0]["root"] = ""
    elif change == "root-too-long": d["blocked_roots"][0]["root"] = "x" * 32769
    elif change == "root-null": d["blocked_roots"][0]["root"] = "x\x00y"
    elif change == "reason-empty": d["blocked_roots"][0]["reason"] = ""
    elif change == "reason-too-long": d["blocked_roots"][0]["reason"] = "x" * 501
    elif change == "blocking-type": d["blocked_roots"][0]["blocking_object"] = []
    elif change == "blocking-too-long": d["blocked_roots"][0]["blocking_object"] = "x" * 501
    elif change == "duplicate-root":
        d["blocked_roots"] *= 2
        d["blocked_root_count"] = 2
    elif change == "missing-field": del d["suppressed_observations"]
    elif change == "wrong-message": kwargs["message"] = "Watched file modified: important.bin"
    elif change == "different-producer": kwargs["module"] = "Other Detector"
    elif change == "critical": kwargs["severity"] = Severity.CRITICAL
    elif change == "raw-severity-int": kwargs["severity"] = int(Severity.HIGH)
    else: raise AssertionError(change)
    candidate = replace(event, **kwargs)
    assert event_disposition(candidate) == "active" and is_active_threat(candidate)


@pytest.mark.parametrize("details", [None, [], ["health"], "health", 1, True])
def test_untyped_health_payload_does_not_raise_or_hide_high_finding(details):
    event = Event("File Integrity Monitor", "FIM coverage incomplete: unavailable",
                  Severity.HIGH, details=details)
    assert event_disposition(event) == "active" and is_active_threat(event)


# Independent literals retain the former filename bypasses even after the
# implementation removes its message-marker list.
LEGACY_HEALTH_WORDS = (
    "quarantined after", "keeps crashing", "left down after", "sensor blind",
    "entered safe_mode", "pipeline regression", "could not catch", "manual signature work",
    "restarts; manual attention", "module crashed (attempt", "module failed to start",
    "module unavailable",
)


@pytest.mark.parametrize("words", LEGACY_HEALTH_WORDS)
@pytest.mark.parametrize("explicit_active", [False, True])
def test_real_file_changes_under_health_words_stay_active(tmp_path, monkeypatch, words, explicit_active):
    watched = tmp_path / words
    watched.mkdir()
    leaf = watched / "ordinary-policy.txt"
    leaf.write_text("private original value", encoding="utf-8")
    monkeypatch.setattr(file_integrity, "watch_roots", lambda: [str(watched)])
    module = file_integrity.FileIntegrityModule()
    authority = BusAuthority(b"J" * 32)
    bus = EventBus()
    bus.arm(authority)
    module.bind(bus)
    module._baseline = dict(module._scan())  # Private in-memory comparison only.
    leaf.write_text("private genuinely changed value", encoding="utf-8")
    module._evaluate_snapshot(module._scan())
    event = next(e for e in bus.recent(10) if e.message.startswith("Watched file modified:"))
    assert words in event.message.casefold() and event.severity is Severity.HIGH
    if explicit_active:
        unsigned = replace(event, details={**event.details, "active_attack": True}, hmac_sig="")
        event = replace(unsigned, hmac_sig=authority.sign(unsigned))
    assert authority.verify(event)
    assert event_disposition(event) == "active" and is_active_threat(event)
    assert event.details["path"] == str(leaf)


@pytest.mark.parametrize("words", LEGACY_HEALTH_WORDS)
def test_legacy_words_alone_do_not_downgrade_high_evidence(words):
    event = Event("File Integrity Monitor", f"Untrusted evidence contains {words}", Severity.HIGH)
    assert event_disposition(event) == "active" and is_active_threat(event)


@pytest.mark.parametrize("raw_root", ["/private/unavailable", r"C:\private\unavailable", r"\\server\share\unavailable"])
def test_retained_absolute_root_spellings_are_lexical_only(tmp_path, monkeypatch, raw_root):
    _module, bus, event, _leaf, _snap, authority = actual_notice(tmp_path, monkeypatch)
    details = deepcopy(event.details)
    reason = "watch root unavailable or unsafe: " + raw_root
    details["blocked_roots"][0] = {"root": raw_root, "reason": reason, "blocking_object": raw_root}
    unsigned = replace(event, message="FIM coverage incomplete: " + reason, details=details, hmac_sig="")
    retained = replace(unsigned, hmac_sig=authority.sign(unsigned))
    assert bus.verify(retained) and event_disposition(retained) == "health"
    # No lookup of these synthetic retained paths occurs.


@pytest.mark.parametrize("raw_root", ["relative/root", r"C:drive-relative", r"\drive-relative"])
def test_relative_root_metadata_cannot_borrow_health(tmp_path, monkeypatch, raw_root):
    _module, _bus, event, *_rest = actual_notice(tmp_path, monkeypatch)
    details = deepcopy(event.details)
    details["blocked_roots"][0]["root"] = raw_root
    assert is_active_threat(replace(event, details=details))


SNAPSHOT_OUTCOMES = (
    "published", "published_finalization_gap", "published_durability_gap", "published_cleanup_gap",
    "held_directory", "held_accounting", "held_storage_budget", "held_custody_unknown",
    "held_space_unknown", "held_free_space", "held_capture_bound", "held_busy", "held_capture_text",
    "held_capture", "held_write", "held_publication_unknown", "held_cleanup_gap",
)


def actual_lifecycle(monkeypatch, *, outcome="held_busy", returns=False):
    from angerona.core.module_base import BaseModule

    class DisposableModule(BaseModule):
        name = "Disposable lifecycle fixture"
        def run(self):
            if not returns:
                raise RuntimeError("inert lifecycle failure")

    class NoWait:
        def __init__(self): self.waits = []
        def wait(self, timeout): self.waits.append(timeout); return False
        def is_set(self): return False

    module = DisposableModule()
    authority = BusAuthority(b"L" * 32)
    bus = EventBus()
    bus.arm(authority)
    module.bind(bus)
    # Exercise actual crash message construction without native snapshot or sleep.
    monkeypatch.setattr(module, "_write_crash_snapshot", lambda *_a: outcome)
    stop = NoWait()
    module._wrapped_run(0, stop, 0.0)
    assert module._thread is None
    return module, bus, list(reversed(bus.recent(10))), authority, stop


@pytest.mark.parametrize("outcome", SNAPSHOT_OUTCOMES)
def test_actual_base_module_restart_and_quarantine_stay_health(monkeypatch, outcome):
    module, bus, events, authority, stop = actual_lifecycle(monkeypatch, outcome=outcome)
    assert stop.waits == [5, 30]
    assert len(events) == 3 and module.status == "error"
    assert [e.severity for e in events] == [Severity.HIGH, Severity.HIGH, Severity.CRITICAL]
    assert events[0].message.startswith("Module crashed (attempt 1/3), restarting in 5s: ")
    assert events[1].message.startswith("Module crashed (attempt 2/3), restarting in 30s: ")
    assert events[-1].details["crash_snapshot_outcome"] == outcome
    before = deepcopy(events)
    assert all(event_disposition(e) == "health" and not is_active_threat(e) for e in events)
    assert events == before and all(authority.verify(e) and bus.verify(e) for e in events)
    assert active_threat_events(events) == []


def test_unexpected_worker_return_remains_outside_crash_health_contract(monkeypatch):
    _module, bus, events, _authority, stop = actual_lifecycle(monkeypatch, returns=True)
    assert stop.waits == [] and len(events) == 1
    assert events[0].details["finding_code"] == "module.lifecycle.unexpected_exit"
    assert is_active_threat(events[0]) and bus.verify(events[0])


@pytest.mark.parametrize("change", [
    "active", "exploitation", "response", "contract", "tamper", "target", "unknown",
    "missing-trace", "trace-type", "trace-empty", "trace-too-long", "restart-delay",
    "restart-attempt", "non-prefix", "message-too-long", "wrong-severity", "unknown-outcome",
    "quarantine-suffix", "quarantine-flag-type",
])
def test_spoofed_lifecycle_and_explicit_evidence_cannot_hide(monkeypatch, change):
    _module, _bus, events, authority, _stop = actual_lifecycle(monkeypatch)
    event = events[-1] if change in ("unknown-outcome", "quarantine-suffix", "quarantine-flag-type") else events[0]
    details = deepcopy(event.details)
    options = {"details": details, "hmac_sig": ""}
    if change == "active": details["active_attack"] = True
    elif change == "exploitation": details["active_exploitation"] = True
    elif change == "response": details["response_authorized"] = True
    elif change == "contract": details["response_contract"] = {"actions": ["kill_process"]}
    elif change == "tamper": details["tamper"] = True
    elif change == "target": details["target"] = "core.enforce"
    elif change == "unknown": details["future_evidence"] = "unreviewed"
    elif change == "missing-trace": del details["traceback"]
    elif change == "trace-type": details["traceback"] = []
    elif change == "trace-empty": details["traceback"] = ""
    elif change == "trace-too-long": details["traceback"] = "x" * 501
    elif change == "restart-delay": options["message"] = event.message.replace("5s:", "1s:")
    elif change == "restart-attempt": options["message"] = event.message.replace("attempt 1/3", "attempt 3/3")
    elif change == "non-prefix": options["message"] = "Watched file modified: " + event.message
    elif change == "message-too-long": options["message"] = event.message + "x" * 16384
    elif change == "wrong-severity": options["severity"] = Severity.CRITICAL
    elif change == "unknown-outcome": details["crash_snapshot_outcome"] = "published_unknown_future"
    elif change == "quarantine-suffix": options["message"] = event.message + " additional detection"
    elif change == "quarantine-flag-type": details["crash_snapshot_outcome"] = []
    else: raise AssertionError(change)
    unsigned = replace(event, **options)
    candidate = replace(unsigned, hmac_sig=authority.sign(unsigned))
    assert authority.verify(candidate)
    assert event_disposition(candidate) == "active" and is_active_threat(candidate)
