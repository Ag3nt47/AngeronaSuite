"""Scoped native loops cannot be satisfied by polling or invented receipt shape."""
from __future__ import annotations

from dataclasses import replace
import os
import threading
import time
from types import SimpleNamespace

import pytest

from angerona.core import kernel_telemetry_probe as probe
from angerona.core.eventbus import BusAuthority, Event, EventBus, Severity
from angerona.modules import canary_drill, etw_realtime_sensor, sysmon_listener

TAG = "DRILLCANARY_ABCDEF0123456789"
BIRTH = "116444746000000000"  # Isolated fixture wall time1000, no host process.


def receipts(now=100.0, *, etw="a" * 32):
    return (probe.ProviderReceipt("kernel-etw", etw, True, now, "inert native-session fixture"),
            probe.ProviderReceipt("sysmon-native", "b" * 64, True, now, "inert native-channel fixture"))


def armed():
    tracker = probe.KernelProbeTracker()
    assert tracker.arm(TAG, pid=4321, birth_ticks=BIRTH, started_wall=1000.0,
                       now=100.0, receipts=receipts()) == ()
    return tracker


def echo(provider="kernel-etw", **changes):
    result = probe.KernelEcho(TAG, provider, "a" * 32 if provider == "kernel-etw" else "b" * 64,
                             4321, 1000.5, "c" * 64, 101.0, False)
    return replace(result, **changes)


def test_provider_echo_and_durable_legs_are_independent_and_never_kernel_integrity():
    tracker = armed()
    observed = echo()
    assert tracker.observe(observed)
    assert tracker.snapshot() == ()  # Sensor leg alone is not pipeline success.
    assert tracker.persisted(replace(observed, hmac="d" * 64), now=102) is None
    outcome = tracker.persisted(observed, now=102)
    assert outcome.state == "observed" and outcome.live_enrolled_observed is False
    assert outcome.event_details()["kernel_integrity_verified"] is False
    assert outcome.event_details()["response_authorized"] is False
    assert outcome.event_details()["trigger_hmac"] == observed.hmac
    assert tracker.awaiting_durable() == ()
    missing, = tracker.expire(now=107)
    assert missing.provider == "sysmon-native" and missing.prior_path_observed is False
    assert missing.state == "missed" and missing.event_details()["active_attack"] is False


@pytest.mark.parametrize("change", [
    {"pid": 4322}, {"tag": "DRILLCANARY_0123456789ABCDEF"}, {"generation": "f" * 32},
    {"observed_monotonic": 99.9}, {"observed_monotonic": 106.1}, {"event_ts": 999.0},
])
def test_wrong_identity_nonce_generation_or_deadline_cannot_advance(change):
    tracker = armed()
    assert not tracker.observe(echo(**change))
    assert tracker.awaiting_durable() == ()


@pytest.mark.parametrize("change", [
    {"provider": "polling"}, {"pid": True}, {"event_ts": float("nan")},
    {"event_ts": 10**400}, {"hmac": "C" * 64}, {"live_enrolled_observed": "true"},
])
def test_untrusted_echo_shapes_are_rejected(change):
    with pytest.raises(ValueError):
        echo(**change)


def test_changed_session_invalidates_old_echo_without_misattributing_a_new_generation_miss():
    tracker = armed()
    tracker.refresh_receipts(receipts(now=102, etw="f" * 32))
    assert not tracker.observe(echo())
    outcomes = tracker.expire(now=107)
    etw = next(row for row in outcomes if row.provider == "kernel-etw")
    assert etw.state == "unavailable" and etw.consecutive_misses == 0
    assert "generation changed" in etw.reason


def test_prior_success_is_not_current_coverage_after_restart_or_native_receipt_loss():
    tracker = armed()
    successful = echo()
    assert tracker.observe(successful)
    assert tracker.persisted(successful, now=102).state == "observed"
    tracker.arm("DRILLCANARY_0123456789ABCDEF", pid=4321, birth_ticks=BIRTH, started_wall=1002,
                now=102, receipts=receipts(now=102))
    changed = receipts(now=103, etw="f" * 32)
    tracker.refresh_receipts(changed)
    current, = tracker.snapshot()
    assert current.state == "unavailable" and current.generation == "f" * 32
    assert current.prior_path_observed is False
    # A pending old generation may report its own outcome, but cannot replace
    # the current generation's unavailable snapshot with an older record.
    tracker.expire(now=109)
    assert next(row for row in tracker.snapshot() if row.provider == "kernel-etw").generation == "f" * 32

    tracker = armed()
    lossy = (replace(receipts()[0], available=False, reason="cached native session lost events"), receipts()[1])
    tracker.refresh_receipts(lossy)
    outcomes = tracker.expire(now=107)
    etw = next(row for row in outcomes if row.provider == "kernel-etw")
    assert etw.state == "unavailable" and etw.consecutive_misses == 0


def test_stale_collector_receipt_is_unavailable_instead_of_a_native_echo_miss():
    tracker = armed()
    outcome = tracker.expire(now=116)
    assert all(row.state == "unavailable" and row.consecutive_misses == 0 for row in outcome)


@pytest.mark.parametrize("change", [
    {"available": False, "reason": "native provider lost records"},
    {"sampled_monotonic": 80.0},
])
def test_queued_echo_cannot_revive_green_after_current_receipt_is_lost(change):
    tracker = armed()
    first = echo()
    assert tracker.observe(first)
    assert tracker.persisted(first, now=102).state == "observed"
    next_tag = "DRILLCANARY_0123456789ABCDEF"
    tracker.arm(next_tag, pid=4321, birth_ticks=BIRTH, started_wall=1002,
                now=102, receipts=receipts(now=102))
    queued = echo(tag=next_tag, observed_monotonic=103, event_ts=1003)
    assert tracker.observe(queued)
    current = (replace(receipts(now=103)[0], **change), receipts(now=103)[1])
    tracker.refresh_receipts(current)
    # Reading the authenticated row after collector loss must not turn a
    # previous green path back on. The queued event remains historical evidence.
    assert tracker.persisted(queued, now=104) is None
    outcome = next(row for row in tracker.expire(now=109) if row.provider == "kernel-etw")
    assert outcome.state == "unavailable" and outcome.consecutive_misses == 0
    assert next(row for row in tracker.snapshot() if row.provider == "kernel-etw").state == "unavailable"


def test_repeated_miss_on_previously_observed_same_provider_preserves_health_semantics():
    tracker = armed()
    successful = echo(live_enrolled_observed=True)
    assert tracker.observe(successful)
    assert tracker.persisted(successful, now=102).live_enrolled_observed is True
    tracker.expire(now=107)
    outcomes = []
    for index in (1, 2):
        tag = "DRILLCANARY_" + f"{index:016X}"
        tracker.arm(tag, pid=4321, birth_ticks=BIRTH, started_wall=1000 + index * 10,
                    now=100 + index * 10, receipts=receipts(now=100 + index * 10))
        outcomes.extend(tracker.expire(now=107 + index * 10))
    etw = [row for row in outcomes if row.provider == "kernel-etw"]
    assert [row.consecutive_misses for row in etw] == [1, 2]
    assert all(row.prior_path_observed and not row.event_details()["active_attack"] for row in etw)


@pytest.mark.parametrize("change", [
    {"mode": "fallback"}, {"live": False}, {"sampled_monotonic": 70},
    {"loss_count": 1}, {"generation": "invented"}, {"source_module": "Telemetry Scanner"},
])
def test_stale_lossy_or_fallback_receipts_cannot_admit_a_native_expectation(change):
    snapshot = dict(source_module=probe.PROVIDERS["sysmon-native"], generation="a" * 32,
                    mode="native", live=True, loss_count=0, sampled_monotonic=100)
    snapshot.update(change)
    result = probe.ProviderReceipt.from_snapshot("sysmon-native", snapshot, now=101)
    assert not result.available


def test_native_receipt_snapshot_reads_do_not_query_the_host_and_old_etw_callbacks_are_fenced(monkeypatch):
    module = etw_realtime_sensor.EtwRealtimeSensorModule()
    emitted = []
    monkeypatch.setattr(module, "emit", lambda *args, **kwargs: emitted.append(kwargs))
    callbacks = []
    monkeypatch.setattr(etw_realtime_sensor, "ETWProcessSensor",
                        lambda callback, logger=None: callbacks.append(callback) or SimpleNamespace())
    module._new_sensor()
    old = callbacks[0]
    module._new_sensor()
    current = callbacks[1]
    old({"name": "inert.exe", "pid": 4321})
    assert emitted == []
    current({"name": "inert.exe", "pid": 4321})
    assert emitted[0]["collection_generation"] == module._collection_generation
    monkeypatch.setattr(module, "_sensor", SimpleNamespace(status_receipt=lambda: pytest.fail("snapshot queried ETW")))
    assert module.collection_snapshot()["mode"] == "starting"
    # A delayed query result cannot revive an earlier native generation.
    module._collection_cache = dict(module._collection_cache, generation="f" * 32, live=True, mode="native")
    assert module.collection_snapshot()["live"] is False


def test_polling_and_unauthenticated_names_cannot_satisfy_native_canary(monkeypatch):
    clock = SimpleNamespace(monotonic=lambda: 101.0, time=lambda: 1001.0)
    monkeypatch.setattr(canary_drill, "time", clock)
    bus = EventBus()
    bus.arm(BusAuthority(b"k" * 32))
    module = canary_drill.CanaryDrillModule()
    module.bind(bus)
    module._native_receipt_cache = {row.provider: row for row in receipts()}
    bus.subscribe(module._on_event)
    bus.publish(Event("Telemetry Scanner", "inert polling echo", Severity.INFO, 1000.5,
                      {"type": "process_creation", "pid": 4321, "cmdline": TAG}))
    assert module._kernel_echo_queue.empty()
    forged = Event(probe.PROVIDERS["kernel-etw"], "forged name", Severity.INFO, 1000.5,
                   {"source": "ETW:Kernel-Process", "event_type": "process_creation", "pid": 4321,
                    "cmdline": TAG, "collection_generation": "a" * 32}, hmac_sig="a" * 64)
    module._on_event(forged)
    assert module._kernel_echo_queue.empty()
    bus.publish(replace(forged, hmac_sig=""))
    captured = module._kernel_echo_queue.get_nowait()
    assert captured.provider == "kernel-etw" and not captured.live_enrolled_observed


def test_sysmon_fallback_cache_is_not_a_native_receipt(monkeypatch):
    module = sysmon_listener.SysmonListenerModule()
    module._collection_cache = module._collection_state("fallback", False, "inert fallback")
    monkeypatch.setattr(module, "_try_open_sysmon", lambda: pytest.fail("snapshot opened channel"))
    snapshot = module.collection_snapshot()
    assert snapshot["mode"] == "fallback" and snapshot["live"] is False


def test_exact_authenticated_recorder_row_is_required_for_the_native_loop(monkeypatch):
    monkeypatch.setattr(canary_drill, "time", SimpleNamespace(monotonic=lambda: 101.0, time=lambda: 1001.0))
    bus = EventBus()
    bus.arm(BusAuthority(b"r" * 32))
    module = canary_drill.CanaryDrillModule()
    module.bind(bus)
    module._kernel_tracker = armed()
    module._native_receipt_cache = {row.provider: row for row in receipts()}
    recorded = []
    module.bind_recorder(SimpleNamespace(bounded_events_in_window=lambda *_args, **_kwargs: (recorded, len(recorded))))
    bus.subscribe(module._on_event)
    bus.publish(Event(probe.PROVIDERS["kernel-etw"], "inert native echo", Severity.INFO, 1000.5,
                      {"source": "ETW:Kernel-Process", "event_type": "process_creation", "pid": 4321,
                       "cmdline": TAG, "collection_generation": "a" * 32}))
    original = bus.recent(1)[0]
    module._check_kernel_echoes()
    assert module._kernel_tracker.snapshot() == ()
    assert len(module._kernel_tracker.awaiting_durable()) == 1
    recorded[:] = [replace(original, details={**original.details, "_ledger_integrity": "invalid"})]
    module._check_kernel_echoes()
    assert module._kernel_tracker.snapshot() == ()
    recorded[:] = [replace(original, message="tampered after signing")]
    module._check_kernel_echoes()
    assert module._kernel_tracker.snapshot() == ()
    recorded[:] = [original]
    module._check_kernel_echoes()
    outcome, = module._kernel_tracker.snapshot()
    assert outcome.state == "observed" and outcome.event_hmac == original.hmac_sig
    assert not outcome.live_enrolled_observed
    emitted = next(row for row in bus.recent(10) if row.module == module.name and row.details.get("source") == "kernel-etw")
    assert emitted.details["kernel_integrity_verified"] is False and emitted.details["active_attack"] is False


def test_kernel_miss_alert_preserves_critical_health_without_breach_or_response():
    bus = EventBus()
    bus.arm(BusAuthority(b"h" * 32))
    module = canary_drill.CanaryDrillModule()
    module.bind(bus)
    outcome = probe.KernelProbeOutcome(TAG, "kernel-etw", "a" * 32, "missed", "cause unconfirmed", True, 2)
    module._kernel_outcome(outcome)
    event = bus.recent(1)[0]
    assert event.severity == Severity.CRITICAL and event.details["disposition"] == "health"
    assert event.details["active_attack"] is False and event.details["response_authorized"] is False
    assert "response_contract" not in event.details


def test_cached_sysmon_generation_changes_are_explicit_without_native_reads(monkeypatch):
    module = sysmon_listener.SysmonListenerModule()
    module._channel_generation = module._generation("observed", 1, "a" * 64)
    module._collection_cache = module._collection_state("native", True, "inert verified-channel fixture")
    before = module.collection_snapshot()
    assert before["mode"] == "native" and before["live"]
    monkeypatch.setattr(module, "_capture_channel_generation", lambda *_a: pytest.fail("snapshot queried native channel"))
    module._channel_generation = module._generation("observed", 2, "b" * 64)
    changed = module.collection_snapshot()
    assert changed["mode"] == "unavailable" and changed["live"] is False
    assert changed["generation"] != before["generation"]
    module._channel_generation = {"state": []}
    assert module.collection_snapshot()["mode"] == "unavailable"


def test_probe_retirement_failure_keeps_custody_and_backpressure(monkeypatch):
    module = canary_drill.CanaryDrillModule()
    failure = SimpleNamespace(retire=lambda **_kwargs: (_ for _ in ()).throw(OSError("inert wait failure")))
    module._owned_probes[TAG] = (failure, 0)
    module._retire_owned_probes(cancel=True)
    assert TAG in module._owned_probes
    assert "unverified" in module.last_error


@pytest.mark.parametrize("setting,expected", [(True, True), (False, False), ("true", False), (1, False), (None, False)])
def test_kernel_only_requires_the_bound_runtime_chill_boolean(setting, expected):
    module = canary_drill.CanaryDrillModule()
    module.bind_manager(SimpleNamespace(config=SimpleNamespace(runtime_chill_active=setting)))
    assert module._kernel_only() is expected
    assert module.kernel_coverage_snapshot()["generic_coverage"] == ("deferred in Chill" if expected else "enabled")


def test_unscaled_control_tick_keeps_the_run_generations_immutable_stop_token(monkeypatch):
    module = canary_drill.CanaryDrillModule()
    waits, cycles = [], []
    replacement = SimpleNamespace(wait=lambda **_k: pytest.fail("control wait used a later generation"))

    def wait(*, timeout):
        waits.append(timeout)
        module._stop = replacement

    module._run_context.stop_event = SimpleNamespace(wait=wait)
    module._throttle = 1000.0
    module._priority_throttle = 500.0
    monkeypatch.setattr(module, "sleep", lambda *_a, **_k: pytest.fail("control tick inherited generic throttle"))
    monkeypatch.setattr(module, "mark_cycle_complete", lambda **kwargs: cycles.append(kwargs))
    module._wait_control_tick()
    module._wait_control_tick()
    assert waits == [1.0, 1.0] and cycles == [{"interval_seconds": 1.0}] * 2


def test_chill_without_native_receipts_never_launches_or_passes_a_generic_drill(monkeypatch):
    module = canary_drill.CanaryDrillModule()
    module.bind_manager(SimpleNamespace(config=SimpleNamespace(runtime_chill_active=True)))
    monkeypatch.setattr(canary_drill, "OwnedCanaryProcess", lambda *_a: pytest.fail("unavailable collectors launched a child"))
    monkeypatch.setattr(module, "emit", lambda *_a, **_k: None)
    assert module._fire_canary() is None
    snapshot = module.kernel_coverage_snapshot()
    assert snapshot["mode"] == "kernel-only" and snapshot["generic_coverage"] == "deferred in Chill"
    assert snapshot["generic_process_loop_caught"] == snapshot["kernel_probe_children_launched"] == 0
    assert module._drills_fired == 0 and module._expectations.pending_count() == 0
    assert {row["coverage_state"] for row in snapshot["providers"]} == {"unavailable"}
    assert all("no probe launched" in row["coverage_reason"] for row in snapshot["providers"])


@pytest.mark.parametrize("chill", [False, True])
def test_kernel_probe_continues_in_chill_while_generic_work_is_explicitly_deferred(monkeypatch, chill):
    clock = SimpleNamespace(now=100.0)
    monkeypatch.setattr(canary_drill, "time", SimpleNamespace(monotonic=lambda: clock.now, time=lambda: clock.now + 900))
    monkeypatch.setattr(canary_drill, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(canary_drill, "jittered", lambda value: value)
    module = canary_drill.CanaryDrillModule()
    module.bind_manager(SimpleNamespace(config=SimpleNamespace(runtime_chill_active=chill)))
    launched, generic, events = [], [], []

    def child(tag):
        launched.append(tag)
        return SimpleNamespace(identity=SimpleNamespace(pid=4321, birth_ticks=int(BIRTH) + 50_000_000),
                               retire=lambda **kwargs: {"native_wait_signaled": True, "owned_tree_empty": True}
                               if kwargs.get("cancel") else None)

    monkeypatch.setattr(canary_drill, "OwnedCanaryProcess", child)
    monkeypatch.setattr(module, "_native_receipts", lambda: receipts(now=clock.now))
    monkeypatch.setattr(module, "emit", lambda message, severity, **details: events.append((message, severity, details)))
    monkeypatch.setattr(module, "_collect_echoes", lambda: generic.append("echo") or [])
    monkeypatch.setattr(module, "_check_durable_receipts", lambda: generic.append("recorder") or [])
    monkeypatch.setattr(module, "_expire_pending", lambda: generic.append("deadline") or [])
    monkeypatch.setattr(module, "_check_sensor_coverage", lambda: generic.append("coverage"))
    module._next_coverage_check = clock.now

    def tick():
        clock.now += 1
        if clock.now >= 113:
            module._stop.set()

    monkeypatch.setattr(module, "_wait_control_tick", tick)
    module.run()
    assert len(launched) == 1 and module._kernel_probes_fired == 1
    assert module._drills_fired == (0 if chill else 1)
    assert bool(generic) is (not chill)
    assert bool(module._generic_pending_tags) is (not chill)
    if chill:
        assert module._expectations.pending_count() == 0 and not module._pending_pids
        assert "generic process/network/file/drill coverage deferred" in module.health_note
        assert not any("DRILL MISS" in row[0] or "COVERAGE" in row[0] for row in events)
    assert all(details.get("response_authorized", False) is False for _message, _severity, details in events)


def test_entering_chill_cancels_only_transient_generic_checks_and_resumes_with_warmup():
    module = canary_drill.CanaryDrillModule()
    assert module._expectations.arm(TAG, canary_drill._PROCESS_CONTRACT, now=100)
    module._generic_pending_tags.add(TAG)
    module._pending_pids[4321] = TAG
    module._pending_durable[TAG] = (1000, 106, "c" * 64)
    module._drills_fired = 1
    module._durable_misses = 2
    module._sensor_last_seen["AMSI Bridge"] = 1
    module._coverage_alerted.add("AMSI Bridge")
    module._echo_queue.put_nowait((TAG, 101, 1001, "c" * 64))
    module._sync_loop_mode(True, 102)
    assert module._expectations.pending_count() == 0 and not module._pending_pids
    assert not module._pending_durable and not module._generic_pending_tags and module._echo_queue.empty()
    assert module._generic_cancelled == 1 and module._durable_misses == 2
    module._sync_loop_mode(True, 103)
    assert module._generic_cancelled == 1
    module._sync_loop_mode(False, 104)
    assert not module._sensor_last_seen and not module._coverage_alerted
    assert module._next_coverage_check == 104 + canary_drill._SENSOR_WARMUP_S


def test_chill_ignores_polling_echo_but_retains_eligible_native_ingress(monkeypatch):
    monkeypatch.setattr(canary_drill, "time", SimpleNamespace(monotonic=lambda: 101.0, time=lambda: 1001.0))
    bus = EventBus()
    bus.arm(BusAuthority(b"j" * 32))
    module = canary_drill.CanaryDrillModule()
    module.bind(bus)
    module.bind_manager(SimpleNamespace(config=SimpleNamespace(runtime_chill_active=True)))
    module._native_receipt_cache = {row.provider: row for row in receipts()}
    bus.subscribe(module._on_event)
    bus.publish(Event("Telemetry Scanner", "polling", Severity.INFO, 1000.5,
                      {"type": "process_creation", "pid": 4321, "cmdline": TAG}))
    assert module._kernel_echo_queue.empty() and module._echo_queue.empty()
    bus.publish(Event(probe.PROVIDERS["kernel-etw"], "native", Severity.INFO, 1000.5,
                      {"source": "ETW:Kernel-Process", "event_type": "process_creation", "pid": 4321,
                       "cmdline": TAG, "collection_generation": "a" * 32}))
    assert module._kernel_echo_queue.qsize() == 1 and module._echo_queue.empty()
    assert module.self_test()[0] is True


@pytest.mark.parametrize("raw,expected", [
    (int(BIRTH), BIRTH), (BIRTH, BIRTH), (float(int(BIRTH)), None),
    (True, None), ("01" + BIRTH, None), ("2026-10-29 12:34:56", None), (10**400, None),
])
def test_kernel_adapter_preserves_only_exact_native_creation_ticks(raw, expected):
    sensor = object.__new__(etw_realtime_sensor.ETWProcessSensor)
    sensor._cache = SimpleNamespace(set=lambda *_args: None, get=lambda *_args: None)
    sensor._parse_failures = 0
    sensor._warn = lambda *_args: pytest.fail("inert parse unexpectedly failed")
    parsed = sensor._parse({"ProcessID": 4321, "ParentProcessID": 1, "ImageName": "inert.exe", "CreateTime": raw})
    assert parsed["process_birth_ticks"] == expected


@pytest.mark.parametrize("native_birth,expect_observed", [(BIRTH, True), (str(int(BIRTH) + 1), False)])
def test_kernel_payload_without_commandline_requires_exact_owned_pid_and_birth(monkeypatch, native_birth, expect_observed):
    monkeypatch.setattr(canary_drill, "time", SimpleNamespace(monotonic=lambda: 101.0, time=lambda: 1001.0))
    bus = EventBus()
    bus.arm(BusAuthority(b"p" * 32))
    module = canary_drill.CanaryDrillModule()
    module.bind(bus)
    module._kernel_tracker = armed()
    module._native_receipt_cache = {row.provider: row for row in receipts()}
    module._owned_probes[TAG] = (SimpleNamespace(identity=SimpleNamespace(pid=4321, birth_ticks=int(BIRTH))), 106)
    recorded = []
    module.bind_recorder(SimpleNamespace(bounded_events_in_window=lambda *_a, **_k: (recorded, len(recorded))))
    bus.subscribe(module._on_event)
    bus.publish(Event(probe.PROVIDERS["kernel-etw"], "inert no-commandline native echo", Severity.INFO, 1000.5,
                      {"source": "ETW:Kernel-Process", "event_type": "process_creation", "pid": 4321,
                       "process_birth_ticks": native_birth, "collection_generation": "a" * 32}))
    recorded[:] = [bus.recent(1)[0]]
    module._check_kernel_echoes()
    result = module._kernel_tracker.snapshot()
    assert bool(result) is expect_observed
    if expect_observed:
        assert result[0].correlation_basis == "native-pid-birth"


@pytest.mark.skipif(os.name != "nt", reason="Windows native owned child custody")
def test_actual_inert_probe_retires_its_exact_native_child_and_tree():
    child = probe.OwnedCanaryProcess(TAG)
    try:
        identity = child.identity
        assert identity.pid > 0 and str(identity.birth_ticks).isascii()
        receipt = None
        deadline = time.monotonic() + canary_drill.CANARY_TIMEOUT_S
        while receipt is None and time.monotonic() < deadline:
            receipt = child.retire()
            if receipt is None:
                time.sleep(0.05)
        # Cold interpreter startup and host scheduling need not finish within
        # the probe's observation window. Match its actual bounded retirement:
        # cancellation proves custody cleanup, never a successful sensor echo.
        cancelled = receipt is None
        if cancelled:
            receipt = child.retire(cancel=True)
        assert receipt is not None and receipt["cancellation_requested"] is cancelled
        if not cancelled:
            assert receipt["exit_code"] == 0
        assert receipt["pid"] == identity.pid and receipt["birth_ticks"] == str(identity.birth_ticks)
        assert receipt["native_wait_signaled"] and receipt["owned_tree_empty"]
        assert child.retire(cancel=True) is None
    finally:
        child.retire(cancel=True)


@pytest.mark.parametrize("running", [False, True])
def test_owned_probe_natural_and_cancelled_retirement_are_distinct_exact_receipts(monkeypatch, running):
    monkeypatch.setattr(probe, "os", SimpleNamespace(name="nt", environ={}))
    identity = SimpleNamespace(pid=4321, birth_ticks=int(BIRTH))
    calls = []

    class Child:
        pid = identity.pid
        _process = 123
        _handle_lock = threading.RLock()

        def __init__(self):
            self.running = running

        def poll(self):
            return None if self.running else 0

        def terminate(self):
            calls.append("terminate-owned-job")
            self.running = False

        def wait(self, *, timeout):
            calls.append("native-wait")
            assert not self.running
            return 1 if running else 0

        def wait_tree(self, *, timeout):
            calls.append("owned-tree-wait")

        def close(self):
            calls.append("close")

    native = SimpleNamespace(object_identity=lambda _h: (identity.pid, identity.birth_ticks),
                             identity=lambda _h: identity)
    child = probe.OwnedCanaryProcess(TAG, _native=native, _launch=lambda *_a, **_k: Child())
    receipt = child.retire()
    if running:
        assert receipt is None and calls == []
        receipt = child.retire(cancel=True)
    assert receipt["cancellation_requested"] is running
    assert receipt["native_wait_signaled"] and receipt["owned_tree_empty"]
    assert receipt["pid"] == identity.pid and receipt["birth_ticks"] == BIRTH
    assert calls == (["terminate-owned-job"] if running else []) + ["native-wait", "owned-tree-wait", "close"]
    assert child.retire(cancel=True) is None
