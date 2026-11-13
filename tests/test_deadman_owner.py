from __future__ import annotations

import threading
import time
from types import SimpleNamespace

from angerona.resilience import deadman, watchdog


NAMES = tuple(name for name, _direction in deadman.RULES)


def wait_for(predicate):
    deadline = time.monotonic() + 2.0
    while not predicate():
        assert time.monotonic() < deadline, "inert owner did not reach its bounded fixture state"
        time.sleep(0.005)


class Firewall:
    def __init__(self, rules=()):
        self.rules = set(rules)
        self.calls = []
        self.fail_delete = False
        self.block_add = False
        self.entered, self.release = threading.Event(), threading.Event()

    def probe(self):
        return {name: deadman.PRESENT if name in self.rules else deadman.ABSENT for name in NAMES}

    def run(self, arguments):
        name = next(value[5:] for value in arguments if value.startswith("name="))
        verb = arguments[2]
        self.calls.append((verb, name, threading.get_ident()))
        assert verb in ("add", "delete") and name in NAMES
        if verb == "add":
            if self.block_add:
                self.entered.set()
                assert self.release.wait(1.0), "inert dispatched add was not released"
            self.rules.add(name)
            return True
        if self.fail_delete:
            return False
        self.rules.discard(name)
        return True


def make_owner(firewall, *, policy=None):
    clock, events, values = [0.0], [], []

    def factory(publish, **kwargs):
        value = deadman.DeadMan(publish, policy=lambda: policy, is_admin=lambda: True, **kwargs)
        values.append(value)
        return value

    owner = deadman.DeadManOwner(lambda *args: events.append(args), factory=factory,
                                 runner=firewall.run, probe=firewall.probe, clock=lambda: clock[0])
    owner.start()
    return owner, clock, events, values


def retire(owner, clock, firewall=None):
    if firewall:
        firewall.release.set()
    owner.request_stop("inert fixture retirement")
    clock[0] += 61
    owner.request_stop("inert fixture retirement")
    assert owner.join(2.0), "inert owner thread remains unretired"


def test_stop_fence_compensates_an_already_dispatched_add_without_second_add():
    firewall = Firewall()
    owner, clock, events, _values = make_owner(firewall, policy={"enabled": True, "threshold_s": 1.0})
    try:
        owner.submit("dead")
        wait_for(lambda: owner.snapshot()["state"] == "armed")
        clock[0] = 2.0
        firewall.block_add = True
        owner.submit("dead")
        assert firewall.entered.wait(1.0)
        owner.request_stop("authenticated stand-down")
        assert owner.submit("dead") is False
        assert owner.submit("alive") is False
        firewall.release.set()
        wait_for(lambda: owner.done)
        assert not firewall.rules
        assert [verb for verb, _name, _thread in firewall.calls].count("add") == 1
        assert all(identity != threading.get_ident() for _verb, _name, identity in firewall.calls)
        assert not any(details.get("deadman") == "engaged" for _level, _message, details in events)
        assert owner.snapshot()["cleanup_pending"] is False
    finally:
        retire(owner, clock, firewall)


def test_coalesced_alive_boundary_cancels_old_engagement_and_resets_next_outage():
    firewall = Firewall()
    owner, clock, _events, values = make_owner(firewall, policy={"enabled": True, "threshold_s": 1.0})
    try:
        owner.submit("dead")
        wait_for(lambda: owner.snapshot()["state"] == "armed")
        clock[0] = 2.0
        firewall.block_add = True
        owner.submit("dead")
        assert firewall.entered.wait(1.0)
        # These must return while the native stand-in is still blocked. The
        # intermediate alive boundary cannot vanish when the latest state wins.
        owner.submit("alive")
        clock[0] = 100.0
        owner.submit("dead")
        firewall.release.set()
        wait_for(lambda: values[0]._down_since == 100.0 and owner.snapshot()["state"] == "armed")
        assert not firewall.rules
        assert [verb for verb, _name, _thread in firewall.calls].count("add") == 1
    finally:
        retire(owner, clock, firewall)


def test_shutdown_retries_cleanup_then_preserves_explicit_failure_at_deadline():
    firewall = Firewall((NAMES[0],))
    firewall.fail_delete = True
    owner, clock, events, _values = make_owner(firewall)
    try:
        owner.submit("dead")
        wait_for(lambda: len(firewall.calls) >= 1)
        owner.request_stop("authenticated stand-down")
        wait_for(lambda: len(firewall.calls) >= 2)
        first_deadline = owner._deadline
        clock[0] = 16.0
        owner.request_stop("authenticated stand-down")
        wait_for(lambda: len(firewall.calls) >= 3)
        assert not owner.done and owner._deadline == first_deadline
        clock[0] = 61.0
        owner.request_stop("authenticated stand-down")
        wait_for(lambda: owner.done)
        assert firewall.rules == {NAMES[0]}
        assert owner.snapshot()["state"] == "cleanup-unresolved"
        assert owner.snapshot()["cleanup_pending"] is True
        assert owner.snapshot()["worker_retired"] is True
        assert any(details.get("deadman") == "cleanup_unresolved" for _level, _message, details in events)
        assert not any(details.get("deadman") == "released" for _level, _message, details in events)
    finally:
        retire(owner, clock, firewall)


def test_stop_before_first_normal_work_cannot_be_overwritten():
    firewall = Firewall()
    owner, clock, _events, _values = make_owner(firewall, policy={"enabled": True, "threshold_s": 1.0})
    try:
        owner.request_stop("authenticated stand-down")
        assert owner.submit("dead") is False
        wait_for(lambda: owner.done)
        assert not firewall.calls and not firewall.rules
        assert owner.snapshot()["cleanup_pending"] is False
    finally:
        retire(owner, clock, firewall)


def test_watchdog_shutdown_wait_keeps_pulses_responsive(monkeypatch):
    pulses, sleeps, published = [], [], []

    class Owner:
        done = False

        def request_stop(self, reason):
            self.reason = reason

        def shutdown_expired(self, grace=0.0):
            return False

        def join(self, timeout=0.0):
            assert timeout == 0.0
            return self.done

    owner = Owner()

    def sleep(seconds):
        sleeps.append(seconds)
        if len(sleeps) == 3:
            owner.done = True

    monkeypatch.setattr(watchdog, "time", SimpleNamespace(sleep=sleep))
    monkeypatch.setattr(watchdog, "_refresh_heartbeat", lambda writer: pulses.append(writer) or writer)
    writer = object()
    result = watchdog._finish_deadman(owner, SimpleNamespace(heartbeat_allowed=lambda: True), writer,
                                     lambda *args: published.append(args), "authenticated stand-down")
    assert result is writer and len(pulses) == len(sleeps) == 3
    assert owner.reason == "authenticated stand-down" and not published


def test_native_call_timeouts_use_remaining_stop_budget_and_no_late_add(monkeypatch):
    clock, calls = [0.0], []
    owner = deadman.DeadManOwner(lambda *_args: None, clock=lambda: clock[0])
    owner.submit("dead")
    owner._work_epoch = owner._latest[1]
    owner.request_stop("authenticated stand-down")
    clock[0] = 58.0
    monkeypatch.setattr(deadman, "_netsh", lambda args, *, timeout: calls.append(("mutation", timeout)) or True)
    monkeypatch.setattr(deadman, "_query_owned_rules", lambda *, timeout: calls.append(("query", timeout)) or {})
    assert owner._mutate(["advfirewall", "firewall", "add"]) is False
    assert owner._mutate(["advfirewall", "firewall", "delete"]) is True
    owner._query()
    assert calls == [("mutation", 2.0), ("query", 2.0)]
    clock[0] = 60.0
    try:
        owner._mutate(["advfirewall", "firewall", "delete"])
    except TimeoutError:
        pass
    else:
        raise AssertionError("native work admitted beyond STOP budget")
    assert len(calls) == 2


def test_watchdog_shutdown_deadline_preserves_unretired_cleanup_evidence(monkeypatch):
    published = []
    owner = SimpleNamespace(
        done=False, request_stop=lambda _reason: None, shutdown_expired=lambda **_kwargs: True,
        join=lambda **_kwargs: False, snapshot=lambda: {"owned_rule_evidence": True},
    )
    monkeypatch.setattr(watchdog, "_refresh_heartbeat", lambda _writer: (_ for _ in ()).throw(
        AssertionError("No heartbeat wait belongs beyond the fixed shutdown deadline")))
    writer = object()
    assert watchdog._finish_deadman(owner, SimpleNamespace(heartbeat_allowed=lambda: True), writer,
                                    lambda *args: published.append(args), "authenticated stand-down") is writer
    [level, _message, details] = published[0]
    assert level == "CRITICAL" and details["cleanup_pending"] is True
    assert details["worker_retired"] is False and details["enforcement_verified"] is False
    assert details["response_authorized"] is False


def test_unavailable_pulse_does_not_skip_bounded_owner_retirement(monkeypatch):
    published, sleeps = [], []
    owner = SimpleNamespace(done=False, request_stop=lambda _reason: None,
                            shutdown_expired=lambda **_kwargs: False, join=lambda **_kwargs: True)

    def sleep(_seconds):
        sleeps.append(True)
        if len(sleeps) == 3:
            owner.done = True

    def unavailable(_writer):
        raise OSError("inert heartbeat mapping unavailable")

    monkeypatch.setattr(watchdog, "time", SimpleNamespace(sleep=sleep))
    monkeypatch.setattr(watchdog, "_refresh_heartbeat", unavailable)
    writer = object()
    assert watchdog._finish_deadman(owner, SimpleNamespace(heartbeat_allowed=lambda: True), writer,
                                    lambda *args: published.append(args), "authenticated stand-down") is writer
    assert len(sleeps) == 3 and len(published) == 1
    assert published[0][2]["heartbeat_unavailable"] is True
    assert published[0][2]["response_authorized"] is False
