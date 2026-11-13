"""Initial retained-launch waiting never grants heartbeat health or duplicates."""
from __future__ import annotations

from types import SimpleNamespace
import threading

import pytest

from angerona.resilience import supervisor


class HeartbeatPath:
    present = False
    error = None

    def lstat(self):
        if self.error:
            raise self.error("inert private path error")
        if not self.present:
            raise FileNotFoundError
        return object()


class Reader:
    def __init__(self):
        self.path = HeartbeatPath()
        self.record = None
        self.auth = "authenticated"
        self.state = "alive"

    def read(self):
        return self.record

    def authentication_status(self, *, record):
        return self.auth

    def classify(self, *, stale_after_s):
        assert stale_after_s == 3.0
        return self.state


class Child:
    owns_descendants = True

    def __init__(self, pid):
        self.pid = pid
        self.identity = (object(), object(), object())
        self.code = None
        self.poll_error = False
        self.terminations = 0

    def poll(self):
        if self.poll_error:
            raise OSError("inert retained-owner error")
        return self.code

    def terminate(self):
        self.terminations += 1
        self.code = 0

    def wait(self, timeout=None):
        return self.code

    def wait_tree(self, timeout=None):
        assert self.code == 0

    def close(self):
        self.identity = None


@pytest.fixture
def harness(monkeypatch):
    mono, wall, launches, notices = [10.0], [1000.0], [], []
    reader = Reader()
    instance = supervisor.ProcessSupervisor(clock=lambda: wall[0], monotonic_clock=lambda: mono[0])
    component = supervisor.Component(name="core", argv=["fixed-runtime", "-m", "angerona"], reader=reader)
    instance.components["core"] = component
    monkeypatch.setattr(supervisor.tok, "is_standdown_requested", lambda: False)
    monkeypatch.setattr(instance, "_pop_restart_requests", lambda: set())
    monkeypatch.setattr(instance, "_capture_recovery_snapshot", lambda *_: None)
    monkeypatch.setattr(instance, "_persist", lambda _: True)
    monkeypatch.setattr(instance, "_emit", lambda level, message, **details:
                        notices.append((level, message, details)))
    monkeypatch.setattr(supervisor, "try_claim_spawn", lambda _: True)
    monkeypatch.setattr(supervisor, "_retained_startup_identity",
                        lambda proc: proc.identity if type(proc) is Child else None)
    monkeypatch.setattr(supervisor.threading, "Thread", lambda **_: SimpleNamespace(start=lambda: None))
    monkeypatch.setattr(supervisor.hb, "pid_alive", lambda _: True)
    monkeypatch.setattr(supervisor, "time", SimpleNamespace(time_ns=lambda: 10**12))

    def spawn(*_args, **_kwargs):
        child = Child(100 + len(launches))
        launches.append(child)
        return child

    monkeypatch.setattr(supervisor, "spawn_detached", spawn)
    assert instance._spawn(component)
    return SimpleNamespace(instance=instance, component=component, reader=reader,
                           mono=mono, wall=wall, launches=launches, notices=notices)


def test_owned_missing_first_heartbeat_does_not_become_three_startup_crashes(harness):
    h = harness
    deadline = h.component._startup.deadline
    for elapsed in (0.0, 1.0, 3.0, 6.0, 60.0, 179.0):
        h.mono[0], h.wall[0] = 10.0 + elapsed, 1000.0 + elapsed
        assert h.instance.tick()["core"] == "starting"
        assert h.instance._spawn(h.component) is True
        assert h.component._startup.deadline == deadline
    assert len(h.launches) == 1 and not h.component._failures
    assert not h.component.safe_mode and h.launches[0].terminations == 0
    assert not any(level == "CRITICAL" for level, *_ in h.notices)


def test_exact_deadline_retires_owned_child_before_budgeted_replacement(harness, monkeypatch):
    h = harness
    child, attempt = h.launches[0], h.component._startup
    h.mono[0], h.wall[0] = attempt.deadline, 1180.0
    retirement = []
    terminate, wait, wait_tree, close = child.terminate, child.wait, child.wait_tree, child.close

    def terminate_owned():
        retirement.append("terminate")
        terminate()

    def wait_owned(timeout=None):
        receipt = wait(timeout=timeout)
        assert type(receipt) is int and receipt == 0
        retirement.append(("wait", receipt))
        return receipt

    def wait_owned_tree(timeout=None):
        wait_tree(timeout=timeout)
        retirement.append("wait-tree")

    def close_owned():
        close()
        assert child.identity is None
        retirement.append("close")

    monkeypatch.setattr(child, "terminate", terminate_owned)
    monkeypatch.setattr(child, "wait", wait_owned)
    monkeypatch.setattr(child, "wait_tree", wait_owned_tree)
    monkeypatch.setattr(child, "close", close_owned)

    # Expiry grants no permission to bypass operator intent or source custody.
    monkeypatch.setattr(supervisor.tok, "is_standdown_requested", lambda: True)
    assert h.instance.tick()["core"] == "standdown"
    monkeypatch.setattr(supervisor.tok, "is_standdown_requested", lambda: False)
    h.instance.launch_guard = lambda _component: False
    assert h.instance.tick()["core"] == "startup-retirement-held"
    assert not retirement and not h.component._failures
    assert h.component.proc is child and h.component._startup is attempt
    h.instance.launch_guard = None

    assert h.instance.tick()["core"] == "backoff(dead)"
    assert retirement == ["terminate", ("wait", 0), "wait-tree", "close"]
    assert child.terminations == 1 and child.code == 0
    assert h.component.proc is None and h.component._startup is None
    assert attempt.failure_recorded and h.component._retained_exit_proven
    assert list(h.component._failures) == [1180.0] and len(h.component._pressure) == 1
    assert h.component.next_restart_at == 1181.0 and not h.component.safe_mode
    for elapsed in (0.0, 0.5):
        h.mono[0], h.wall[0] = attempt.deadline + elapsed, 1180.0 + elapsed
        assert h.instance.tick()["core"] == "backoff(dead)"
    assert len(h.launches) == 1 and child.terminations == 1
    assert list(h.component._failures) == [1180.0] and len(h.component._pressure) == 1

    launch = supervisor.spawn_detached

    def launch_after_retirement(*args, **kwargs):
        assert retirement == ["terminate", ("wait", 0), "wait-tree", "close"]
        assert h.component.proc is None and child.identity is None
        return launch(*args, **kwargs)

    monkeypatch.setattr(supervisor, "spawn_detached", launch_after_retirement)
    h.mono[0], h.wall[0] = attempt.deadline + 1.0, 1181.0
    assert h.instance.tick()["core"] == "respawned(dead)"
    assert len(h.launches) == 2 and h.component.proc is h.launches[1]
    assert h.component._startup is not attempt and h.instance._assess(h.component) == "starting"
    assert child.terminations == 1 and list(h.component._failures) == [1180.0]
    held = [row for row in h.notices if row[2].get("startup_state")]
    retired = [row for row in h.notices if row[2].get("startup_retired")]
    assert len(held) == 1 and held[0][2]["startup_state"] == "startup-timeout"
    assert len(retired) == 1 and retired[0][2]["response_authorized"] is False


@pytest.mark.parametrize("exit_code", [0, 1, -9], ids=["clean", "failure", "signal"])
def test_observed_owned_exit_is_immediate_even_before_waiter_sets_dead(harness, exit_code):
    h = harness
    h.launches[0].code = exit_code
    assert h.instance._assess(h.component) == "dead"
    assert h.instance.tick()["core"] == "backoff(dead)"
    assert list(h.component._failures) == [1000.0]


def test_waiter_dead_flag_is_not_masked_by_startup_window(harness):
    harness.component._dead = True
    assert harness.instance._assess(harness.component) == "dead"


def test_fresh_signed_bytes_do_not_consume_window_if_existing_classifier_is_not_alive(harness):
    h = harness
    h.reader.record = {"pid": 101, "flags": 1, "ts_ns": 10**12}
    h.reader.state = "suspended"
    attempt = h.component._startup
    assert h.instance._spawn(h.component) is False
    assert h.component._startup is attempt and len(h.launches) == 1


@pytest.mark.parametrize("state", ["dead", "suspended", "stopped", "unknown"])
def test_old_signed_nonready_record_is_not_new_launch_readiness(harness, state):
    h = harness
    h.reader.record = {"pid": 900, "flags": 1, "ts_ns": 0}
    h.reader.state = state
    attempt = h.component._startup
    assert h.instance._assess(h.component) == "startup-unavailable"
    assert h.component._startup is attempt
    assert h.instance._spawn(h.component) is False
    assert len(h.launches) == 1 and not h.component._failures
    h.reader.record = {"pid": 101, "flags": 1, "ts_ns": 10**12}
    h.reader.state = "alive"
    assert h.instance._assess(h.component) == "alive"
    assert h.component._startup is None
    h.reader.state = "suspended"
    assert h.instance._assess(h.component) == "suspended"


@pytest.mark.parametrize("auth", ["invalid", "legacy", "replay"])
def test_rejected_heartbeat_never_uses_starting_and_cannot_reset_window(harness, auth):
    h = harness
    h.reader.record = {"pid": 101, "flags": 1, "ts_ns": 10**12}
    h.reader.auth = auth
    attempt = h.component._startup
    expected = "legacy_unverified" if auth == "legacy" else "unauthenticated_" + auth
    assert h.instance._assess(h.component) == expected
    assert h.instance._spawn(h.component) is False
    h.reader.record = None
    assert h.instance._assess(h.component) == "startup-unavailable"
    assert h.component._startup is attempt and attempt.deadline == 190.0


@pytest.mark.parametrize("condition", ["present-malformed", "denied", "read-error"])
def test_none_from_reader_is_not_assumed_to_mean_absent_file(harness, condition):
    h = harness
    if condition == "present-malformed":
        h.reader.path.present = True
    else:
        h.reader.path.error = PermissionError if condition == "denied" else OSError
    assert h.instance.tick()["core"] == "startup-unavailable"
    assert len(h.launches) == 1 and not h.component._failures
    h.reader.path.present, h.reader.path.error = False, None
    assert h.instance.tick()["core"] == "startup-unavailable"


@pytest.mark.parametrize("change", ["process", "process-handle-or-job", "closed-owner", "poll-error"])
def test_replaced_or_unavailable_retained_custody_is_held_not_adopted(harness, change):
    h = harness
    attempt = h.component._startup
    if change == "process":
        h.component.proc = Child(h.component.proc.pid)  # Same number grants no ownership.
    elif change == "process-handle-or-job":
        h.component.proc.identity = (object(), object(), object())
    elif change == "closed-owner":
        h.component.proc.identity = None
    else:
        h.component.proc.poll_error = True
    assert h.instance.tick()["core"] == "startup-unavailable"
    assert h.instance._spawn(h.component) is False
    assert h.component._startup is attempt and len(h.launches) == 1


@pytest.mark.parametrize("bad_clock", [True, float("nan"), -1.0, 9.0],
                         ids=["bool", "nan", "negative", "regressed"])
def test_clock_failure_cannot_renew_or_resume_initial_window(harness, bad_clock):
    h = harness
    deadline = h.component._startup.deadline
    h.mono[0] = bad_clock
    assert h.instance.tick()["core"] == "startup-unavailable"
    h.mono[0] = 11.0
    assert h.instance.tick()["core"] == "startup-unavailable"
    assert h.component._startup.deadline == deadline and len(h.launches) == 1


def test_wall_clock_adjustment_does_not_change_monotonic_startup_budget(harness):
    h = harness
    deadline = h.component._startup.deadline
    for wall_time in (0.0, 10**10):
        h.wall[0] = wall_time
        h.mono[0] += 1
        assert h.instance.tick()["core"] == "starting"
        assert h.component._startup.deadline == deadline and len(h.launches) == 1


def test_an_unowned_pid_never_acquires_a_startup_window(harness):
    h = harness
    h.component._startup = None
    h.component.proc = Child(100)
    h.component.adopted = True
    assert h.instance._assess(h.component) == "dead"
    assert h.component._startup is None


def test_stop_stands_down_then_uses_existing_owned_cleanup(harness):
    h = harness
    h.instance._stop.set()
    assert h.instance.tick() == {"core": "standdown"}
    assert len(h.launches) == 1 and not h.component._failures
    h.instance.stop()
    assert h.launches[0].terminations == 1
    assert h.component.proc is None and h.component._startup is None


def test_authenticated_manual_restart_can_replace_the_held_owned_generation(harness, monkeypatch):
    h = harness
    h.mono[0] = 200.0
    assert h.instance._assess(h.component) == "startup-timeout"
    monkeypatch.setattr(h.instance, "_pop_restart_requests", lambda: {"core"})
    assert h.instance.tick()["core"] == "manual_restart"
    assert h.launches[0].terminations == 1 and len(h.launches) == 2
    assert h.component._startup.proc is h.launches[1]
    assert h.component._startup.deadline == 380.0


def test_windows_launch_identity_requires_exact_retained_owner_without_native_calls(monkeypatch):
    from angerona.core.windows_child_job import OwnedWindowsChild

    monkeypatch.setattr(supervisor, "os", SimpleNamespace(name="nt"))
    child = OwnedWindowsChild.__new__(OwnedWindowsChild)
    child._process, child._job = object(), SimpleNamespace(_handle=object())
    child._handle_lock = SimpleNamespace(acquire=lambda **_: True, release=lambda: None)
    identity = supervisor._retained_startup_identity(child)
    assert identity[0] is child._process and identity[1] is child._job and identity[2] is child._job._handle
    assert supervisor._retained_startup_identity(SimpleNamespace(owns_descendants=True, pid=100)) is None
    child._job._handle = None
    assert supervisor._retained_startup_identity(child) is None
    child._handle_lock = SimpleNamespace(acquire=lambda **_: False)
    assert supervisor._retained_startup_identity(child) is None


def test_waiter_error_does_not_poison_live_startup_or_disclose_native_error(harness):
    h = harness
    attempt = h.component._startup

    def failed_wait():
        raise OSError("inert private native-handle duplication detail")

    h.launches[0].wait = failed_wait
    h.instance._waiter(h.component, h.launches[0])
    assert h.component._dead is False and h.component._startup is attempt
    assert h.instance._assess(h.component) == "starting"
    gaps = [row for row in h.notices if "wait_observation" in row[2]]
    assert len(gaps) == 1 and gaps[0][2]["wait_observation"] == "unavailable"
    assert "private" not in str(gaps)


@pytest.mark.parametrize("result", [None, True, False, 0.0, "0", object()],
                         ids=["none", "true", "false", "float", "text", "object"])
def test_waiter_requires_strict_integer_exit_receipt(harness, result):
    h = harness
    h.launches[0].wait = lambda: result
    h.instance._waiter(h.component, h.launches[0])
    assert h.component._dead is False
    assert h.instance._assess(h.component) == "starting"
    assert any(row[2].get("wait_observation") == "invalid-result" for row in h.notices)


@pytest.mark.parametrize("result", [0, 7, -9], ids=["clean", "failure", "signal"])
def test_successful_integer_wait_publishes_death_for_its_current_generation(harness, result):
    h = harness
    h.launches[0].wait = lambda: result
    h.instance._waiter(h.component, h.launches[0])
    assert h.component._dead is True
    assert h.instance._assess(h.component) == "dead"


def test_waiter_never_holds_lifecycle_lock_across_wait(harness):
    h = harness
    events = []

    class Lock:
        held = False

        def __enter__(self):
            self.held = True
            events.append("lock")

        def __exit__(self, *_):
            self.held = False
            events.append("unlock")

    lock = Lock()
    h.instance._lifecycle_lock = lock

    def wait():
        assert lock.held is False
        events.append("wait")
        return 0

    h.launches[0].wait = wait
    h.instance._waiter(h.component, h.launches[0])
    assert events == ["wait", "lock", "unlock"]
    assert h.component._dead is True


def test_waiter_comparison_and_death_publication_serialize_with_replacement():
    """Replay the check-to-assignment interleaving without scheduler timing."""
    comparison_seen, replacement_done = threading.Event(), threading.Event()
    original, replacement = object(), object()

    class LifecycleLock:
        def __init__(self):
            self.lock = threading.RLock()
            self.local = threading.local()

        def __enter__(self):
            self.lock.acquire()
            self.local.held = True

        def __exit__(self, *_):
            self.local.held = False
            self.lock.release()

        def held_here(self):
            return bool(getattr(self.local, "held", False))

    lock = LifecycleLock()

    class RacingComponent:
        name = "core"

        def __init__(self):
            self.current, self._dead = original, False

        @property
        def proc(self):
            observed = self.current
            comparison_seen.set()
            if not lock.held_here():
                # Before the fix this returns the old owner after another
                # thread has installed a new one, exposing the stale write.
                assert replacement_done.wait(10)
            return observed

    component = RacingComponent()
    instance = supervisor.ProcessSupervisor()
    instance._lifecycle_lock = lock
    instance._emit = lambda *_args, **_kwargs: pytest.fail("valid wait must not report a gap")
    failures = []

    def replace():
        try:
            if not comparison_seen.wait(10):
                raise AssertionError("waiter did not perform its owner comparison")
            with lock:
                component.current, component._dead = replacement, False
        except BaseException as error:
            failures.append(error)
        finally:
            replacement_done.set()

    replacer = threading.Thread(target=replace, name="inert-supervisor-replacement-test")
    replacer.start()

    class WaitedOwner:
        def wait(self):
            assert not lock.held_here()
            return 0

    waited = WaitedOwner()
    component.current = waited
    try:
        instance._waiter(component, waited)
        assert replacement_done.wait(10)
    finally:
        comparison_seen.set()
        replacer.join(timeout=10)
    assert not replacer.is_alive() and not failures
    assert component.current is replacement and component._dead is False
