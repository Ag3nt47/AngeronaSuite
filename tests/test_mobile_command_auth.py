"""Fake-only protected mobile admission contracts; no OS credential access."""
from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import FrozenInstanceError
from types import SimpleNamespace

import pytest

from angerona.core import mobile_command_auth as auth


class _Crash(BaseException):
    pass


class _Clock:
    def __init__(self):
        self.wall = 1_700_000_000.0
        self.monotonic = 100.0

    def advance(self, seconds):
        self.wall += seconds
        self.monotonic += seconds


class _Store:
    def __init__(self):
        self.values = {}
        self.writes = []
        self.write_calls = 0
        self.read_calls = 0
        self.fail_before = set()
        self.fail_after = set()
        self.crash_after = set()
        self.exit_failure_once = False
        self.ignore_write = set()
        self._lock = threading.RLock()
        self._local = threading.local()

    @property
    def depth(self):
        return getattr(self._local, "depth", 0)

    @contextmanager
    def transaction(self, _root=None):
        with self._lock:
            previous = self.depth
            self._local.depth = previous + 1
            try:
                yield
            finally:
                self._local.depth = previous
            if not previous and self.exit_failure_once:
                self.exit_failure_once = False
                raise OSError("inert lease retirement uncertainty")

    def read(self, names, _root=None, *, strict=False):
        assert strict is True
        assert self.depth > 0
        self.read_calls += 1
        return {name: self.values[name] for name in names if name in self.values}

    def write(self, updates, _root=None):
        assert self.depth > 0
        assert set(updates) <= set(auth.MOBILE_AUTH_SECRET_NAMES)
        self.write_calls += 1
        current = self.write_calls
        if current in self.fail_before:
            raise OSError("inert prepublication failure")
        if current not in self.ignore_write:
            for name, value in updates.items():
                if value in (None, ""):
                    self.values.pop(name, None)
                else:
                    self.values[name] = value
        self.writes.append(dict(updates))
        if current in self.crash_after:
            raise _Crash("inert termination after publication")
        if current in self.fail_after:
            raise OSError("inert postpublication uncertainty")

    def state(self):
        return json.loads(self.values[auth.MOBILE_AUTH_STATE_SECRET])


@pytest.fixture
def harness(monkeypatch, tmp_path):
    store, clock = _Store(), _Clock()
    monkeypatch.setattr(auth, "secret_transaction", store.transaction)
    monkeypatch.setattr(auth, "read_secret_values", store.read)
    monkeypatch.setattr(auth, "write_secret_map", store.write)
    scope = {
        "cli": r"C:\Trusted\signal-cli.exe", "host": "+13035550100",
        "dest": "+13035550199", "sha256": "a" * 64, "publisher": "CN=Inert Test Publisher",
    }

    def make(**changes):
        return auth.MobileCommandAuthorization(
            tmp_path / "unused-fake-store", scope={**scope, **changes},
            clock=lambda: clock.wall, monotonic=lambda: clock.monotonic,
        )

    return SimpleNamespace(store=store, clock=clock, scope=scope, make=make)


def _arm(h):
    helper = h.make()
    status = helper.rearm_local("123456", "123456")
    assert status.ready
    return helper, status.generation


def test_missing_state_and_environment_never_initialize_or_authorize(harness, monkeypatch):
    h = harness
    monkeypatch.setenv(auth.MOBILE_PIN_SECRET, "123456")
    monkeypatch.setenv(auth.LEGACY_MOBILE_PIN_SECRET, "inert-legacy-blob")
    helper = h.make()
    assert not helper.status().ready
    assert not helper.verify_pin("123456", expected_generation="a" * 64).authorized
    assert helper.read_pin() is None
    assert auth.read_pin() is None
    assert h.store.values == {}
    assert not h.store.writes


@pytest.mark.parametrize("pin,confirmation", [
    ("1234", "1234"), ("12345", "12345"), ("1" * 13, "1" * 13),
    ("１２３４５６", "１２３４５６"), ("123456 ", "123456 "), ("123456", "654321"),
])
def test_local_rearm_requires_strong_ascii_confirmation(harness, pin, confirmation):
    assert not harness.make().rearm_local(pin, confirmation).ready
    assert not harness.store.writes


def test_rearm_atomically_replaces_pin_state_and_legacy_without_other_secrets(harness):
    h = harness
    h.store.values.update({"UNRELATED_FAKE_SECRET": "preserve", auth.LEGACY_MOBILE_PIN_SECRET: "old"})
    helper, generation = _arm(h)
    assert len(h.store.writes) == 1
    assert set(h.store.writes[0]) == set(auth.MOBILE_AUTH_SECRET_NAMES)
    assert auth.LEGACY_MOBILE_PIN_SECRET not in h.store.values
    assert h.store.values["UNRELATED_FAKE_SECRET"] == "preserve"
    assert helper.read_pin() == "123456"
    assert h.store.state()["generation"] == generation
    with pytest.raises(FrozenInstanceError):
        helper.status().ready = False


def test_only_new_format_protected_pin_is_read(harness):
    h = harness
    h.store.values[auth.MOBILE_PIN_SECRET] = "1234"
    assert h.make().read_pin() is None
    h.store.values[auth.MOBILE_PIN_SECRET] = "123456"
    assert h.make().read_pin() == "123456"
    assert not h.make().status().ready


def test_comparison_requires_verified_failure_reservation_and_outer_lease(harness, monkeypatch):
    h = harness
    helper, generation = _arm(h)
    original = auth.hmac
    comparisons = []

    def compare(a, b):
        if type(a) is bytes and type(b) is bytes:
            assert h.store.depth > 0
            state = h.store.state()
            assert state["failures"] == 1
            assert state["reservation"]["prior_failures"] == 0
            comparisons.append((len(a), len(b)))
        return original.compare_digest(a, b)

    monkeypatch.setattr(auth, "hmac", SimpleNamespace(new=original.new, compare_digest=compare))
    result = helper.verify_pin("123456", expected_generation=generation)
    assert result.authorized
    assert comparisons == [(6, 6)]
    assert h.store.write_calls == 3
    assert h.store.state()["failures"] == 0
    assert h.store.state()["reservation"] is None


def test_wrong_pin_persists_backoff_and_success_never_erases_old_failure(harness):
    h = harness
    helper, generation = _arm(h)
    wrong = helper.verify_pin("000000", expected_generation=generation)
    assert not wrong.authorized and wrong.failures == 1
    assert wrong.retry_after_s == pytest.approx(5)
    restarted = h.make()
    assert restarted.status().retry_after_s == pytest.approx(5)
    before = h.store.write_calls
    assert not restarted.verify_pin("123456", expected_generation=generation).authorized
    assert h.store.write_calls == before
    h.clock.advance(5)
    result = restarted.verify_pin("123456", expected_generation=generation)
    assert result.authorized and result.failures == 1
    assert h.store.state()["failures"] == 1


def test_cumulative_ten_failure_latch_survives_restart_and_requires_local_rearm(harness):
    h = harness
    helper, generation = _arm(h)
    for count in range(1, 11):
        result = helper.verify_pin("000000", expected_generation=generation)
        assert not result.authorized and result.failures == count
        h.clock.advance(min(900, 5 * 2 ** (count - 1)))
    assert h.make().status().locked
    h.clock.advance(100_000)
    before = h.store.write_calls
    assert not h.make().verify_pin("123456", expected_generation=generation).authorized
    assert h.store.write_calls == before
    rearmed = helper.rearm_local("654321", "654321")
    assert rearmed.ready and rearmed.failures == 0 and rearmed.generation != generation
    assert not helper.verify_pin("654321", expected_generation=generation).authorized
    assert helper.verify_pin("654321", expected_generation=rearmed.generation).authorized


def test_correct_tenth_reservation_releases_only_its_own_charge(harness):
    h = harness
    helper, generation = _arm(h)
    for count in range(1, 10):
        assert not helper.verify_pin("000000", expected_generation=generation).authorized
        h.clock.advance(min(900, 5 * 2 ** (count - 1)))
    result = helper.verify_pin("123456", expected_generation=generation)
    assert result.authorized and result.failures == 9
    assert not helper.status().locked
    assert h.store.state()["failures"] == 9


def test_crash_after_reservation_keeps_charge_for_next_process(harness):
    h = harness
    helper, generation = _arm(h)
    h.store.crash_after.add(h.store.write_calls + 1)
    with pytest.raises(_Crash):
        helper.verify_pin("123456", expected_generation=generation)
    assert h.store.state()["failures"] == 1
    assert h.store.state()["reservation"] is not None
    restarted = h.make()
    assert restarted.status().retry_after_s == pytest.approx(5)
    h.clock.advance(5)
    assert restarted.verify_pin("123456", expected_generation=generation).failures == 1


@pytest.mark.parametrize("fault", ["before", "after", "ignored"])
def test_unverified_reservation_never_compares_pin_or_authorizes(harness, monkeypatch, fault):
    h = harness
    helper, generation = _arm(h)
    next_write = h.store.write_calls + 1
    {"before": h.store.fail_before, "after": h.store.fail_after, "ignored": h.store.ignore_write}[fault].add(next_write)
    original = auth.hmac

    def compare(a, b):
        assert not (type(a) is bytes and type(b) is bytes), "PIN compared before verified charge"
        return original.compare_digest(a, b)

    monkeypatch.setattr(auth, "hmac", SimpleNamespace(new=original.new, compare_digest=compare))
    assert not helper.verify_pin("123456", expected_generation=generation).authorized
    assert not helper.status().ready


def test_failed_completion_does_not_authorize_and_retains_reserved_charge(harness):
    h = harness
    helper, generation = _arm(h)
    h.store.fail_before.add(h.store.write_calls + 2)
    assert not helper.verify_pin("123456", expected_generation=generation).authorized
    assert h.store.state()["failures"] == 1
    assert h.store.state()["reservation"] is not None
    assert not helper.status().ready


def test_lease_retirement_failure_never_returns_success(harness):
    h = harness
    helper, generation = _arm(h)
    h.store.exit_failure_once = True
    assert not helper.verify_pin("123456", expected_generation=generation).authorized
    assert not helper.status().ready
    assert helper.rearm_local("123456", "123456").ready


def test_scope_or_protected_pin_change_holds_without_automatic_reset(harness):
    h = harness
    helper, generation = _arm(h)
    before = h.store.write_calls
    changed_scope = h.make(dest="+13035550198")
    assert "scope-changed" in changed_scope.status().reason
    assert not changed_scope.verify_pin("123456", expected_generation=generation).authorized
    h.store.values[auth.MOBILE_PIN_SECRET] = "654321"
    assert "pin-changed" in helper.status().reason
    assert not helper.verify_pin("654321", expected_generation=generation).authorized
    assert h.store.write_calls == before


@pytest.mark.parametrize("change", [
    {"schema": True}, {"schema": 2}, {"failures": True}, {"failures": -1}, {"failures": 11},
    {"wall_high_water_ms": float("nan")}, {"next_attempt_ms": float("inf")},
    {"next_attempt_ms": 253_402_300_799_999}, {"extra": "unknown"},
    {"reservation": {"id": "a" * 32, "generation": "b" * 64, "prior_failures": 0}},
])
def test_malformed_state_is_held_and_preserved(harness, change):
    h = harness
    helper, generation = _arm(h)
    state = {**h.store.state(), **change}
    raw = json.dumps(state)
    h.store.values[auth.MOBILE_AUTH_STATE_SECRET] = raw
    before = h.store.write_calls
    assert not helper.status().ready
    assert not helper.verify_pin("123456", expected_generation=generation).authorized
    assert h.store.values[auth.MOBILE_AUTH_STATE_SECRET] == raw
    assert h.store.write_calls == before


@pytest.mark.parametrize("raw", ['{"schema":1,"schema":1}', "x" * 8193, "[]", "null"])
def test_duplicate_oversize_and_nonobject_state_never_initialize(harness, raw):
    h = harness
    h.store.values.update({auth.MOBILE_AUTH_STATE_SECRET: raw, auth.MOBILE_PIN_SECRET: "123456"})
    assert not h.make().status().ready
    assert h.store.values[auth.MOBILE_AUTH_STATE_SECRET] == raw
    assert not h.store.writes


def test_observed_wall_rollback_latches_even_after_clock_is_restored_and_restart(harness):
    h = harness
    helper, _generation = _arm(h)
    h.clock.wall -= 1
    assert "clock-rollback" in helper.status().reason
    assert h.store.state()["held_reason"] == "clock-rollback"
    h.clock.advance(100)
    assert not h.make().status().ready
    assert helper.rearm_local("123456", "123456").ready


def test_forward_wall_jump_cannot_shorten_session_monotonic_cooldown(harness):
    h = harness
    helper, generation = _arm(h)
    assert not helper.verify_pin("000000", expected_generation=generation).authorized
    h.clock.wall += 3600
    assert helper.status().retry_after_s == pytest.approx(5)
    assert not helper.verify_pin("123456", expected_generation=generation).authorized
    h.clock.monotonic += 5
    assert helper.verify_pin("123456", expected_generation=generation).authorized


def test_monotonic_rollback_latches_persistently(harness):
    h = harness
    helper, _generation = _arm(h)
    h.clock.monotonic -= 1
    assert "clock-rollback" in helper.status().reason
    assert not h.make().status().ready


def test_clock_rollback_during_correct_comparison_cannot_authorize(harness, monkeypatch):
    h = harness
    helper, generation = _arm(h)
    original = auth.hmac

    def compare(a, b):
        if type(a) is bytes and type(b) is bytes:
            h.clock.wall -= 1
        return original.compare_digest(a, b)

    monkeypatch.setattr(auth, "hmac", SimpleNamespace(new=original.new, compare_digest=compare))
    assert not helper.verify_pin("123456", expected_generation=generation).authorized
    assert h.store.state()["failures"] == 1
    assert h.store.state()["held_reason"] == "clock-rollback"


@pytest.mark.parametrize("given", ["１２３４５６", "123456 ", "9" * 1000, None])
def test_invalid_pin_input_is_charged_without_comparison_type_errors(harness, given):
    h = harness
    helper, generation = _arm(h)
    result = helper.verify_pin(given, expected_generation=generation)
    assert not result.authorized and result.failures == 1
    assert h.store.state()["failures"] == 1


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), True, -1, 10 ** 20])
def test_invalid_clock_cannot_rearm(harness, bad):
    harness.clock.wall = bad
    assert not harness.make().rearm_local("123456", "123456").ready
    assert not harness.store.writes


def test_competing_helpers_serialize_one_failure_and_share_backoff(harness):
    h = harness
    _helper, generation = _arm(h)
    first, second = h.make(), h.make()
    barrier = threading.Barrier(2)

    def attempt(helper):
        barrier.wait(timeout=5)
        return helper.verify_pin("000000", expected_generation=generation)

    with ThreadPoolExecutor(max_workers=2) as workers:
        futures = [workers.submit(attempt, helper) for helper in (first, second)]
        results = [future.result(timeout=5) for future in futures]
    assert not any(result.authorized for result in results)
    assert {result.reason for result in results} == {"incorrect-pin", "retry-backoff"}
    assert h.store.state()["failures"] == 1
    assert h.store.write_calls == 2


@pytest.mark.parametrize("change", [
    {"host": "+13035550199"}, {"host": "13035550100"}, {"sha256": "x" * 64},
    {"publisher": ""}, {"cli": "C:\\bad\npath"}, {"dest": False},
])
def test_invalid_scope_is_rejected_without_accessing_credentials(harness, change):
    with pytest.raises(ValueError):
        harness.make(**change)
    assert harness.store.read_calls == 0
    assert not harness.store.writes


def test_digest_binding_is_stable_and_state_writes_are_narrow(harness):
    h = harness
    helper, generation = _arm(h)
    reordered = dict(reversed(list(h.scope.items())))
    equivalent = auth.MobileCommandAuthorization(
        scope={**reordered, "sha256": "A" * 64},
        clock=lambda: h.clock.wall, monotonic=lambda: h.clock.monotonic,
    )
    assert equivalent.scope_digest == helper.scope_digest
    h.store.values["NEW_UNRELATED_FAKE_SECRET"] = "concurrent-change"
    assert not helper.verify_pin("000000", expected_generation=generation).authorized
    assert set(h.store.writes[-1]) == {auth.MOBILE_AUTH_STATE_SECRET}
    assert h.store.values["NEW_UNRELATED_FAKE_SECRET"] == "concurrent-change"
