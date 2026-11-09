"""Strict ownership deadlines retain their original input across float rounding.

All native operations below use the existing opaque-token fixtures. No Windows
handle or user process is opened, changed or terminated by these cases.
"""
from __future__ import annotations

import math

import pytest

from test_child_job_owned_identities import inert_child_factory
from test_process_snapshot_owned_identities import inert_owner

from angerona.core import windows_child_job
from angerona.telemetry import process_snapshot_worker


class _BudgetLock:
    def __init__(self, actual, limit, observed):
        self.actual, self.limit, self.observed = actual, limit, observed

    def acquire(self, *args, **kwargs):
        if "timeout" in kwargs:
            budget = kwargs["timeout"]
            self.observed.append(budget)
            assert 0 < budget <= self.limit, "An internal budget exceeded the validated input"
        return self.actual.acquire(*args, **kwargs)

    def release(self):
        self.actual.release()

    def __enter__(self):
        self.actual.acquire()
        return self

    def __exit__(self, *_):
        self.actual.release()


def _graph(request, target, timeout):
    observed = []
    if target == "child":
        sample = request.getfixturevalue("inert_child_factory")()
        owner, error = sample.owner, windows_child_job.NativeOwnershipObservationError
        names = ("_owned_observation_lock", "_handle_lock")
    else:
        sample = request.getfixturevalue("inert_owner")
        owner, error = sample.provider, process_snapshot_worker.InventoryWorkerError
        names = ("_retirement", "_lock")
    for name in names:
        setattr(owner, name, _BudgetLock(getattr(owner, name), timeout, observed))
    return sample, owner, error, observed


@pytest.mark.parametrize("target", ["child", "inventory"])
@pytest.mark.parametrize("timeout", [1.0, 0.1, 0.3])
def test_remaining_lock_budgets_never_exceed_original_timeout(request, target, timeout):
    sample, owner, _error, observed = _graph(request, target, timeout)
    started = math.nextafter(511.01, -math.inf)
    assert (started + timeout) - started > timeout  # The concrete binary boundary.
    sample.clock[0] = started
    rows = owner.observe_owned_process_identities(timeout=timeout)
    assert rows and observed and all(0 < budget <= timeout for budget in observed)
    assert all(row.observed_monotonic == started for row in rows)
    if target == "child":
        created = {entry[3] for entry in sample.native.duplicates + sample.native.opened}
    else:
        created = {entry[3] for entry in sample.native.opened}
    assert set(sample.native.closed) == created


@pytest.mark.parametrize("target", ["child", "inventory"])
@pytest.mark.parametrize("timeout", [math.nextafter(1.0, math.inf), True, float("nan"), float("inf")])
def test_public_deadline_validation_is_not_relaxed(request, target, timeout):
    sample, owner, error, observed = _graph(request, target, 1.0)
    with pytest.raises(error):
        owner.observe_owned_process_identities(timeout=timeout)
    assert observed == [] and sample.native.calls == []


@pytest.mark.parametrize("target", ["child", "inventory"])
@pytest.mark.parametrize("invalid", [True, -1.0, float("nan"), float("inf")])
def test_invalid_initial_clock_still_refuses_before_native_or_lock_admission(request, target, invalid):
    sample, owner, error, observed = _graph(request, target, 1.0)
    sample.clock[0] = invalid
    with pytest.raises(error):
        owner.observe_owned_process_identities(timeout=1.0)
    assert observed == [] and sample.native.calls == []


@pytest.mark.parametrize("target", ["child", "inventory"])
@pytest.mark.parametrize("change", ["regressed", "expired", "nan", "infinite", "bool"])
def test_rounding_clamp_does_not_rescue_invalid_or_expired_native_observation(request, target, change):
    sample, owner, error, observed = _graph(request, target, 1.0)
    started = math.nextafter(511.01, -math.inf)
    sample.clock[0] = started
    changed = []

    def invalidate(operation, _subject):
        if operation == "identity" and not changed:
            changed.append(True)
            sample.clock[0] = {
                "regressed": started - 0.001, "expired": started + 1.0,
                "nan": float("nan"), "infinite": float("inf"), "bool": True,
            }[change]

    sample.native.hook = invalidate
    with pytest.raises(error):
        owner.observe_owned_process_identities(timeout=1.0)
    assert changed and observed and all(0 < budget <= 1.0 for budget in observed)
    if target == "child":
        created = {entry[3] for entry in sample.native.duplicates + sample.native.opened}
    else:
        created = {entry[3] for entry in sample.native.opened}
    assert set(sample.native.closed) == created
