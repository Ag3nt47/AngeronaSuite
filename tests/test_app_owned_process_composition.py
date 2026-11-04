"""Production App composes real ownership APIs through inert native seams.

These tests do not start Angerona or create an OS process/handle. The imported
fixtures retain actual owner classes; only their native operations are inert.
"""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import FrozenInstanceError, replace
import os
import threading
from types import SimpleNamespace

import pytest

from test_child_job_owned_identities import inert_child_factory
from test_owned_process_context import context, publish
from test_process_snapshot_owned_identities import inert_owner

from angerona import app as app_module
from angerona.app import AngeronaApp
from angerona.core import ollama_lifecycle, windows_process_lease
from angerona.core.process_snapshot_lifecycle import ProcessSnapshotLifecycle
from angerona.core.werfault_guard import OwnedProcessIdentity, OwnedProcessReadError, read_owned_process_snapshot
from angerona.core.windows_child_job import NativeOwnershipObservationError, OwnedWindowsChild
from angerona.resilience import manager as manager_module
from angerona.resilience.manager import ResilienceManager
from angerona.resilience.supervisor import Component, ProcessSupervisor
from angerona.telemetry import process_snapshot_worker as worker, sensors


_REJECTIONS = (worker.InventoryWorkerError, NativeOwnershipObservationError, OwnedProcessReadError)


@pytest.fixture
def composition(context, inert_owner, inert_child_factory, monkeypatch):
    # This fixture represents a fresh Core generation, including real AI
    # admission state. No native verifier or complete-scope result is replaced.
    monkeypatch.setattr(ollama_lifecycle, "_owned_services", {})
    monkeypatch.setattr(ollama_lifecycle, "_startup_attempts", OrderedDict())
    monkeypatch.setattr(ollama_lifecycle, "_ai_shutdown", threading.Event())
    # The Core cache still performs its real native-witness/owner-link logic.
    core = replace(context.identities["core"], pid=os.getpid())
    context.identities["core"] = context.owners["core"] = core
    context.records["core"] = dict(context.records["core"], pid=core.pid)
    context.cache._owned_core_pid = core.pid
    publish(context)

    children = {
        "watchdog": inert_child_factory((2001, 2002)),
        "scanner": inert_child_factory((2101,)),
        "blackbox": inert_child_factory((2201,)),
    }
    native = children["watchdog"].native
    monkeypatch.setattr(windows_process_lease, "_Native", lambda: native)
    clock = children["watchdog"].clock
    clock[0] = inert_owner.clock[0] = context.clock[0] = 100.0
    monotonic = SimpleNamespace(monotonic=lambda: clock[0])
    monkeypatch.setattr(app_module, "time", monotonic)
    monkeypatch.setattr(manager_module, "time", monotonic)
    monkeypatch.setattr(manager_module, "os", SimpleNamespace(name="nt", getpid=os.getpid))

    supervisor = object.__new__(ProcessSupervisor)
    supervisor._stop = threading.Event()
    supervisor._lifecycle_lock = threading.RLock()
    supervisor.components = {
        name: Component(name, [rf"C:\inert\{name}.exe"], proc=child.owner)
        for name, child in children.items()
    }
    resilience = object.__new__(ResilienceManager)
    resilience._stop = threading.Event()
    resilience._sup = supervisor
    resilience._component_heartbeat_cache = context.cache
    resilience._owned_core_pid = core.pid
    resilience.start_watchdog, resilience.with_ui, resilience.status = True, False, "running"
    inventory = ProcessSnapshotLifecycle(inert_owner.provider)
    # The inert provider fixture owns its native lifetime. No owner thread is
    # started; its already-ready metadata is an explicit lifecycle test seam.
    inventory._ready, inventory._state = True, "running"
    inventory._start_finished.set()
    app = object.__new__(AngeronaApp)
    app._shutdown_requested = threading.Event()
    app._resilience, app._process_snapshot_lifecycle = resilience, inventory
    actual_inventory_observe = worker.ProcessSnapshotProvider.observe_owned_process_identities

    def inventory_observe(**kwargs):
        # Both sides execute their actual complete-membership API. Native
        # registries are separate inert seams, never manufactured success rows.
        with monkeypatch.context() as native_boundary:
            native_boundary.setattr(windows_process_lease, "_Native", lambda: inert_owner.native)
            return actual_inventory_observe(inert_owner.provider, **kwargs)

    monkeypatch.setattr(inert_owner.provider, "observe_owned_process_identities", inventory_observe)
    return SimpleNamespace(app=app, resilience=resilience, supervisor=supervisor,
        inventory=inventory, provider=inert_owner.provider, inventory_context=inert_owner,
        cache=context.cache, core_context=context, children=children, native=native,
        make_child=inert_child_factory, clock=clock)


def observe(sample):
    return sample.app._owned_process_identities_for_response()


def identity(row):
    return row.pid, row.birth_ticks, row.create_time, row.image


def add_ui(sample):
    sample.resilience.with_ui = True
    for name, pids in (("watchdog_ui", (2301, 2302)), ("scanner_ui", (2401, 2402))):
        child = sample.make_child(pids)
        sample.children[name] = child
        sample.supervisor.components[name] = Component(name, [rf"C:\inert\{name}.exe"], proc=child.owner)


def test_app_complete_scope_executes_actual_core_child_and_inventory_apis(composition):
    sample = composition
    rows = observe(sample)
    expected = {os.getpid(), 1001, 1002, 1003, 2001, 2002, 2101, 2201}
    assert {row.pid for row in rows} == expected
    assert all(type(row) is OwnedProcessIdentity for row in rows)
    assert all(row.observed_monotonic == 100.0 and row.expires_monotonic == 102.0 for row in rows)
    assert {row.role for row in rows}.issuperset({"core", "watchdog", "scanner", "blackbox", "inventory-worker"})
    assert sample.inventory_context.native.opened and sample.native.opened
    assert read_owned_process_snapshot(lambda: rows, not_before=100.0, clock=lambda: 100.1).rows is rows
    with pytest.raises(FrozenInstanceError):
        rows[0].pid = 123
    with pytest.raises(OwnedProcessReadError):
        read_owned_process_snapshot(lambda: rows, not_before=102.0, clock=lambda: 102.0)


def test_full_start_includes_actual_ui_jobs_and_their_redirectors(composition):
    add_ui(composition)
    rows = observe(composition)
    assert {2301, 2302, 2401, 2402}.issubset({row.pid for row in rows})
    assert {row.role for row in rows}.issuperset({"watchdog-ui", "scanner-ui"})


def test_intentionally_disabled_companion_is_distinct_from_missing_owner(composition):
    sample = composition
    sample.cache._enabled["blackbox"] = False
    sample.supervisor.components.pop("blackbox")
    rows = observe(sample)
    assert 2201 not in {row.pid for row in rows}
    sample.cache._enabled["blackbox"] = True
    with pytest.raises(worker.InventoryWorkerError, match="missing"):
        observe(sample)


@pytest.mark.parametrize("missing", ["watchdog", "scanner", "blackbox", "watchdog_ui", "scanner_ui"])
def test_each_configured_companion_requires_complete_coverage(composition, missing):
    sample = composition
    if missing.endswith("_ui"):
        add_ui(sample)
    sample.supervisor.components.pop(missing)
    with pytest.raises(worker.InventoryWorkerError, match="missing"):
        observe(sample)


@pytest.mark.parametrize("change", ["app-stop", "resilience-stop", "inventory-stop", "inventory-route",
    "inventory-not-ready", "provider-failure", "owner-closed", "owner-stopped", "owner-close-gap"])
def test_unavailable_owner_never_becomes_fresh_core_only(composition, monkeypatch, change):
    sample = composition
    if change == "app-stop":
        sample.app._shutdown_requested.set()
    elif change == "resilience-stop":
        sample.resilience._stop.set()
    elif change == "inventory-stop":
        sample.inventory._stop_requested.set()
    elif change == "inventory-route":
        sensors.configure_process_snapshot_provider(None)
    elif change == "inventory-not-ready":
        sample.inventory._ready = False
    elif change == "provider-failure":
        sample.provider._failure = "inert provider failure"
    elif change == "owner-closed":
        monkeypatch.setattr(sample.children["scanner"].owner, "_process", None)
    elif change == "owner-stopped":
        monkeypatch.setattr(sample.children["scanner"].owner, "_owned_observation_stopped", True)
    else:
        monkeypatch.setattr(sample.children["scanner"].owner, "_owned_observation_close_holds", [object()])
    assert any(row.role == "core" for row in sample.cache.owned_process_identities())
    with pytest.raises(_REJECTIONS):
        observe(sample)


def test_external_watchdog_without_native_owner_is_explicitly_held(composition):
    composition.cache._expected["watchdog"] = None
    with pytest.raises(worker.InventoryWorkerError, match="External watchdog"):
        observe(composition)


def test_adopted_only_metadata_cannot_create_ownership(composition):
    sample = composition
    component = sample.supervisor.components["scanner"]
    component.proc = None
    component.adopted = True
    component.adopted_identity = {"pid": 2101, "birth": 1700000000.0, "image": r"C:\inert\scanner.exe"}
    # Its authentic fixed-role identity is still outside every proved child Job.
    with pytest.raises(worker.InventoryWorkerError, match="outside retained native Jobs"):
        observe(sample)


def test_adopted_fixed_role_can_only_select_existing_exact_native_job_member(composition):
    sample = composition
    component = sample.supervisor.components["scanner"]
    component.proc = None
    component.adopted = True
    sample.children["watchdog"].members[:] = [[2001, 2002, 2101]]
    alias = replace(sample.native.identities[2101],
                    image=windows_process_lease._image_path(sample.native.identities[2101].image))
    sample.cache._authenticated_identities["scanner"] = alias
    rows = observe(sample)
    assert [row.pid for row in rows].count(2101) == 1
    sample.cache._authenticated_identities["scanner"] = replace(alias, birth_ticks=alias.birth_ticks + 1)
    with pytest.raises(worker.InventoryWorkerError, match="outside retained native Jobs"):
        observe(sample)


@pytest.mark.parametrize("change", ["registry-copy", "equal-component-copy", "owner-epoch", "owner-stop",
    "owner-handle", "owner-raw-close", "job-raw-close", "app-stop", "resilience-stop", "configuration", "inventory-route", "inventory-pin"])
def test_whole_app_scope_rechecks_after_native_inventory_observation(composition, monkeypatch, change):
    sample = composition
    actual = sample.provider.observe_owned_process_identities

    def observe_then_change(**kwargs):
        rows = actual(**kwargs)
        scanner = sample.supervisor.components["scanner"]
        if change == "registry-copy":
            sample.supervisor.components = dict(sample.supervisor.components)
        elif change == "equal-component-copy":
            sample.supervisor.components["scanner"] = replace(scanner)
        elif change == "owner-epoch":
            monkeypatch.setattr(scanner.proc, "_owned_observation_epoch", scanner.proc._owned_observation_epoch + 1)
        elif change == "owner-stop":
            monkeypatch.setattr(scanner.proc, "_owned_observation_stopped", True)
        elif change == "owner-handle":
            monkeypatch.setattr(scanner.proc, "_process", object())
        elif change == "owner-raw-close":
            scanner.proc._process.Close()
        elif change == "job-raw-close":
            scanner.proc._job._handle.Close()
        elif change == "app-stop":
            sample.app._shutdown_requested.set()
        elif change == "resilience-stop":
            sample.resilience._stop.set()
        elif change == "configuration":
            sample.cache._enabled["blackbox"] = False
        elif change == "inventory-route":
            sensors.configure_process_snapshot_provider(sample.provider)
        else:
            monkeypatch.setattr(sample.provider._child, "closed", True)
        return rows

    monkeypatch.setattr(sample.provider, "observe_owned_process_identities", observe_then_change)
    with pytest.raises(_REJECTIONS):
        observe(sample)


def test_original_core_lease_expiring_during_composition_is_not_renewed(composition, monkeypatch):
    sample = composition
    epoch, rows = sample.cache._owned_publication
    sample.cache._owned_publication = (epoch, tuple(
        replace(row, observed_monotonic=98.75, expires_monotonic=100.75)
        if row.role == "core" else row for row in rows))
    actual = sample.provider.observe_owned_process_identities

    def observe_then_age(**kwargs):
        rows = actual(**kwargs)
        sample.clock[0] = 100.8
        return rows

    monkeypatch.setattr(sample.provider, "observe_owned_process_identities", observe_then_age)
    with pytest.raises(OwnedProcessReadError, match="stale"):
        observe(sample)


def test_complete_scope_over_existing_sixteen_row_bound_is_held(composition):
    sample = composition
    sample.children["watchdog"].members[:] = [[2001, 2002, *range(2501, 2512)]]
    # The extra identities exist in the actual inert native registry, not just
    # a list of fabricated DTOs. The complete combined scope exceeds16.
    extra = sample.make_child(tuple(range(2501, 2512)))
    sample.supervisor.components["extra"] = Component("extra", [r"C:\inert\extra.exe"], proc=extra.owner)
    with pytest.raises(worker.InventoryWorkerError, match="bound"):
        observe(sample)


def test_gui_thread_rejection_precedes_any_native_query(composition, monkeypatch):
    sample = composition
    before_child, before_inventory = list(sample.native.calls), list(sample.inventory_context.native.calls)
    monkeypatch.setattr(worker, "on_gui_thread", lambda: True)
    with pytest.raises(worker.InventoryWorkerError, match="GUI thread"):
        observe(sample)
    assert sample.native.calls == before_child
    assert sample.inventory_context.native.calls == before_inventory


def test_cached_app_display_supplier_stays_no_io_and_stop_fenced(composition, monkeypatch):
    sample = composition
    original = sample.cache.owned_process_identities()
    def forbidden(*_args, **_kwargs):
        pytest.fail("Cached display context attempted native observation")
    monkeypatch.setattr(sample.resilience, "observe_owned_process_identities", forbidden)
    monkeypatch.setattr(sample.provider, "observe_owned_process_identities", forbidden)
    monkeypatch.setattr(app_module, "time", SimpleNamespace(monotonic=forbidden))
    assert sample.app._owned_process_identities_cached() is original
    sample.app._shutdown_requested.set()
    assert sample.app._owned_process_identities_cached() == ()


@pytest.mark.parametrize("field,value", [("_owned_close_failure", "inert unproven close"),
                                         ("_native_cleanup_failed_roles", {"scanner"})])
def test_sticky_native_cache_cleanup_gap_cannot_be_replaced_by_fresh_other_owners(composition, field, value):
    sample = composition
    setattr(sample.cache, field, value)
    try:
        assert any(row.role == "core" for row in sample.cache.owned_process_identities())
        with pytest.raises(worker.InventoryWorkerError, match="cleanup remains unproven"):
            observe(sample)
    finally:
        # Only this test's inert expected diagnostic is reset for fixture cleanup.
        setattr(sample.cache, field, "" if field == "_owned_close_failure" else set())



def test_matching_nested_job_member_keeps_one_original_identity_and_lease(composition):
    sample = composition
    sample.children["watchdog"].members[:] = [[2001, 2002, 2101]]
    rows = observe(sample)
    member = [row for row in rows if row.pid == 2101]
    assert len(member) == 1 and member[0].observed_monotonic == 100.0
    assert member[0].expires_monotonic == 102.0
    # Both actual registered owners were queried, even though one native
    # member occurs in both complete Job scopes.
    assert sample.children["watchdog"].model.reads >= 3
    assert sample.children["scanner"].model.reads >= 3


def test_contradictory_reobserved_pid_birth_rejects_the_whole_scope(composition, monkeypatch):
    sample = composition
    sample.children["watchdog"].members[:] = [[2001, 2002, 2101]]
    actual = OwnedWindowsChild.observe_owned_process_identities
    observations = []
    before = sample.native.identities[2101]

    def observe_then_reuse(owner, **kwargs):
        rows = actual(owner, **kwargs)
        if owner is sample.children["scanner"].owner:
            observations.append(("scanner", tuple(identity(row) for row in rows if row.pid == 2101)))
            # The registry is sorted: scanner is observed BEFORE watchdog.
            # Change only the inert native identity after the first real API
            # returned; the later actual watchdog query sees the new birth.
            sample.native.identities[2101] = replace(before, birth_ticks=before.birth_ticks + 1)
        elif owner is sample.children["watchdog"].owner:
            observations.append(("watchdog", tuple(identity(row) for row in rows if row.pid == 2101)))
        return rows

    monkeypatch.setattr(OwnedWindowsChild, "observe_owned_process_identities", observe_then_reuse)
    with pytest.raises(worker.InventoryWorkerError, match="contradictory"):
        observe(sample)
    assert [name for name, _rows in observations] == ["scanner", "watchdog"]
    first, second = observations[0][1], observations[1][1]
    assert len(first) == len(second) == 1
    assert first[0][0] == second[0][0] == 2101
    assert first[0][1] == str(before.birth_ticks)
    assert second[0][1] == str(before.birth_ticks + 1)
    assert first[0][3] == second[0][3]


def test_late_inventory_query_cannot_reset_the_whole_one_second_budget(composition, monkeypatch):
    sample = composition
    actual = sample.provider.observe_owned_process_identities
    received = []

    def observe_then_overrun(**kwargs):
        received.append(kwargs["timeout"])
        rows = actual(**kwargs)
        sample.clock[0] = 101.01
        return rows

    monkeypatch.setattr(sample.provider, "observe_owned_process_identities", observe_then_overrun)
    with pytest.raises(worker.InventoryWorkerError, match="deadline"):
        observe(sample)
    assert len(received) == 1 and 0 < received[0] <= 1.0



@pytest.mark.parametrize("conversion_error", [TypeError, ValueError, OverflowError, OSError, RuntimeError])
def test_invalid_native_handle_conversion_is_a_typed_whole_hold_before_any_query(
    composition, monkeypatch, conversion_error,
):
    sample = composition
    before_child = list(sample.native.calls)
    before_inventory = list(sample.inventory_context.native.calls)

    class InvalidNativeHandle:
        def __int__(self):
            raise conversion_error("Inert internal conversion error; do not publish its text")

    monkeypatch.setattr(sample.children["scanner"].owner, "_process", InvalidNativeHandle())
    with pytest.raises(worker.InventoryWorkerError, match="retained native handle is not numeric"):
        observe(sample)
    assert sample.native.calls == before_child
    assert sample.inventory_context.native.calls == before_inventory


@pytest.mark.parametrize("scope", ["companion", "inventory"])
def test_required_native_scope_cannot_disappear_as_an_empty_result(composition, monkeypatch, scope):
    sample = composition
    producer = sample.resilience if scope == "companion" else sample.provider
    actual = producer.observe_owned_process_identities
    observations = []

    def observe_then_lose_rows(**kwargs):
        rows = actual(**kwargs)
        assert rows and all(type(row) is OwnedProcessIdentity for row in rows)
        observations.append(rows)
        return ()  # Faulty output after the actual complete native API returned.

    monkeypatch.setattr(producer, "observe_owned_process_identities", observe_then_lose_rows)
    with pytest.raises(OwnedProcessReadError) as result:
        observe(sample)
    assert result.value.reason_code == "snapshot_empty"
    assert result.value.snapshot_count == 0 and len(observations) == 1


def test_configured_external_owner_cannot_disappear_as_an_empty_result(composition):
    sample = composition
    external = sample.make_child((2501, 2502))
    observations = []

    def observe_then_lose_rows(**kwargs):
        rows = external.owner.observe_owned_process_identities(role="source-update-controller", **kwargs)
        assert {row.pid for row in rows} == {2501, 2502}
        observations.append(rows)
        return ()  # Negative output fault, not a controller authority substitute.

    # This negative adapter delegates the actual child Job API. It never
    # supplies fabricated successful controller rows or a registration proof.
    sample.app._source_update_controller = SimpleNamespace(observe=observe_then_lose_rows)
    with pytest.raises(OwnedProcessReadError) as result:
        observe(sample)
    assert result.value.reason_code == "snapshot_empty"
    assert result.value.snapshot_count == 0 and len(observations) == 1


@pytest.mark.parametrize("kind", ["list", "dict", "none", "tuple-subclass"])
def test_absent_ai_registry_does_not_allow_malformed_empty_observer_output(composition, monkeypatch, kind):
    sample = composition
    before = ollama_lifecycle.capture_owned_ollama_process_scope()
    assert before[2] == ()
    actual = ollama_lifecycle.observe_owned_ollama_process_identities
    observations = []

    class EmptyTuple(tuple):
        pass

    malformed = {"list": [], "dict": {}, "none": None, "tuple-subclass": EmptyTuple()}[kind]

    def observe_then_change_type(**kwargs):
        rows = actual(**kwargs)
        assert type(rows) is tuple and not rows
        observations.append(rows)
        return malformed

    monkeypatch.setattr(ollama_lifecycle, "observe_owned_ollama_process_identities", observe_then_change_type)
    with pytest.raises(OwnedProcessReadError) as result:
        observe(sample)
    assert result.value.reason_code == "snapshot_type_invalid"
    assert len(observations) == 1
    assert ollama_lifecycle.capture_owned_ollama_process_scope() == before


@pytest.mark.parametrize("discard_output", [False, True])
def test_registered_actual_ai_job_is_required_and_cannot_be_skipped_when_output_is_empty(
    composition, monkeypatch, discard_output,
):
    sample = composition
    ai = sample.make_child((2601, 2602))
    key = ("http://127.0.0.1:11434", os.getpid())
    assert ollama_lifecycle._owned_services == {}
    # Registry setup is the inert native fixture's explicit lifetime seam.
    # Both capture and observation still execute the real AI/child-owner APIs.
    ollama_lifecycle._owned_services[key] = ai.owner
    before = ollama_lifecycle.capture_owned_ollama_process_scope()
    assert before[2] == ((key, ai.owner),)
    actual = ollama_lifecycle.observe_owned_ollama_process_identities
    observations = []

    def observe_then_optionally_lose_rows(**kwargs):
        rows = actual(**kwargs)
        assert {row.pid for row in rows} == {2601, 2602}
        assert all(type(row) is OwnedProcessIdentity and row.role == "local-ai" for row in rows)
        observations.append(rows)
        return () if discard_output else rows

    monkeypatch.setattr(ollama_lifecycle, "observe_owned_ollama_process_identities",
                        observe_then_optionally_lose_rows)
    if discard_output:
        with pytest.raises(OwnedProcessReadError) as result:
            observe(sample)
        assert result.value.reason_code == "snapshot_empty"
        assert result.value.snapshot_count == 0
    else:
        rows = observe(sample)
        assert {row.pid for row in rows}.issuperset({2601, 2602})
        assert all(any(row is original for row in rows) for original in observations[0])
        assert all(row.observed_monotonic == 100.0 and row.expires_monotonic == 102.0
                   for row in observations[0])
    assert len(observations) == 1
    assert ollama_lifecycle.capture_owned_ollama_process_scope() == before
