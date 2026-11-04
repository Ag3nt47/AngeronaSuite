"""Shared test-only native Core/inventory context; no native work at import.

Product imports and real collectors are entered only by the fixture owner.
The optional pump is for a GUI fixture's startup wait; the supplier remains
memory-only and never drops an unavailable inventory companion to Core-only.
"""
from __future__ import annotations

from contextlib import contextmanager
import os
import sys
import threading
import time


@contextmanager
def native_companion_context(*, retirement_owner, pump_events=None):
    """Use the runtime's owned rich collector instead of a GUI-local fallback.

    This fixture tests collection/response, not the separate application-entry
    privilege gate. Calling the fixed worker API directly lets elevated hosted
    runners exercise the same real collector and authenticated private protocol
    without changing the production source-entry refusal or supplying fake rows.
    """
    from angerona.core.process_snapshot_lifecycle import ProcessSnapshotLifecycle
    from angerona.core.werfault_guard import read_owned_process_snapshot
    from angerona.resilience.component_status import ComponentHeartbeatCache, ROLES
    from angerona.telemetry.process_snapshot_worker import InventoryWorkerError, ProcessSnapshotProvider

    provider = ProcessSnapshotProvider(command=[
        sys.executable, "-c",
        "from angerona.telemetry.process_snapshot_worker import worker_main; "
        "raise SystemExit(worker_main())",
    ])
    owner = ProcessSnapshotLifecycle(provider)
    core = ComponentHeartbeatCache(
        {role: None for role in ROLES},
        enabled={role: role == "core" for role in ROLES}, owned_core_pid=os.getpid(),
    )
    stopped, ready = threading.Event(), threading.Event()
    publication = ((), "not-ready")
    close_errors = []

    def owned_process_identities():
        # This supplier is deliberately memory-only, as in normal App startup.
        rows, error = publication
        if stopped.is_set() or error is not None:
            raise InventoryWorkerError("Cached GUI fixture companion ownership is unavailable")
        return rows

    def refresh_context():
        nonlocal publication
        try:
            while not stopped.is_set():
                sampled = time.monotonic()
                try:
                    core.refresh_owned_processes()
                    core_rows = core.owned_process_identities()
                    if (len(core_rows) != 1 or core_rows[0].role != "core"
                            or core_rows[0].pid != os.getpid()):
                        raise InventoryWorkerError("Native fixture Core ownership is unavailable")
                    rows = core_rows + provider.observe_owned_process_identities()
                    # Validate the combined sample without renewing either
                    # producer's leases or dropping an unavailable companion.
                    rows = read_owned_process_snapshot(
                        lambda: rows, not_before=sampled, clock=time.monotonic,
                    ).rows
                    if not stopped.is_set():
                        publication = (rows, None)
                        ready.set()
                except Exception as exc:
                    publication = ((), type(exc).__name__)
                stopped.wait(max(0.0, 1.0 - (time.monotonic() - sampled)))
        finally:
            publication = ((), "stopped")
            try:
                core.close()
            except Exception as exc:
                close_errors.append(type(exc).__name__)

    context_worker = threading.Thread(target=refresh_context, name="GuiLiveNativeCompanionContext", daemon=False)
    context_start_proven = False
    assert owner.start()
    try:
        context_worker.start()
        context_start_proven = True
        deadline = time.monotonic() + 10.0
        while not ready.is_set() and context_worker.is_alive() and time.monotonic() < deadline:
            if pump_events is not None:
                pump_events()
            time.sleep(0.01)
        assert ready.is_set(), "Native Core/inventory companion context was not established"
        yield owned_process_identities
    finally:
        # The test's producer/combat cleanup runs before fixture teardown. Keep
        # exact native context available through that retirement, then revoke.
        stopped.set()
        publication = ((), "stopped")
        if context_worker.ident is not None:
            context_worker.join(timeout=3.0)
        context_retired = context_start_proven and not context_worker.is_alive() and not close_errors
        if not context_retired:
            # Preserve uncertain observer owners; never close its handles from
            # a competing thread or claim that missing references prove exit.
            retirement_owner._inventory_context_retirement_hold = (context_worker, core, owner, close_errors)
        owner.request_stop()
        retired = []
        waiter = threading.Thread(
            target=lambda: retired.append(owner.wait_retired(timeout=30.0)),
            name="GuiLiveInventoryRetirement",
        )
        waiter.start()
        waiter.join(timeout=31.0)
        if waiter.is_alive() or retired != [True]:
            retirement_owner._inventory_retirement_hold = (waiter, owner, provider, retired)
        assert context_retired, "Native companion context retirement or handle closure is unproven"
        assert not waiter.is_alive(), "Inventory retirement waiter did not finish"
        assert retired == [True], "The exact owned inventory process did not retire"
