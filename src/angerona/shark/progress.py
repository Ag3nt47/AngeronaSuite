"""Bounded in-memory simulation workflow progress; never response authority."""
from __future__ import annotations

from contextlib import contextmanager
import threading


class SimulationProgress:
    """Publish actual settled work units without parsing narration or time.

    An engine run owns one generation. Its worker binds that generation while
    executing, so a late worker can never update a newer run's display. A unit
    means one technique attempt or one resolved optional-noise decision. It
    says nothing about detection, containment, success or protection coverage.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._local = threading.local()
        self._generation = None
        self._snapshot = {"schema": 1, "run_id": "", "state": "idle",
                          "finished": 0, "total": 0, "current_task": "",
                          "failed_units": 0}

    def begin(self, run_id: str, total: int):
        if (type(run_id) is not str or not run_id or len(run_id) > 160
                or type(total) is not int or not 0 < total <= 10_000):
            raise ValueError("Simulation progress needs a bounded exact run and plan")
        generation = object()
        with self._lock:
            self._generation = generation
            self._snapshot = {"schema": 1, "run_id": run_id, "state": "queued",
                              "finished": 0, "total": total,
                              "current_task": "Waiting for simulation worker",
                              "failed_units": 0}
        return generation

    @contextmanager
    def worker(self, generation):
        previous = getattr(self._local, "generation", None)
        self._local.generation = generation
        with self._lock:
            if generation is self._generation:
                self._snapshot.update(state="running", current_task="Preparing technique sequence")
        try:
            yield
        finally:
            self._local.generation = previous

    def _owns_generation(self) -> bool:
        return (self._generation is not None
                and getattr(self._local, "generation", None) is self._generation)

    def start_unit(self, label: str) -> None:
        with self._lock:
            if self._owns_generation():
                self._snapshot["current_task"] = str(label).replace("\n", " ")[:160]

    def finish_unit(self, *, failed: bool = False) -> None:
        with self._lock:
            if self._owns_generation():
                row = self._snapshot
                if row["finished"] < row["total"]:
                    row["finished"] += 1
                else:
                    # A producer-plan discrepancy is visible, never wrapped or
                    # converted into invented percentage progress.
                    row.update(state="incomplete", current_task="Progress plan count mismatch")
                row["failed_units"] += int(bool(failed))

    def request_stop(self, run_id: str) -> None:
        with self._lock:
            if (run_id == self._snapshot["run_id"]
                    and self._snapshot["state"] in {"queued", "running"}):
                self._snapshot.update(state="stopping", current_task="Stopping current technique and cleaning owned controls")

    def finish(self, generation, *, cancelled: bool = False, failed: bool = False) -> bool:
        with self._lock:
            if generation is not self._generation:
                return False
            row = self._snapshot
            if cancelled:
                state, label = "cancelled", "Simulation cancelled"
            elif failed:
                state, label = "failed", "Simulation worker failed"
            elif row["finished"] != row["total"] or row["state"] == "incomplete":
                state, label = "incomplete", "Simulation ended before all planned work settled"
            else:
                state = "completed"
                label = "Technique attempts complete; awaiting authenticated report"
                if row["failed_units"]:
                    label = "Technique attempts ended with errors; awaiting authenticated report"
            row.update(state=state, current_task=label)
            return True

    def snapshot(self) -> dict:
        with self._lock:
            return dict(self._snapshot)
