"""Non-blocking, offline evidence ingestion for EventBus subscribers."""
from __future__ import annotations

import queue
import threading
import time
from dataclasses import dataclass

from angerona.core.eventbus import Event
from angerona.core.evidence_store import EvidenceEnvelope, EvidenceStore


@dataclass(frozen=True)
class IngestionMetrics:
    accepted: int
    persisted: int
    duplicates: int
    dropped_full: int
    failed: int
    queue_depth: int
    queue_capacity: int
    batches: int
    running: bool


class EvidenceIngestionWorker:
    """Bounded queue + single local writer; ``submit`` never waits."""

    def __init__(
        self,
        store: EvidenceStore,
        *,
        queue_capacity: int = 2048,
        batch_size: int = 100,
        flush_interval: float = 0.25,
    ) -> None:
        if queue_capacity < 1 or batch_size < 1 or flush_interval <= 0:
            raise ValueError("worker limits must be positive")
        if not store.local_only:
            raise ValueError("ingestion worker requires a local-only evidence store")
        self._store = store
        self._queue: queue.Queue[EvidenceEnvelope | Event] = queue.Queue(
            maxsize=int(queue_capacity)
        )
        self._batch_size = min(int(batch_size), int(queue_capacity))
        self._flush_interval = float(flush_interval)
        self._state_lock = threading.Lock()
        self._metrics_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._accepted = 0
        self._persisted = 0
        self._duplicates = 0
        self._dropped_full = 0
        self._failed = 0
        self._batches = 0

    def start(self) -> bool:
        """Start once. Return false when already running."""
        with self._state_lock:
            if self._thread is not None and self._thread.is_alive():
                return False
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._run, name="angerona-evidence-ingestion", daemon=True
            )
            self._thread.start()
            return True

    def submit(self, evidence: EvidenceEnvelope) -> bool:
        """Attempt enqueue without blocking the calling producer."""
        try:
            self._queue.put_nowait(evidence)
        except queue.Full:
            with self._metrics_lock:
                self._dropped_full += 1
            return False
        with self._metrics_lock:
            self._accepted += 1
        return True

    def submit_event(self, event: Event, **normalization: object) -> bool:
        # The EventBus calls subscribers inline. Enqueue the immutable Event
        # itself so JSON canonicalization and hashing also happen on the worker,
        # not on a sensor/GUI producer thread. Custom normalization is kept out
        # of this hot-path API intentionally; live bus events use the canonical
        # defaults and explicit envelopes can still be submitted by callers.
        if normalization:
            return self.submit(EvidenceEnvelope.from_event(event, **normalization))
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            with self._metrics_lock:
                self._dropped_full += 1
            return False
        with self._metrics_lock:
            self._accepted += 1
        return True

    def _flush(self, batch: list[EvidenceEnvelope | Event]) -> None:
        if not batch:
            return
        persisted = duplicates = failed = 0
        try:
            envelopes = [
                EvidenceEnvelope.from_event(item)
                if isinstance(item, Event) else item
                for item in batch
            ]
            append_many = getattr(self._store, "append_many", None)
            if callable(append_many):
                persisted, duplicates = append_many(envelopes)
            else:  # small injectable test/durable-store compatibility seam
                for envelope in envelopes:
                    if self._store.append(envelope):
                        persisted += 1
                    else:
                        duplicates += 1
        except Exception:
            failed = len(batch)
        finally:
            for _item in batch:
                self._queue.task_done()
        with self._metrics_lock:
            self._persisted += persisted
            self._duplicates += duplicates
            self._failed += failed
            self._batches += 1

    def _run(self) -> None:
        batch: list[EvidenceEnvelope | Event] = []
        deadline = time.monotonic() + self._flush_interval
        while not self._stop.is_set() or not self._queue.empty():
            remaining = max(0.0, deadline - time.monotonic())
            try:
                item = self._queue.get(timeout=min(remaining, 0.05))
                batch.append(item)
            except queue.Empty:
                pass
            now = time.monotonic()
            if batch and (
                len(batch) >= self._batch_size
                or now >= deadline
                or (self._stop.is_set() and self._queue.empty())
            ):
                self._flush(batch)
                batch = []
                deadline = now + self._flush_interval
            elif now >= deadline:
                deadline = now + self._flush_interval
        self._flush(batch)

    def stop(self, *, drain_timeout: float = 5.0) -> bool:
        """Request a drain and wait at most ``drain_timeout`` seconds."""
        if drain_timeout < 0:
            raise ValueError("drain_timeout must be non-negative")
        with self._state_lock:
            thread = self._thread
            if thread is None:
                return True
            self._stop.set()
        thread.join(timeout=float(drain_timeout))
        stopped = not thread.is_alive()
        if stopped:
            with self._state_lock:
                if self._thread is thread:
                    self._thread = None
        return stopped

    def metrics(self) -> IngestionMetrics:
        with self._metrics_lock:
            values = (
                self._accepted, self._persisted, self._duplicates,
                self._dropped_full, self._failed, self._batches,
            )
        with self._state_lock:
            running = self._thread is not None and self._thread.is_alive()
        return IngestionMetrics(
            accepted=values[0], persisted=values[1], duplicates=values[2],
            dropped_full=values[3], failed=values[4],
            queue_depth=self._queue.qsize(),
            queue_capacity=self._queue.maxsize, batches=values[5],
            running=running,
        )

    def __enter__(self) -> "EvidenceIngestionWorker":
        self.start()
        return self

    def __exit__(self, *_args: object) -> None:
        self.stop()
