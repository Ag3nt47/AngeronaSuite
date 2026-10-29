"""Explicit, asynchronous ownership of the isolated process inventory provider."""
from __future__ import annotations

import threading


class ProcessSnapshotLifecycle:
    """One explicit runtime owner; construction never launches a collector.

    The provider is registered before GUI readers or modules are constructed.
    Only this retained worker starts and retires it. Failed bootstrap leaves the
    configured provider unavailable rather than selecting a local collector.
    """

    def __init__(self, provider=None, *, configure=None) -> None:
        if provider is None:
            from angerona.telemetry.process_snapshot_worker import ProcessSnapshotProvider
            provider = ProcessSnapshotProvider()
        if configure is None:
            from angerona.telemetry.sensors import configure_process_snapshot_provider
            configure = configure_process_snapshot_provider
        self.provider = provider
        self._lock = threading.Lock()
        self._stop_requested = threading.Event()
        self._start_finished = threading.Event()
        self._retired = threading.Event()
        self._thread = None
        self._ready = False
        self._state = "configured"
        self._error_type = ""
        configure(provider)

    def start(self) -> bool:
        """Schedule once without native I/O or a GUI-thread wait."""
        with self._lock:
            if self._stop_requested.is_set():
                return False
            if self._thread is not None:
                return self._thread.is_alive() or self._ready
            self._state = "starting"
            self._thread = threading.Thread(
                target=self._run, name="ProcessInventoryOwner", daemon=False,
            )
            try:
                self._thread.start()
            except Exception as exc:
                self._state = "unavailable"
                self._error_type = type(exc).__name__[:120]
                self._start_finished.set()
                self._retired.set()
                return False
        return True

    def _run(self) -> None:
        try:
            if self._stop_requested.is_set():
                return
            try:
                ready = bool(self.provider.start())
            except Exception as exc:
                ready = False
                with self._lock:
                    self._error_type = type(exc).__name__[:120]
            with self._lock:
                self._ready = ready and not self._stop_requested.is_set()
                self._state = "running" if self._ready else "unavailable"
            self._start_finished.set()
            if ready:
                self._stop_requested.wait()
        finally:
            self._start_finished.set()
            with self._lock:
                self._ready = False
                self._state = "retiring"
            # False means native ownership remains, not successful retirement.
            # Keep this single owner alive; never create a replacement child.
            while True:
                try:
                    if self.provider.stop(timeout=3.0) is True:
                        break
                except Exception as exc:
                    with self._lock:
                        self._error_type = type(exc).__name__[:120]
                threading.Event().wait(0.1)
            with self._lock:
                self._state = "stopped"
            self._retired.set()

    def wait_started(self, timeout: float = 6.0) -> bool:
        """Background startup barrier; callers must not run this on Qt."""
        self._require_background_wait()
        if not self._start_finished.wait(max(0.0, min(30.0, float(timeout)))):
            return False
        return self.lifecycle_snapshot()["ready"]

    @staticmethod
    def _require_background_wait() -> None:
        import sys
        qt = sys.modules.get("PySide6.QtCore")
        if qt is not None:
            application = qt.QCoreApplication.instance()
            if application is not None and qt.QThread.currentThread() == application.thread():
                raise RuntimeError("Process inventory waits must run off the GUI thread")

    def request_stop(self) -> None:
        """Signal only; native drain and termination stay on the owner worker."""
        self._stop_requested.set()
        self._start_finished.set()
        with self._lock:
            self._ready = False
            if self._thread is None:
                self._state = "stopped"
                self._retired.set()

    def wait_retired(self, timeout: float = 3.0) -> bool:
        self._require_background_wait()
        return self._retired.wait(max(0.0, min(30.0, float(timeout))))

    def lifecycle_snapshot(self) -> dict:
        """Cached advisory state only; no host probe, IPC or native handle wait."""
        with self._lock:
            result = dict(state=self._state, ready=self._ready,
                          retired=self._retired.is_set(), error_type=self._error_type,
                          advisory_only=True)
        try:
            result["provider"] = dict(self.provider.lifecycle_snapshot())
        except Exception as exc:
            result["provider"] = dict(error_type=type(exc).__name__[:120])
        provider = result["provider"]
        # The owner remains alive to retain custody after a provider failure.
        # Its successful startup is not evidence that the provider is still
        # ready. Reconcile only the provider's existing memory publication;
        # never probe, restart or select a local collector from this accessor.
        if result["state"] == "running":
            if self._stop_requested.is_set():
                result.update(state="retiring", ready=False)
            elif (provider.get("ready") is not True
                    or provider.get("retired") is not False
                    or provider.get("error")
                    or provider.get("retirement_error")
                    or provider.get("auxiliary_close_unproven") is True):
                result.update(state="unavailable", ready=False)
        return result


