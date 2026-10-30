"""Native-owned Core context for the admitted headless service, not a beat.

Reuse the real query-only identity cache on one retained background worker.
No heartbeat files are read/created and no watchdog/scanner/Black Box is inferred.
The consumer receives only the existing immutable two-second context DTOs.
"""
from __future__ import annotations

import threading

from .windows_engine_custody import active_engine_custody

_RETIREMENT_HOLD = None


class ServiceProcessContext:
    def __init__(self, custody, *, _cache_factory=None):
        if custody is not active_engine_custody() or _RETIREMENT_HOLD is not None:
            raise PermissionError("Service Core context requires its actual admitted owner")
        self._custody = custody
        self._cache_factory = _cache_factory
        self._cache = None
        self._stop = threading.Event()
        self._ready = threading.Event()
        self._thread = None
        self.error_type = ""
        self._close_error = ""
        self._retirement_error = False
        self._start_failed = False

    def start(self):
        global _RETIREMENT_HOLD

        if self._thread is not None or self._stop.is_set():
            raise RuntimeError("Service Core context cannot restart a process generation")
        worker = threading.Thread(target=self._work, name="ServiceCoreNativeContext", daemon=False)
        self._thread = worker
        try:
            worker.start()
        except BaseException as exc:
            # Thread.start can fail after native admission but before ident is
            # published. Neither ident=None nor is_alive=False proves that a
            # delayed bootstrap cannot run. Fence publication and retain owner.
            self._stop.set()
            self._start_failed = self._retirement_error = True
            self.error_type = type(exc).__name__
            _RETIREMENT_HOLD = self
            raise

    @staticmethod
    def _no_heartbeat_reader(_role):
        raise PermissionError("Service native context does not read heartbeat files")

    def _work(self):
        cache = None
        try:
            from angerona.resilience.component_status import ComponentHeartbeatCache, ROLES

            factory = self._cache_factory or ComponentHeartbeatCache
            cache = factory({role: None for role in ROLES},
                enabled={role: role == "core" for role in ROLES},
                owned_core_pid=self._custody.identity.pid, reader_factory=self._no_heartbeat_reader)
            self._cache = cache
            while not self._stop.is_set():
                if self._custody is not active_engine_custody():
                    raise PermissionError("Service native context lost its admitted owner")
                cache.refresh_owned_processes()
                self._ready.set()
                self._stop.wait(1.0)
        except BaseException as exc:
            self.error_type = type(exc).__name__
        finally:
            self._stop.set()
            if cache is not None:
                try:
                    cache.close()
                except BaseException as exc:
                    self._close_error = type(exc).__name__
            self._ready.set()

    def owned_process_identities(self) -> tuple:
        """Memory-only getter; the existing WER consumer checks DTO expiry."""
        cache = self._cache
        return cache.owned_process_identities() if not self._stop.is_set() and cache is not None else ()

    def request_stop(self):
        self._stop.set()
        cache = self._cache
        if cache is not None:
            cache.mark_stopped()

    def close(self, timeout=3.0):
        global _RETIREMENT_HOLD

        self.request_stop()
        worker = self._thread
        if worker is not None and worker.ident is not None and worker is not threading.current_thread():
            worker.join(max(0.0, min(10.0, float(timeout))))
        if self._start_failed or self._retirement_error or self._close_error or worker is not None and worker.is_alive():
            self._retirement_error = True
            _RETIREMENT_HOLD = self
            raise RuntimeError("Service Core native context retirement remains unproven")
        return True
