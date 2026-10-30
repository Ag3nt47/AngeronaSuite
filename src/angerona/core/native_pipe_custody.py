"""Owned overlapped pipe resources; no endpoint, authentication or authority.

Unknown I/O retirement retains the exact OVERLAPPED, buffer and event plus the
main handle. Failed CloseHandle is sticky and never retried by number. Resource
consumers must fence new admission when native_pipe_retirement_held() is true.
The optional on_hold callback lets the current listener stop without polling or
closing beneath unproven native I/O.
"""
from __future__ import annotations

import threading

from .live_debug import _Pipe, LiveDebugError

_HOLD_LOCK = threading.Lock()
_RETIREMENT_HOLDS: list[object] = []


def native_pipe_retirement_held() -> bool:
    with _HOLD_LOCK:
        return bool(_RETIREMENT_HOLDS)


class _EventOwner:
    def __init__(self):
        self.handle = None
        self.attempted = False
        self.failed = False
        self.discarded_number = None

    def add(self, handle):
        self.handle = handle
        return handle

    def close(self):
        if self.attempted:
            return not self.failed
        self.attempted = True
        if self.handle is not None:
            try:
                self.handle.Close()
            except BaseException:
                self.failed = True
                try:
                    self.discarded_number = self.handle.Detach()
                except BaseException:
                    pass
            else:
                self.handle = None
        return not self.failed


class RetainedPipe(_Pipe):
    """Resource-only extension: retain auxiliary events/buffers on uncertainty."""
    def __init__(self, handle, *, on_hold=None):
        super().__init__(handle)
        self._io_owners = {}
        self._io_held = False
        self._on_hold = on_hold
        self.close_proven = False
        self._close_uncertain = False
        self._ambiguous_handle = None
        self._discarded_number = None

    def _overlap(self):
        import pywintypes
        import win32event
        if native_pipe_retirement_held():
            self._hold_io()
            raise PermissionError("Previous native pipe retirement is held")
        owner = _EventOwner()
        overlap = pywintypes.OVERLAPPED()
        self._io_owners[id(overlap)] = {"overlap": overlap, "owner": owner, "buffer": None}
        try:
            overlap.hEvent = owner.add(win32event.CreateEvent(None, True, False, None))
        except BaseException:
            if owner.close():
                del self._io_owners[id(overlap)]
            else:
                self._hold_io()
            raise
        return overlap

    def _hold_io(self):
        self._io_held = True
        self._retain()

    def _retire_overlap(self, overlap, issued=True):
        import win32file
        from .live_debug import _cancel_pipe_io
        known = not issued
        if issued:
            try:
                win32file.GetOverlappedResult(self.handle, overlap, False)
                known = True
            except BaseException as exc:
                if getattr(exc, "winerror", None) == 996:
                    try:
                        _cancel_pipe_io(self.handle)
                    except BaseException:
                        pass
                    try:
                        win32file.GetOverlappedResult(self.handle, overlap, True)
                        known = True
                    except BaseException as drained:
                        known = getattr(drained, "winerror", None) in {995, 109, 232, 233, 234}
                else:
                    known = getattr(exc, "winerror", None) in {995, 109, 232, 233, 234}
        record = self._io_owners[id(overlap)]
        if not known:
            self._hold_io()
            raise PermissionError("Installed overlapped I/O retirement is unproven")
        if not record["owner"].close():
            self._hold_io()
            raise PermissionError("Installed overlapped event retirement is unproven")
        del self._io_owners[id(overlap)]

    def _connect_server(self, timeout):
        import win32pipe
        overlap = self._overlap()
        issued = False
        try:
            try:
                issued = True
                code = win32pipe.ConnectNamedPipe(self.handle, overlap)
            except Exception as exc:
                error = getattr(exc, "winerror", None)
                if error == 535:  # documented already-connected, no IRP submitted
                    issued = False
                    return
                if error != 997:
                    issued = False if type(error) is int else True
                    raise
                code = 997
            if code in (0, 535):  # synchronous completion / already connected
                issued = False
                return
            if code != 997:
                raise LiveDebugError("Unexpected owned pipe connection status")
            self._wait(overlap, timeout)
        finally:
            self._retire_overlap(overlap, issued)

    def _read(self, timeout):
        import win32file
        from .live_debug import MAX_FRAME_BYTES
        overlap = self._overlap()
        issued = False
        try:
            buffer = win32file.AllocateReadBuffer(MAX_FRAME_BYTES)
            self._io_owners[id(overlap)]["buffer"] = buffer
            try:
                issued = True
                win32file.ReadFile(self.handle, buffer, overlap)
            except Exception as exc:
                error = getattr(exc, "winerror", None)
                issued = error == 997 if type(error) is int else True
                raise
            count = self._wait(overlap, timeout)
            return bytes(buffer[:count])
        finally:
            self._retire_overlap(overlap, issued)

    def _write(self, raw, timeout):
        import win32file
        overlap = self._overlap()
        issued = False
        self._io_owners[id(overlap)]["buffer"] = raw
        try:
            try:
                issued = True
                win32file.WriteFile(self.handle, raw, overlap)
            except Exception as exc:
                error = getattr(exc, "winerror", None)
                issued = error == 997 if type(error) is int else True
                raise
            if self._wait(overlap, timeout) != len(raw):
                raise LiveDebugError("Incomplete owned pipe write")
        finally:
            self._retire_overlap(overlap, issued)

    def close(self, timeout=None):
        self.cancel()
        acquired = self._io_lock.acquire() if timeout is None else self._io_lock.acquire(timeout=max(0.0, timeout))
        if not acquired:
            return False
        try:
            if self._io_held:
                return False
            if not self._handle_closed:
                owned, self.handle = self.handle, None
                self._handle_closed = True
                self._ambiguous_handle = owned
                try:
                    owned.Close()
                except BaseException:
                    self._close_uncertain = True
                    try:
                        self._discarded_number = owned.Detach()
                    except BaseException:
                        pass
                    self._retain()
                else:
                    self.close_proven = True
                    self._ambiguous_handle = None
            return self.cleanup_proven
        finally:
            self._io_lock.release()


    @property
    def retirement_held(self):
        return self._io_held or self._close_uncertain

    @property
    def cleanup_proven(self):
        return self.close_proven and not self.retirement_held and not self._io_owners

    def _retain(self):
        with _HOLD_LOCK:
            if not any(owner is self for owner in _RETIREMENT_HOLDS):
                _RETIREMENT_HOLDS.append(self)
        if self._on_hold is not None:
            try:
                self._on_hold()
            except BaseException:
                pass  # the exact resource owner is already retained
