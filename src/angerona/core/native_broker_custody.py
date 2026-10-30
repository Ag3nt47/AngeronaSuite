"""Resource-only OS-authenticated broker listener and native handle custody.

No policy executor, keys, service enrollment or endpoint authority is granted
by importing this module. Callers retain their own installed-service admission.
"""
from __future__ import annotations

import threading
import time

from . import privileged_pipe as wire
from .privileged_pipe import NativePeer
from .native_pipe_custody import RetainedPipe, native_pipe_retirement_held

_RETIREMENT_LOCK = threading.Lock()
_RETIREMENT_HOLDS: list[object] = []


def native_broker_retirement_held() -> bool:
    with _RETIREMENT_LOCK:
        return bool(_RETIREMENT_HOLDS) or native_pipe_retirement_held()


class NativeCustodyOwner:
    """Known handles close independently once; any ambiguity retains the owner."""
    def __init__(self):
        if native_broker_retirement_held():
            raise PermissionError("Installed native custody retirement is held")
        self.rows = []
        self.closed = False
        self.uncertain = False
        self._close_lock = threading.Lock()
        self._pending_open = None

    def add(self, handle, closer=None):
        if self.closed:
            raise PermissionError("Closed native custody cannot adopt another handle")
        self.rows.append({"handle": handle, "closer": closer or (lambda value: value.Close()), "attempted": False})
        return handle

    def open(self, opener, *args, closer=None, **kwargs):
        """Retain admission across native handle creation, before it returns."""
        with self._close_lock:
            if self.closed or self.uncertain or native_broker_retirement_held():
                raise PermissionError("Native handle admission is held")
            self._pending_open = (opener, args, kwargs)
            try:
                handle = opener(*args, **kwargs)
            except BaseException as exc:
                if type(getattr(exc, "winerror", None)) is int:
                    self._pending_open = None  # native API reported a completed failure, no handle
                else:
                    with _RETIREMENT_LOCK:
                        self.uncertain = True
                        if not any(owner is self for owner in _RETIREMENT_HOLDS):
                            _RETIREMENT_HOLDS.append(self)
                raise
            self.add(handle, closer)
            self._pending_open = None
            if self.uncertain:
                raise PermissionError("Native handle creation overlapped uncertain retirement")
            return handle

    def close(self):
        if not self._close_lock.acquire(blocking=False):
            with _RETIREMENT_LOCK:
                if self.closed and not self.uncertain:
                    return True
                self.uncertain = True
                if not any(owner is self for owner in _RETIREMENT_HOLDS):
                    _RETIREMENT_HOLDS.append(self)
                return False
        try:
            if self.closed:
                return not self.uncertain
            for row in reversed(self.rows):
                row["attempted"] = True
                handle = row["handle"]
                try:
                    row["closer"](handle)
                except BaseException:
                    with _RETIREMENT_LOCK:
                        self.uncertain = True
                    try:
                        row["discarded_number"] = handle.Detach()
                    except BaseException:
                        pass
            with _RETIREMENT_LOCK:
                self.closed = True
                if self.uncertain and not any(owner is self for owner in _RETIREMENT_HOLDS):
                    _RETIREMENT_HOLDS.append(self)
                return not self.uncertain
        finally:
            self._close_lock.release()

    def __enter__(self):
        return self

    def __exit__(self, _kind, exc, _traceback):
        if not self.close():
            if isinstance(exc, wire.PeerAuthenticationError) and exc.fatal:
                return False
            raise PermissionError("Installed native custody cleanup remains unproven")


def _capture_native_peer(handle):
    """Same fixed OS peer proof, with explicit token/process close ownership."""
    import win32api
    import win32pipe
    import win32process
    import win32security
    import win32event
    with NativeCustodyOwner() as owner:
        try:
            wire._impersonate(handle)
        except BaseException as exc:
            with _RETIREMENT_LOCK:
                owner.uncertain = True
                _RETIREMENT_HOLDS.append(owner)
            raise wire.PeerAuthenticationError("Native impersonation admission is unproven", fatal=True) from exc
        try:
            token = owner.open(win32security.OpenThreadToken, win32api.GetCurrentThread(), 8, True)
            user = win32security.ConvertSidToStringSid(win32security.GetTokenInformation(token, win32security.TokenUser)[0])
            groups = win32security.GetTokenInformation(token, win32security.TokenGroups)
            logons = [win32security.ConvertSidToStringSid(sid) for sid, flags in groups if flags & 0xC0000000 == 0xC0000000]
            if len(logons) != 1 or user == "S-1-5-7":
                raise wire.PeerAuthenticationError("Enrolled native logon identity unavailable")
            authentication = str(win32security.GetTokenInformation(token, win32security.TokenStatistics)["AuthenticationId"])
        finally:
            try:
                wire._revert()
            except BaseException as exc:
                with _RETIREMENT_LOCK:
                    owner.uncertain = True
                    _RETIREMENT_HOLDS.append(owner)
                raise wire.PeerAuthenticationError("Native identity reversion is unproven", fatal=True) from exc
        pid = win32pipe.GetNamedPipeClientProcessId(handle)
        process = owner.open(win32api.OpenProcess, 0x00101000, False, pid)
        birth = win32process.GetProcessTimes(process)["CreationTime"].timestamp()
        if win32event.WaitForSingleObject(process, 0) != 258:
            raise wire.PeerAuthenticationError("Native peer process exited")
        return NativePeer(wire._sid(user), logons[0], authentication, pid, birth)


class RetainedBrokerPipeServer(wire.PrivilegedPipeServer):
    """Existing response wire; strict pipe and OS peer handle retirement only."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._start_uncertain = False
        self._raw_owner = None
        self._lifecycle_lock = threading.Lock()

    def _retain_self(self):
        with _RETIREMENT_LOCK:
            if not any(owner is self for owner in _RETIREMENT_HOLDS):
                _RETIREMENT_HOLDS.append(self)

    def start(self):
        if not self._lifecycle_lock.acquire(blocking=False):
            raise PermissionError("Native broker lifecycle is already active")
        try:
            return self._start_known()
        finally:
            self._lifecycle_lock.release()

    def _start_known(self):
        import win32file
        import win32pipe
        if self.pipes or self.stop_event.is_set() or _RETIREMENT_HOLDS or native_pipe_retirement_held():
            raise PermissionError("Installed response listener cannot restart")
        try:
            for index in range(wire.MAX_CLIENTS):
                if self.stop_event.is_set():
                    raise PermissionError("Native listener startup was stopped")
                self._raw_owner = NativeCustodyOwner()
                handle = self._raw_owner.open(win32pipe.CreateNamedPipe, self.endpoint,
                    3 | win32file.FILE_FLAG_OVERLAPPED | (0x80000 if index == 0 else 0),
                    0x8, wire.MAX_CLIENTS, wire.MAX_FRAME + 4, wire.MAX_FRAME + 4, 1000,
                    wire._attributes(self.server_sid, self.allowed_sids))
                pipe = RetainedPipe(handle, on_hold=self.stop_event.set)
                self.pipes.append(pipe)
                self._raw_owner.rows.clear()  # exact native handle ownership transferred to pipe
                self._raw_owner = None
            for index, pipe in enumerate(self.pipes):
                if self.stop_event.is_set():
                    raise PermissionError("Native listener startup was stopped")
                worker = threading.Thread(target=self._serve, args=(pipe,), name=f"RetainedBrokerPipe-{index}", daemon=False)
                self.threads.append(worker)
                worker.start()
        except BaseException:
            self._start_uncertain = True
            self._retain_self()
            self._stop_known(3.0)
            raise

    def _serve(self, pipe):
        import win32pipe
        try:
            while not self.stop_event.is_set():
                connected = False
                try:
                    try:
                        pipe.connect_server(.5)
                    except TimeoutError:
                        continue
                    connected = True
                    frame = wire._read_frame(pipe)
                    if (set(frame) != {"protocol", "nonce", "request"} or frame["protocol"] != wire.PROTOCOL
                            or type(frame["nonce"]) is not str or not wire._NONCE.fullmatch(frame["nonce"])
                            or type(frame["request"]) is not dict):
                        raise wire.BrokerPipeError("Invalid installed response frame")
                    peer = _capture_native_peer(pipe.handle)
                    if peer.user_sid not in self.allowed_sids:
                        raise wire.PeerAuthenticationError("OS peer is outside installed operator enrollment")
                    with self._dispatch_lock:
                        if self.stop_event.is_set():
                            break
                        result = self.dispatch(frame["request"], peer)
                        self.accepted += 1
                    wire._write_response_until_received(pipe, dict(protocol=wire.PROTOCOL, nonce=frame["nonce"], ok=True, result=result))
                except wire.PeerAuthenticationError as exc:
                    self.rejected += 1
                    if exc.fatal:
                        self.error = "Native identity reversion failed; installed response is held"
                        self.stop_event.set()
                except Exception:
                    self.rejected += 1
                finally:
                    if _RETIREMENT_HOLDS or native_pipe_retirement_held():
                        self.error = "Installed native peer cleanup is held"
                        self.stop_event.set()
                    if connected and not self.stop_event.is_set():
                        try:
                            win32pipe.DisconnectNamedPipe(pipe.handle)
                        except Exception:
                            pass
        finally:
            if pipe.close() is not True:
                self.error = "Installed response pipe cleanup is held"
                self.stop_event.set()

    def stop(self, timeout=3.0):
        self.stop_event.set()
        if not self._lifecycle_lock.acquire(blocking=False):
            self._start_uncertain = True
            self._retain_self()
            return False
        try:
            return self._stop_known(timeout)
        finally:
            self._lifecycle_lock.release()

    def _stop_known(self, timeout):
        deadline = time.monotonic() + max(0.0, min(10.0, float(timeout)))
        self.stop_event.set()
        clean = True
        for pipe in self.pipes:
            try:
                pipe.cancel()
            except BaseException:
                clean = False
                self._start_uncertain = True
                self._retain_self()
        for worker in self.threads:
            try:
                if worker.ident is not None and worker is not threading.current_thread():
                    worker.join(max(0.0, deadline - time.monotonic()))
                if worker.ident is None or worker.is_alive():
                    clean = False
            except BaseException:
                clean = False
                self._start_uncertain = True
                self._retain_self()
        for pipe in self.pipes:
            try:
                if pipe.close(max(0.0, deadline - time.monotonic())) is not True:
                    clean = False
            except BaseException:
                clean = False
                self._start_uncertain = True
                self._retain_self()
        if self._raw_owner is not None:
            try:
                if not self._raw_owner.close():
                    clean = False
            except BaseException:
                clean = False
                self._start_uncertain = True
                self._retain_self()
        return clean and not self._start_uncertain and not _RETIREMENT_HOLDS and not native_pipe_retirement_held()
