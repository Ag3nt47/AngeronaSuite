"""Test-only independent, read-only exact-generation kernel observers.

No PID polling after cleanup and no termination permission. Raw creation time
binds an observer before any retirement action; unknown is a test failure.
"""
import ctypes
from ctypes import wintypes

from angerona.core.ugcap_job_witness import JobMemberWitness, NativeJobMemberAPI


class EmptyMembers:
    """Explicit inert empty-job composition; never a production fallback."""
    @staticmethod
    def snapshot(_job):
        return 0, ()

    @staticmethod
    def total(_job):
        return 0


def empty_members():
    return JobMemberWitness(EmptyMembers())


class ObserverPool:
    def __init__(self):
        self.api = NativeJobMemberAPI()
        self.records = {}
        kernel = self.api.api
        kernel.GetCurrentProcess.argtypes, kernel.GetCurrentProcess.restype = [], wintypes.HANDLE
        kernel.DuplicateHandle.argtypes = [wintypes.HANDLE, wintypes.HANDLE,
            wintypes.HANDLE, ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD,
            wintypes.BOOL, wintypes.DWORD]
        kernel.DuplicateHandle.restype = wintypes.BOOL

    def pin_handle(self, source, *, job=None):
        kernel = self.api.api
        process = kernel.GetCurrentProcess()
        output = wintypes.HANDLE()
        assert kernel.DuplicateHandle(process, source, process, ctypes.byref(output),
            0x00101000, False, 0), "independent query/synchronize duplicate unavailable"
        handle = int(output.value)
        try:
            identity = self.api.identity(handle)
            assert identity[0] > 0 and identity[1] > 0
            if job is not None:
                assert self.api.in_job(handle, job), "native job membership unavailable"
            if identity in self.records:
                assert self.api.close(handle)
                handle = None
            else:
                self.records[identity] = handle
                handle = None
            return identity
        finally:
            if handle is not None:
                assert self.api.close(handle)

    def observe_capture(self, monkeypatch):
        original = JobMemberWitness.capture

        def capture(witness, job, deadline):
            result = original(witness, job, deadline)
            for record in witness.records.values() if isinstance(witness.api, NativeJobMemberAPI) else ():
                if record["handle"] is not None:
                    self.pin_handle(record["handle"], job=job)
            return result

        monkeypatch.setattr(JobMemberWitness, "capture", capture)

    def require_retired(self, identity):
        assert identity in self.records, "actual native generation was never retained"
        handle = self.records[identity]
        assert self.api.identity(handle) == identity
        assert self.api.wait(handle, 0) is True, "exact owned kernel generation is not signaled"
        return dict(pid=identity[0], birth_raw=identity[1], wait_object_0=True)

    def require_all_retired(self):
        return [self.require_retired(identity) for identity in self.records]

    def close(self):
        # Consume each value before native closure, even if an assertion fails.
        failed = False
        for identity in tuple(self.records):
            handle = self.records.pop(identity)
            try:
                failed = self.api.close(handle) is not True or failed
            except BaseException:
                failed = True
        assert not failed, "independent observer close outcome unknown"
