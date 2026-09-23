"""Windows SCM host for a separately provisioned, trusted frozen package.

This is a headless machine-service entry, not the per-user desktop IPC host.
The signed installer must register the frozen executable with --engine-service
and provision its protected data root. Current unprovisioned publisher pins
deliberately prohibit installation/use; no source interpreter is elevated.
"""
from __future__ import annotations

import sys
import threading


def require_package_service() -> None:
    if sys.platform != "win32" or not getattr(sys, "frozen", False):
        raise PermissionError("SCM protection requires an installed signed frozen Windows package")
    from .windows_package_identity import verify_current_msix_authority
    authority = verify_current_msix_authority()
    if not authority.trusted:
        raise PermissionError(authority.reason)


def run_dispatcher() -> int:
    require_package_service()
    import servicemanager
    import win32service
    import win32serviceutil

    class AngeronaProtectionService(win32serviceutil.ServiceFramework):
        _svc_name_ = "AngeronaProtection"
        _svc_display_name_ = "Angerona Protection Engine"
        _svc_description_ = "Signed-package headless Angerona protection"

        def __init__(self, args):
            super().__init__(args)
            self.stop_event = threading.Event()

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self.stop_event.set()

        def SvcShutdown(self):
            self.SvcStop()

        def SvcDoRun(self):
            require_package_service()
            from .data_paths import configure_runtime_environment
            from .headless import run_headless
            from .singleton import acquire_single_instance
            configure_runtime_environment()
            lease = acquire_single_instance()
            if lease is None:
                raise RuntimeError("Another Angerona protection graph already owns this data root")
            try:
                run_headless(stop_event=self.stop_event)
            finally:
                lease.close()

    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(AngeronaProtectionService)
    servicemanager.StartServiceCtrlDispatcher()
    return 0
