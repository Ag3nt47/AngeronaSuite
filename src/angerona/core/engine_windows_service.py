"""Windows SCM host for a separately provisioned, trusted frozen package.

This is a headless machine-service entry, not the per-user desktop IPC host.
The signed installer must register the frozen executable with --engine-service
and provision its protected data root. Current unprovisioned publisher pins
deliberately prohibit installation/use; no source interpreter is elevated.
"""
from __future__ import annotations

import sys
import threading

_SERVICE_RETIREMENT_HOLD = None


def require_package_service() -> None:
    """Package admission only; the engine additionally proves SCM custody."""
    if sys.platform != "win32" or not getattr(sys, "frozen", False):
        raise PermissionError("SCM protection requires an installed signed frozen Windows package")
    from .windows_package_identity import verify_current_msix_authority
    authority = verify_current_msix_authority()
    if not authority.trusted:
        raise PermissionError(authority.reason)


def _run_protected_engine(stop_event: threading.Event) -> int:
    # Complete native SCM/token/process/package/storage admission before even
    # importing Config/headless or opening a signing key. A package alone, an
    # environment flag, or a manually launched same-name process is insufficient.
    from .windows_engine_custody import prepare_engine_custody

    global _SERVICE_RETIREMENT_HOLD

    if _SERVICE_RETIREMENT_HOLD is not None:
        raise RuntimeError("A previous service graph still owns unretired resources")
    custody = prepare_engine_custody()
    lease = control = None
    try:
        from .data_paths import configure_runtime_environment
        from .singleton import acquire_single_instance

        configure_runtime_environment()
        lease = acquire_single_instance()
        if lease is None:
            raise RuntimeError("Another Angerona protection graph already owns this service root")
        from .engine_service_status import ServiceStatusControl

        control = ServiceStatusControl(custody)
        control.start()
        from .headless import run_headless

        return run_headless(stop_event=stop_event, force_chill=True,
                            runtime_control=control, service_custody=custody)
    finally:
        held = bool(control is not None and getattr(control, "graph_retirement_pending", False))
        try:
            try:
                if control is not None:
                    control.close()
                if not held and lease is not None:
                    lease.close()
                if not held:
                    custody.close()
            except BaseException:
                held = True
                raise
        finally:
            if held:
                # Do not release the singleton or native custody while a
                # startup failure still owns a writer, sensor or native pipe.
                _SERVICE_RETIREMENT_HOLD = (custody, lease, control)


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
            _run_protected_engine(self.stop_event)

    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(AngeronaProtectionService)
    servicemanager.StartServiceCtrlDispatcher()
    return 0
