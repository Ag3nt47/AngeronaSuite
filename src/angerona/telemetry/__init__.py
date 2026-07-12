"""Windows telemetry adapters (kernel-sourced data via supported APIs).

This package isolates all OS-specific data collection so modules stay clean and
testable. Today it provides process/network sampling via psutil/WMI; the
``KernelSensor`` seam below documents where a *signed* ETW or minifilter driver
could plug in later without changing any module code.
"""
