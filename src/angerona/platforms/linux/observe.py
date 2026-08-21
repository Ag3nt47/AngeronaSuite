"""Privacy-minimized Linux process, network, and posture observation.

The collector is deliberately useful without root.  It baselines process and
connection state with psutil, then emits only newly observed activity through
Angerona's bounded :class:`~angerona.core.sensor_events.SensorEvent` schema.
Command lines, environment variables, usernames, and file contents are never
collected.  A separate opt-in eBPF module can add kernel telemetry when the
operator deliberately grants the required privileges.
"""
from __future__ import annotations

import platform
import time
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any

from angerona.core.sensor_events import SensorEvent

ProcessProvider = Callable[[], Iterable[dict[str, Any]]]
NetworkProvider = Callable[[], Iterable[dict[str, Any]]]
PostureProvider = Callable[[], Mapping[str, Any]]


def _read_small(path: str, maximum: int = 512) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")[:maximum].strip()
    except OSError:
        return ""


def process_snapshot() -> list[dict[str, Any]]:
    import psutil

    result: list[dict[str, Any]] = []
    for proc in psutil.process_iter(["pid", "ppid", "name", "exe", "create_time", "uids"]):
        try:
            info = proc.info
            uids = info.get("uids")
            uid = int(getattr(uids, "effective", getattr(uids, "real", -1)))
            result.append({
                "pid": int(info.get("pid") or 0),
                "ppid": int(info.get("ppid") or 0),
                "name": str(info.get("name") or "unknown")[:512],
                "executable": str(info.get("exe") or "")[:4096],
                "create_time": float(info.get("create_time") or 0.0),
                "uid": uid,
                "command_line_collected": False,
            })
        except (psutil.AccessDenied, psutil.NoSuchProcess, ValueError, TypeError):
            continue
    return result


def network_snapshot() -> list[dict[str, Any]]:
    import psutil

    result: list[dict[str, Any]] = []
    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, OSError) as exc:
        raise PermissionError(
            "system-wide network snapshot is unavailable in this account context"
        ) from exc
    for conn in connections:
        try:
            if conn.status != psutil.CONN_ESTABLISHED or not conn.raddr:
                continue
            local = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
            remote = f"{conn.raddr.ip}:{conn.raddr.port}"
            result.append({
                "pid": int(conn.pid or 0),
                "local": local,
                "remote": remote,
                "transport": "tcp",
                "status": "established",
            })
        except (AttributeError, TypeError, ValueError):
            continue
    return result


def posture_snapshot() -> dict[str, Any]:
    """Return bounded, non-identifying Linux security posture signals."""
    apparmor = _read_small("/sys/module/apparmor/parameters/enabled", 16)
    selinux = _read_small("/sys/fs/selinux/enforce", 16)
    lsm = _read_small("/sys/kernel/security/lsm", 256)
    lockdown = _read_small("/sys/kernel/security/lockdown", 128)
    unprivileged_bpf = _read_small("/proc/sys/kernel/unprivileged_bpf_disabled", 16)
    return {
        "kernel_release": platform.release()[:256] or "unknown",
        "apparmor_enabled": apparmor.casefold() in {"y", "yes", "1"},
        "selinux_enforcing": selinux == "1",
        "active_lsm": lsm or "unavailable",
        "kernel_lockdown": lockdown or "unavailable",
        "unprivileged_bpf_disabled": unprivileged_bpf or "unavailable",
    }


class LinuxObserveCollector:
    def __init__(
        self,
        process_provider: ProcessProvider = process_snapshot,
        network_provider: NetworkProvider = network_snapshot,
        posture_provider: PostureProvider = posture_snapshot,
        *,
        network_every: int = 3,
        posture_every: int = 12,
        state_limit: int = 16_384,
        clock=time.time,
    ) -> None:
        self._process_provider = process_provider
        self._network_provider = network_provider
        self._posture_provider = posture_provider
        self._network_every = max(1, min(60, int(network_every)))
        self._posture_every = max(1, min(720, int(posture_every)))
        self._state_limit = max(1024, min(131_072, int(state_limit)))
        self._clock = clock
        self._processes: set[tuple[int, float]] = set()
        self._connections: set[tuple[int, str, str]] = set()
        self._posture: dict[str, Any] = {}
        self._poll_count = 0
        self._baseline_complete = False
        self.degraded_reasons: tuple[str, ...] = ()

    @staticmethod
    def _trim(values: set[tuple], maximum: int) -> set[tuple]:
        if len(values) <= maximum:
            return values
        return set(sorted(values, key=repr)[-maximum:])

    def poll(self) -> list[SensorEvent]:
        now = float(self._clock())
        observations: list[SensorEvent] = []
        degraded: list[str] = []

        try:
            processes = list(self._process_provider())
        except Exception as exc:
            processes = []
            degraded.append(f"process observation unavailable: {exc}")
        process_keys = {
            (int(item.get("pid") or 0), float(item.get("create_time") or 0.0))
            for item in processes
        }
        if self._baseline_complete:
            new_keys = process_keys - self._processes
            for item in processes:
                key = (int(item.get("pid") or 0), float(item.get("create_time") or 0.0))
                if key in new_keys:
                    observations.append(SensorEvent(
                        platform="linux",
                        sensor="angerona.linux.observe",
                        kind="process",
                        action="start",
                        observed_at=now,
                        process=item,
                        privacy_classes=("process", "file_metadata"),
                    ))
        self._processes = self._trim(process_keys, self._state_limit)

        self._poll_count += 1
        if self._poll_count == 1 or self._poll_count % self._network_every == 0:
            try:
                connections = list(self._network_provider())
            except Exception as exc:
                connections = []
                degraded.append(f"network observation unavailable: {exc}")
            connection_keys = {
                (
                    int(item.get("pid") or 0),
                    str(item.get("local") or ""),
                    str(item.get("remote") or ""),
                )
                for item in connections
            }
            if self._baseline_complete:
                new_connections = connection_keys - self._connections
                for item in connections:
                    key = (
                        int(item.get("pid") or 0),
                        str(item.get("local") or ""),
                        str(item.get("remote") or ""),
                    )
                    if key in new_connections:
                        observations.append(SensorEvent(
                            platform="linux",
                            sensor="angerona.linux.observe",
                            kind="network",
                            action="connect",
                            observed_at=now,
                            process={"pid": int(item.get("pid") or 0)},
                            network=item,
                            privacy_classes=("process", "network"),
                        ))
            self._connections = self._trim(connection_keys, self._state_limit)

        if self._poll_count == 1 or self._poll_count % self._posture_every == 0:
            try:
                posture = dict(self._posture_provider())
            except Exception as exc:
                posture = {}
                degraded.append(f"security posture unavailable: {exc}")
            if self._baseline_complete and posture and posture != self._posture:
                observations.append(SensorEvent(
                    platform="linux",
                    sensor="angerona.linux.observe",
                    kind="security",
                    action="posture_change",
                    observed_at=now,
                    security=posture,
                    privacy_classes=("system_posture",),
                ))
            self._posture = posture

        self.degraded_reasons = tuple(degraded)
        self._baseline_complete = True
        return observations

    @property
    def posture(self) -> dict[str, Any]:
        return dict(self._posture)

