"""Low-overhead macOS Observe collector for the Python sensor edition.

This collector provides a useful, honest preview without claiming native
Endpoint Security coverage.  It baselines and then observes process starts and
new established network flows using psutil.  Command lines and usernames are
excluded by default because they commonly contain secrets and personal data.

An entitled native host can be added through ``native_provider``; every native
observation must already be a validated, normalized ``SensorEvent``.
"""
from __future__ import annotations

import time
from collections.abc import Callable, Iterable
from typing import Any

from angerona.core.sensor_events import SensorEvent

ProcessProvider = Callable[[], Iterable[dict[str, Any]]]
NetworkProvider = Callable[[], Iterable[dict[str, Any]]]
NativeProvider = Callable[[], Iterable[SensorEvent]]


def process_snapshot() -> list[dict[str, Any]]:
    import psutil

    result: list[dict[str, Any]] = []
    for proc in psutil.process_iter(["pid", "ppid", "name", "exe", "create_time"]):
        try:
            info = proc.info
            result.append({
                "pid": int(info.get("pid") or 0),
                "ppid": int(info.get("ppid") or 0),
                "name": str(info.get("name") or "unknown")[:512],
                "executable": str(info.get("exe") or "")[:4096],
                "create_time": float(info.get("create_time") or 0.0),
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


class MacOSObserveCollector:
    def __init__(
        self,
        process_provider: ProcessProvider = process_snapshot,
        network_provider: NetworkProvider = network_snapshot,
        native_provider: NativeProvider | None = None,
        *,
        network_every: int = 3,
        state_limit: int = 16_384,
        clock=time.time,
    ) -> None:
        self._process_provider = process_provider
        self._network_provider = network_provider
        self._native_provider = native_provider or (lambda: ())
        self._network_every = max(1, min(60, int(network_every)))
        self._state_limit = max(1024, min(131_072, int(state_limit)))
        self._clock = clock
        self._processes: set[tuple[int, float]] = set()
        self._connections: set[tuple[int, str, str]] = set()
        self._poll_count = 0
        self._baseline_complete = False
        self.degraded_reasons: tuple[str, ...] = ()

    @staticmethod
    def _trim(values: set[tuple], maximum: int) -> set[tuple]:
        if len(values) <= maximum:
            return values
        # State identity is not a security decision; deterministic bounded
        # retention is preferable to unbounded growth during long uptimes.
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
                key = (
                    int(item.get("pid") or 0),
                    float(item.get("create_time") or 0.0),
                )
                if key not in new_keys:
                    continue
                observations.append(SensorEvent(
                    platform="macos",
                    sensor="angerona.macos.observe",
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
                    if key not in new_connections:
                        continue
                    observations.append(SensorEvent(
                        platform="macos",
                        sensor="angerona.macos.observe",
                        kind="network",
                        action="connect",
                        observed_at=now,
                        process={"pid": int(item.get("pid") or 0)},
                        network=item,
                        privacy_classes=("process", "network"),
                    ))
            self._connections = self._trim(connection_keys, self._state_limit)

        for event in self._native_provider():
            if not isinstance(event, SensorEvent) or event.platform != "macos":
                continue
            observations.append(event)
        self.degraded_reasons = tuple(degraded)
        self._baseline_complete = True
        return observations
