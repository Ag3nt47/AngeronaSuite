"""Compact, non-blocking host resource monitor for the main dashboard."""
from __future__ import annotations

import ipaddress
import math
import os
import re
import socket
import subprocess
import sys
import threading
import time
from collections import deque
from pathlib import Path

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QVBoxLayout,
)
from shiboken6 import isValid

from angerona.gui.presentation_timer import PresentationTimer


SPEED_TEST_INTERVAL_SECONDS = 60 * 60
SPEED_TEST_RETRY_SECONDS = 60
SPEED_TEST_DOWNLOAD_BYTES = 2 * 1024 * 1024
SPEED_TEST_UPLOAD_BYTES = 512 * 1024
_SPEED_TEST_DOWNLOAD_URL = "https://speed.cloudflare.com/__down"
_SPEED_TEST_UPLOAD_URL = "https://speed.cloudflare.com/__up"


def _rate(value: float) -> str:
    value = max(0.0, float(value))
    for suffix in ("B/s", "KB/s", "MB/s", "GB/s"):
        if value < 1024.0 or suffix == "GB/s":
            return f"{value:.0f} {suffix}" if value >= 10 else f"{value:.1f} {suffix}"
        value /= 1024.0
    return "0 B/s"


def _memory(value: float) -> str:
    gib = max(0.0, float(value)) / (1024.0 ** 3)
    return f"{gib:.1f} GB"


def _mbps(value: object) -> str:
    try:
        number = max(0.0, float(value))
    except (TypeError, ValueError, OverflowError):
        return "--"
    return f"{number:.1f} Mbps" if number < 100 else f"{number:.0f} Mbps"


def _connection_kind(
    name: str, *, platform: str | None = None,
    darwin_ports: dict[str, str] | None = None,
) -> str:
    """Classify a local interface without exposing its host-specific name."""
    raw = str(name or "").strip()
    folded = raw.casefold()
    system = sys.platform if platform is None else platform
    if not folded or folded in {"lo", "lo0", "loopback", "loopback pseudo-interface 1"}:
        return "Loopback"
    if system == "darwin" and darwin_ports:
        port = str(darwin_ports.get(raw, "")).casefold()
        if "wi-fi" in port or "airport" in port:
            return "Wi-Fi"
        if "ethernet" in port:
            return "Ethernet"
        if "bluetooth" in port:
            return "Bluetooth"
    if any(token in folded for token in (
        "wireless", "wi-fi", "wifi", "wlan", "airport",
    )) or re.fullmatch(r"wl[a-z0-9_.-]*", folded):
        return "Wi-Fi"
    if any(token in folded for token in (
        "cellular", "mobile", "wwan", "rmnet", "lte", "5g",
    )):
        return "Cellular"
    if any(token in folded for token in (
        "tailscale", "zerotier", "wireguard", "vpn", "utun", "tun", "tap", "ppp",
    )):
        return "VPN"
    if any(token in folded for token in (
        "bluetooth", "pan",
    )):
        return "Bluetooth"
    if any(token in folded for token in (
        "docker", "veth", "vethernet", "vmnet", "virtual", "hyper-v", "bridge", "br-",
    )):
        return "Virtual"
    if (
        any(token in folded for token in ("ethernet", "gbe", "lan"))
        or re.fullmatch(r"(?:eth|enp|eno|ens|em)[a-z0-9_.-]*", folded)
        or (system == "darwin" and re.fullmatch(r"en\d+", folded))
    ):
        return "Ethernet"
    if system == "linux" and Path("/sys/class/net", raw, "wireless").is_dir():
        return "Wi-Fi"
    return "Network"


def _darwin_hardware_ports() -> dict[str, str]:
    """Return networksetup's device-to-port map off the GUI thread."""
    if sys.platform != "darwin":
        return {}
    executable = Path("/usr/sbin/networksetup")
    if not executable.is_file():
        return {}
    try:
        result = subprocess.run(
            [str(executable), "-listallhardwareports"],
            cwd="/usr/sbin",
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C"},
            capture_output=True,
            text=True,
            errors="replace",
            timeout=1.5,
            check=False,
        )
    except Exception:
        return {}
    ports: dict[str, str] = {}
    hardware_port = ""
    for line in result.stdout.splitlines():
        if line.startswith("Hardware Port:"):
            hardware_port = line.partition(":")[2].strip()
        elif line.startswith("Device:") and hardware_port:
            device = line.partition(":")[2].strip()
            if device:
                ports[device] = hardware_port
    return ports


def _preferred_local_ip() -> str:
    """Ask the route table for its IPv4 source without sending a packet."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("192.0.2.1", 9))
            return str(probe.getsockname()[0])
    except OSError:
        return ""


def _active_connection(
    psutil, *, darwin_ports: dict[str, str] | None = None,
) -> tuple[str, str]:
    """Return the best active interface name and its portable connection kind."""
    try:
        stats = psutil.net_if_stats()
        addresses = psutil.net_if_addrs()
        counters = psutil.net_io_counters(pernic=True)
    except Exception:
        return "", "Offline"
    preferred_ip = _preferred_local_ip()
    candidates: list[tuple[int, int, int, str, str]] = []
    for name, status in stats.items():
        if not getattr(status, "isup", False):
            continue
        kind = _connection_kind(name, darwin_ports=darwin_ports)
        if kind == "Loopback":
            continue
        has_routable_ip = False
        preferred = False
        for address in addresses.get(name, ()):
            if getattr(address, "family", None) not in {socket.AF_INET, socket.AF_INET6}:
                continue
            value = str(getattr(address, "address", "")).split("%", 1)[0]
            try:
                parsed = ipaddress.ip_address(value)
            except ValueError:
                continue
            if parsed.is_loopback or parsed.is_unspecified:
                continue
            has_routable_ip = True
            preferred = preferred or value == preferred_ip
        if not has_routable_ip:
            continue
        traffic = counters.get(name)
        total = int(getattr(traffic, "bytes_recv", 0)) + int(
            getattr(traffic, "bytes_sent", 0)
        )
        physical = kind not in {"Virtual", "Network"}
        candidates.append((int(preferred), int(physical), total, name, kind))
    if not candidates:
        return "", "Offline"
    _preferred, _physical, _traffic, name, kind = max(candidates)
    return name, kind


def _quick_speed_test() -> dict[str, float]:
    """Run one bounded HTTPS estimate using public Cloudflare test endpoints."""
    import requests

    session = requests.Session()
    session.headers.update({
        "Accept": "application/octet-stream",
        "Cache-Control": "no-store",
        "User-Agent": "Angerona-System-Pulse/1",
    })
    try:
        started = time.perf_counter()
        first_byte_at: float | None = None
        received = 0
        with session.get(
            _SPEED_TEST_DOWNLOAD_URL,
            params={"bytes": SPEED_TEST_DOWNLOAD_BYTES},
            stream=True,
            allow_redirects=False,
            timeout=(2.0, 4.0),
        ) as response:
            response.raise_for_status()
            for chunk in response.iter_content(chunk_size=64 * 1024):
                if not chunk:
                    continue
                if first_byte_at is None:
                    first_byte_at = time.perf_counter()
                received += len(chunk)
                if received >= SPEED_TEST_DOWNLOAD_BYTES:
                    break
        download_elapsed = max(
            0.001, time.perf_counter() - (first_byte_at or started)
        )
        if received < 64 * 1024:
            raise RuntimeError("download sample too small")

        payload = bytes(SPEED_TEST_UPLOAD_BYTES)
        started = time.perf_counter()
        with session.post(
            _SPEED_TEST_UPLOAD_URL,
            data=payload,
            headers={"Content-Type": "application/octet-stream"},
            stream=True,
            allow_redirects=False,
            timeout=(2.0, 4.0),
        ) as response:
            response.raise_for_status()
        upload_elapsed = max(0.001, time.perf_counter() - started)
        return {
            "speed_download_mbps": received * 8.0 / download_elapsed / 1_000_000.0,
            "speed_upload_mbps": len(payload) * 8.0 / upload_elapsed / 1_000_000.0,
        }
    finally:
        session.close()


def _wifi_signal_windows() -> int | None:
    """Best-effort Wi-Fi signal query, always called outside the GUI thread."""
    if sys.platform != "win32":
        return None
    try:
        from angerona.core.privilege import sanitized_child_environment, trusted_windows_directories
        native = trusted_windows_directories()[1]
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        result = subprocess.run(
            [str(native / "netsh.exe"), "wlan", "show", "interfaces"],
            cwd=str(native), env=sanitized_child_environment(),
            capture_output=True,
            text=True,
            errors="replace",
            timeout=1.5,
            creationflags=flags,
            check=False,
        )
        match = re.search(r"(?im)^\s*Signal\s*:\s*(\d{1,3})\s*%", result.stdout)
        if match:
            return max(0, min(100, int(match.group(1))))
    except Exception:
        pass
    return None


class _SystemPulseCollector:
    """Plain host counters and cache; this object never retains a Qt owner."""

    def __init__(
        self, *, speed_test_interval_s: float = SPEED_TEST_INTERVAL_SECONDS,
        speed_test_enabled: bool = True, speed_test=None,
    ) -> None:
        self._last_net = None
        self._last_net_at = 0.0
        self._wifi_cache: int | None = None
        self._sample_index = 0
        self._darwin_ports: dict[str, str] = {}
        self._connection_name = ""
        self._connection_kind = "Offline"
        self._speed_test_enabled = bool(speed_test_enabled)
        self._speed_test_interval_s = max(60.0, float(speed_test_interval_s))
        self._speed_test = speed_test or _quick_speed_test
        self._speed_test_due_at = 0.0
        self._speed_result: dict[str, object] = {}

    def _refresh_speed_test(self, now: float) -> None:
        if not self._speed_test_enabled or now < self._speed_test_due_at:
            return
        self._speed_test_due_at = now + self._speed_test_interval_s
        if self._connection_kind == "Offline":
            self._speed_result = {"speed_test_error": "Offline"}
            self._speed_test_due_at = now + min(
                SPEED_TEST_RETRY_SECONDS, self._speed_test_interval_s
            )
            return
        try:
            result = dict(self._speed_test())
            down = max(0.0, float(result["speed_download_mbps"]))
            up = max(0.0, float(result["speed_upload_mbps"]))
            if not (math.isfinite(down) and math.isfinite(up) and down > 0.0 and up > 0.0):
                raise ValueError("non-positive speed result")
            self._speed_result = {
                "speed_download_mbps": down,
                "speed_upload_mbps": up,
                "speed_tested_at": time.time(),
                "speed_test_error": "",
            }
        except Exception:
            self._speed_result = {"speed_test_error": "Test unavailable"}

    def __call__(self) -> dict[str, object]:
        data: dict[str, object] = {}
        try:
            import psutil

            now = time.monotonic()
            vm = psutil.virtual_memory()
            net = psutil.net_io_counters()
            data.update(
                cpu=float(psutil.cpu_percent(interval=None)),
                ram=float(vm.percent),
                available=float(vm.available),
                memory_total=float(vm.total),
            )
            if self._last_net is not None and self._last_net_at > 0.0:
                seconds = max(0.25, now - self._last_net_at)
                data["down"] = max(0.0, net.bytes_recv - self._last_net.bytes_recv) / seconds
                data["up"] = max(0.0, net.bytes_sent - self._last_net.bytes_sent) / seconds
            else:
                data["down"] = data["up"] = 0.0
            self._last_net = net
            self._last_net_at = now

            if sys.platform == "darwin" and self._sample_index % 150 == 0:
                self._darwin_ports = _darwin_hardware_ports()
            if self._sample_index % 15 == 0:
                self._connection_name, self._connection_kind = _active_connection(
                    psutil, darwin_ports=self._darwin_ports
                )
            data["connection_type"] = self._connection_kind
            data["connection_interface"] = self._connection_name

            # Wi-Fi shell queries are slower, so refresh them only every fifth
            # pulse (~10 seconds) and retain the latest result between queries.
            if self._sample_index % 5 == 0 and self._connection_kind == "Wi-Fi":
                self._wifi_cache = _wifi_signal_windows()
            elif self._connection_kind != "Wi-Fi":
                self._wifi_cache = None
            self._sample_index += 1
            data["wifi"] = self._wifi_cache
            self._refresh_speed_test(now)
            data.update(self._speed_result)
            for direction, rate_key in (("download", "down"), ("upload", "up")):
                capacity = data.get(f"speed_{direction}_mbps")
                data[f"{direction}_utilization"] = (
                    None if not capacity else min(
                        100.0,
                        float(data[rate_key]) * 8.0 / (float(capacity) * 1_000_000.0) * 100.0,
                    )
                )
        except Exception as exc:
            data["error"] = str(exc)
        return data


class _SystemPulseSampler:
    """One owned plain-Python worker and one latest-result mailbox."""

    def __init__(self, collect) -> None:
        self.collect = collect
        self._lock = threading.Lock()
        self.closed = threading.Event()
        self.busy = threading.Event()
        self.requested = threading.Event()
        self.retired = threading.Event()
        self._pending = False
        self._active = False
        self._result: dict[str, object] | None = None
        self._accepted = self._completed = self._cancelled = 0
        self._discarded = self._failed = 0
        self.thread = threading.Thread(
            target=self._run, name="SystemPulseSampler", daemon=True,
        )

    def request(self) -> bool:
        with self._lock:
            if self.closed.is_set() or self._pending or self._active or self.busy.is_set():
                return False
            self._pending = True
            self._accepted += 1
            self.busy.set()
            self.requested.set()
            return True

    def close(self, *_args) -> None:
        """Close admission and wake idle work; an active native call may remain."""
        with self._lock:
            if self.closed.is_set():
                return
            self.closed.set()
            if self._pending:
                self._pending = False
                self._cancelled += 1
            if self._result is not None:
                self._result = None
                self._discarded += 1
            if not self._active:
                self.busy.clear()
            self.requested.set()

    def drain(self) -> tuple[dict[str, object] | None, bool]:
        with self._lock:
            if self.closed.is_set():
                return None, False
            result, self._result = self._result, None
            return result, self.busy.is_set()

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            return {
                "accepted": self._accepted, "completed": self._completed,
                "cancelled": self._cancelled, "discarded": self._discarded,
                "failed": self._failed, "pending": self._pending,
                "active": self._active, "buffered": self._result is not None,
                "closed": self.closed.is_set(), "retired": self.retired.is_set(),
            }

    def _run(self) -> None:
        try:
            while True:
                self.requested.wait()
                with self._lock:
                    self.requested.clear()
                    if self.closed.is_set():
                        return
                    if not self._pending:
                        continue
                    self._pending = False
                    self._active = True
                failed = False
                try:
                    result = self.collect()
                except BaseException:
                    # A broken provider must not strand busy admission or print
                    # sensitive exception text from a background thread.
                    failed = True
                    result = {"error": "Host sample unavailable"}
                with self._lock:
                    self._active = False
                    self.busy.clear()
                    self._completed += 1
                    self._failed += int(failed)
                    if self.closed.is_set():
                        self._discarded += 1
                    else:
                        if self._result is not None:
                            self._discarded += 1
                        self._result = result
        finally:
            with self._lock:
                self._active = False
                self.busy.clear()
                self.retired.set()


class _Metric:
    def __init__(self, title: str, tooltip: str) -> None:
        self.title = QLabel(title)
        self.value = QLabel("--")
        self.value.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self.value.setStyleSheet("font-weight:700;")
        self.bar = QProgressBar()
        self.bar.setRange(0, 100)
        self.bar.setValue(0)
        self.bar.setTextVisible(False)
        self.bar.setFixedHeight(6)
        self.title.setToolTip(tooltip)
        self.value.setToolTip(tooltip)
        self.bar.setToolTip(tooltip)
        self._rendered: tuple[str, int | None] | None = None

    def add(self, layout: QGridLayout, row: int) -> None:
        layout.addWidget(self.title, row, 0)
        layout.addWidget(self.value, row, 1)
        layout.addWidget(self.bar, row + 1, 0, 1, 2)

    def update(self, value: str, percent: float | None) -> None:
        text = str(value)
        bounded = (
            None
            if percent is None
            else max(0, min(100, int(round(percent))))
        )
        rendered = (text, bounded)
        if rendered == self._rendered:
            return
        self._rendered = rendered
        self.value.setText(text)
        if bounded is None:
            self.bar.setValue(0)
            self.bar.setProperty("unknown", True)
        else:
            self.bar.setProperty("unknown", False)
            self.bar.setValue(bounded)


class SystemPulseCard(QFrame):
    """Live CPU/RAM/link/speed card with all host work off the Qt thread."""

    sample_ready = Signal(object)
    details_requested = Signal()

    def __init__(
        self, parent=None, interval_ms: int = 2000, *,
        speed_test_interval_s: float = SPEED_TEST_INTERVAL_SECONDS,
        speed_test_enabled: bool | None = None, speed_test=None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("Card")
        self.setCursor(Qt.PointingHandCursor)
        self.setMinimumWidth(205)
        self.setMaximumWidth(340)
        self.setToolTip(
            "Live host health. A bounded speed estimate runs at startup and every hour "
            "in a background worker, so network and platform queries cannot freeze the dashboard."
        )

        root = QVBoxLayout(self)
        root.setContentsMargins(12, 10, 12, 10)
        root.setSpacing(6)
        title_row = QHBoxLayout()
        title = QLabel("SYSTEM PULSE")
        title.setObjectName("SectionTitle")
        self._state = QLabel("● LIVE")
        self._state.setStyleSheet("color:#2fe38a; font-size:10px; font-weight:800;")
        title_row.addWidget(title)
        title_row.addStretch()
        title_row.addWidget(self._state)
        details = QLabel("›")
        details.setStyleSheet("color:#38bdf8; font-size:16px; font-weight:800;")
        title_row.addWidget(details)
        root.addLayout(title_row)

        grid = QGridLayout()
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(3)
        grid.setColumnStretch(1, 1)
        self._cpu = _Metric("CPU", "Total processor use across the host.")
        self._ram = _Metric("RAM", "Physical memory in use and available.")
        self._wifi = _Metric(
            "LINK", "Active connection type and Wi-Fi signal when the platform exposes it."
        )
        self._download = _Metric(
            "DOWNLOAD", "Latest bounded Cloudflare estimate and current receive utilization."
        )
        self._upload = _Metric(
            "UPLOAD", "Latest bounded Cloudflare estimate and current send utilization."
        )
        self._cpu.add(grid, 0)
        self._ram.add(grid, 2)
        self._wifi.add(grid, 4)
        self._download.add(grid, 6)
        self._upload.add(grid, 8)
        root.addLayout(grid)

        self._memory = QLabel("Available memory  --")
        self._memory.setWordWrap(True)
        self._memory.setStyleSheet("color:#94a3b8; font-size:11px;")
        root.addWidget(self._memory)
        self._network = QLabel("LIVE  ↓ --   ↑ --")
        self._network.setWordWrap(True)
        self._network.setStyleSheet("color:#38bdf8; font-weight:700;")
        self._network.setToolTip(
            "Aggregate receive and send throughput across active network interfaces."
        )
        root.addWidget(self._network)
        root.addStretch(1)

        self._external_view_active = False
        self._latest: dict[str, object] = {}
        self._history: deque[dict[str, object]] = deque(maxlen=90)
        self._sample_revision = 0
        self._rendered_state: tuple[str, str] | None = None
        if speed_test_enabled is None:
            speed_test_enabled = os.environ.get(
                "ANGERONA_SPEED_TEST_DISABLED", ""
            ).strip().casefold() not in {"1", "true", "yes", "on"}
        self._sampler = _SystemPulseSampler(_SystemPulseCollector(
            speed_test_interval_s=speed_test_interval_s,
            speed_test_enabled=speed_test_enabled,
            speed_test=speed_test,
        ))
        try:
            self._busy = self._sampler.busy
            self._closed = self._sampler.closed
            self._sample_requested = self._sampler.requested
            self._sample_worker = self._sampler.thread
            self.destroyed.connect(self._sampler.close)
            self.sample_ready.connect(self._apply_sample)
            self._normal_interval_ms = max(1000, int(interval_ms))
            self._chill_interval_ms = max(30_000, self._normal_interval_ms)
            self._timer = PresentationTimer(
                self, pressure_sensitive=False, chill_sensitive=False,
                visible_when=lambda: self.isVisible() or self._external_view_active,
            )
            self._timer.timeout.connect(self.request_sample)
            self._timer.start(self._normal_interval_ms)
            # Poll only while a sample is pending. Keeping delivery separate from
            # the presentation cadence preserves immediate manual reads in Chill.
            self._delivery_timer = QTimer(self)
            self._delivery_timer.setSingleShot(True)
            self._delivery_timer.setInterval(25)
            self._delivery_timer.timeout.connect(self._drain_sample)
            app = QApplication.instance()
            if app is not None:
                app.aboutToQuit.connect(self.shutdown)
            self._sample_worker.start()
            QTimer.singleShot(120, self, self.request_sample)
        except BaseException:
            # Start may have launched the native thread before interruption.
            # Close admission without joining or claiming that it has retired.
            self.shutdown()
            raise

    def request_sample(self) -> None:
        if self._closed.is_set():
            return
        window = self.window()
        if (
            self._busy.is_set()
            or not (self.isVisible() or self._external_view_active)
            or (window is not None and (not window.isVisible() or window.isMinimized()))
        ):
            return
        if self._sampler.request() and not self._delivery_timer.isActive():
            self._delivery_timer.start()

    def set_external_view_active(self, enabled: bool) -> None:
        """Share the existing sampler with a visible footer/overview tab."""
        self._external_view_active = bool(enabled)
        self._timer.refresh()

    def set_chill_mode(self, enabled: bool, *, active: bool | None = None) -> None:
        """Reduce cosmetic host sampling while quiet Chill is active."""
        if self._closed.is_set():
            return
        foreground = self.window().isActiveWindow() if active is None else bool(active)
        interval = (self._chill_interval_ms * (1 if foreground else 2)
                    if enabled else self._normal_interval_ms)
        if self._timer.interval() != interval:
            self._timer.setInterval(interval)
        self._timer.refresh()

    def _drain_sample(self) -> None:
        """Deliver plain completed data only on the card's GUI thread."""
        self._delivery_timer.stop()
        data, pending = self._sampler.drain()
        if pending:
            self._delivery_timer.start()
        if data is not None:
            # Slots may destroy this card, so do not access its Qt state after
            # emitting. The worker has no signal or Qt owner to call later.
            self.sample_ready.emit(data)

    def shutdown(self) -> None:
        """Stop scheduling and discard any late sampler completion."""
        sampler = getattr(self, "_sampler", None)
        if sampler is not None:
            sampler.close()
        for name in ("_timer", "_delivery_timer"):
            timer = getattr(self, name, None)
            if timer is not None and isValid(timer):
                timer.stop()

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt signature
        self.shutdown()
        super().closeEvent(event)

    def latest_sample(self) -> dict[str, object]:
        """Copy one retained GUI sample without copying the history."""
        return dict(self._latest)

    def snapshot(self) -> dict[str, object]:
        """Return a bounded GUI-owned snapshot for the expanded detail view."""
        return {
            "latest": self.latest_sample(),
            "history": [dict(sample) for sample in self._history],
            "busy": self._busy.is_set(),
        }

    def sample_revision(self) -> int:
        """Cheap change token for detail views that mirror retained samples."""
        return self._sample_revision

    def sample_busy(self) -> bool:
        """Return sampler activity without copying the retained history."""
        return self._busy.is_set()

    def _set_state(self, text: str, style: str) -> None:
        rendered = (text, style)
        if rendered == self._rendered_state:
            return
        self._rendered_state = rendered
        self._state.setText(text)
        self._state.setStyleSheet(style)

    def mousePressEvent(self, event) -> None:  # noqa: N802 - Qt signature
        if event.button() == Qt.LeftButton:
            self.details_requested.emit()
        super().mousePressEvent(event)

    def _apply_sample(self, data: dict) -> None:
        if self._closed.is_set():
            return
        if data.get("error"):
            self._set_state(
                "● WAIT", "color:#f59e0b; font-size:10px; font-weight:800;"
            )
            return
        self._set_state(
            "● LIVE", "color:#2fe38a; font-size:10px; font-weight:800;"
        )
        sample = dict(data)
        sample["ts"] = time.time()
        self._latest = sample
        self._history.append(sample)
        self._sample_revision += 1
        cpu = float(data.get("cpu", 0.0))
        ram = float(data.get("ram", 0.0))
        wifi = data.get("wifi")
        connection_type = str(data.get("connection_type") or "Offline")
        self._cpu.update(f"{cpu:.0f}%", cpu)
        self._ram.update(f"{ram:.0f}%", ram)
        link_text = connection_type
        if connection_type == "Wi-Fi" and wifi is not None:
            link_text += f" · {int(wifi)}%"
        self._wifi.update(link_text, wifi)
        tested_down = data.get("speed_download_mbps")
        tested_up = data.get("speed_upload_mbps")
        download_utilization = data.get("download_utilization")
        upload_utilization = data.get("upload_utilization")
        speed_error = str(data.get("speed_test_error") or "")
        download_text = speed_error or _mbps(tested_down)
        upload_text = speed_error or _mbps(tested_up)
        if not speed_error and download_utilization is not None:
            download_text += f" · {float(download_utilization):.0f}%"
        if not speed_error and upload_utilization is not None:
            upload_text += f" · {float(upload_utilization):.0f}%"
        self._download.update(
            download_text, download_utilization
        )
        self._upload.update(
            upload_text, upload_utilization
        )
        memory_text = f"Available memory  {_memory(float(data.get('available', 0.0)))}"
        if self._memory.text() != memory_text:
            self._memory.setText(memory_text)
        network_text = (
            f"LIVE  ↓ {_rate(float(data.get('down', 0.0)))}   "
            f"↑ {_rate(float(data.get('up', 0.0)))}"
        )
        if self._network.text() != network_text:
            self._network.setText(network_text)
