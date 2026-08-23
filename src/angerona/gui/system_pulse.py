"""Compact, non-blocking host resource monitor for the main dashboard."""
from __future__ import annotations

import re
import subprocess
import sys
import threading
import time
from collections import deque

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QVBoxLayout,
)


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


def _wifi_signal_windows() -> int | None:
    """Best-effort Wi-Fi signal query, always called outside the GUI thread."""
    if sys.platform != "win32":
        return None
    try:
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        result = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
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
    """Live CPU/RAM/Wi-Fi/network card with sampling off the Qt thread."""

    sample_ready = Signal(object)
    details_requested = Signal()

    def __init__(self, parent=None, interval_ms: int = 2000) -> None:
        super().__init__(parent)
        self.setObjectName("Card")
        self.setCursor(Qt.PointingHandCursor)
        self.setMinimumWidth(205)
        self.setMaximumWidth(340)
        self.setToolTip(
            "Live host health. Sampling runs in a tiny background worker so slow "
            "Windows or Wi-Fi queries cannot freeze the dashboard."
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
        self._wifi = _Metric("WI-FI", "Current Windows Wi-Fi signal strength.")
        self._cpu.add(grid, 0)
        self._ram.add(grid, 2)
        self._wifi.add(grid, 4)
        root.addLayout(grid)

        self._memory = QLabel("Available memory  --")
        self._memory.setStyleSheet("color:#94a3b8; font-size:11px;")
        root.addWidget(self._memory)
        self._network = QLabel("↓ --   ↑ --")
        self._network.setStyleSheet("color:#38bdf8; font-weight:700;")
        self._network.setToolTip(
            "Aggregate receive and send throughput across active network interfaces."
        )
        root.addWidget(self._network)
        root.addStretch(1)

        self._busy = threading.Event()
        self._closed = threading.Event()
        self._sample_requested = threading.Event()
        self._last_net = None
        self._last_net_at = 0.0
        self._wifi_cache: int | None = None
        self._sample_index = 0
        self._latest: dict[str, object] = {}
        self._history: deque[dict[str, object]] = deque(maxlen=90)
        self._sample_revision = 0
        self._rendered_state: tuple[str, str] | None = None
        self._sample_worker = threading.Thread(
            target=self._sample_loop,
            name="SystemPulseSampler",
            daemon=True,
        )
        self._sample_worker.start()
        self.sample_ready.connect(self._apply_sample)
        self._normal_interval_ms = max(1000, int(interval_ms))
        self._chill_interval_ms = max(10_000, self._normal_interval_ms)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.request_sample)
        self._timer.start(self._normal_interval_ms)
        QTimer.singleShot(120, self.request_sample)

    def request_sample(self) -> None:
        window = self.window()
        if (
            self._closed.is_set()
            or self._busy.is_set()
            or not self.isVisible()
            or (window is not None and window.isMinimized())
        ):
            return
        self._busy.set()
        self._sample_requested.set()

    def set_chill_mode(self, enabled: bool) -> None:
        """Reduce cosmetic host sampling while quiet Chill is active."""
        if self._closed.is_set():
            return
        interval = self._chill_interval_ms if enabled else self._normal_interval_ms
        if self._timer.interval() != interval:
            self._timer.start(interval)

    def _sample_loop(self) -> None:
        """Service coalesced sample requests without per-pulse thread churn."""
        while True:
            self._sample_requested.wait()
            self._sample_requested.clear()
            if self._closed.is_set():
                return
            self._sample()

    def _sample(self) -> None:
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
            )
            if self._last_net is not None and self._last_net_at > 0.0:
                seconds = max(0.25, now - self._last_net_at)
                data["down"] = max(0.0, net.bytes_recv - self._last_net.bytes_recv) / seconds
                data["up"] = max(0.0, net.bytes_sent - self._last_net.bytes_sent) / seconds
            else:
                data["down"] = data["up"] = 0.0
            self._last_net = net
            self._last_net_at = now

            # Wi-Fi shell queries are slower, so refresh them only every fifth
            # pulse (~10 seconds) and retain the latest result between queries.
            if self._sample_index % 5 == 0:
                self._wifi_cache = _wifi_signal_windows()
            self._sample_index += 1
            data["wifi"] = self._wifi_cache
        except Exception as exc:
            data["error"] = str(exc)
        finally:
            self._busy.clear()
        if not self._closed.is_set():
            self.sample_ready.emit(data)

    def shutdown(self) -> None:
        """Stop scheduling and discard any late sampler completion."""
        if self._closed.is_set():
            return
        self._closed.set()
        self._timer.stop()
        self._sample_requested.set()

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt signature
        self.shutdown()
        super().closeEvent(event)

    def snapshot(self) -> dict[str, object]:
        """Return a bounded GUI-owned snapshot for the expanded detail view."""
        return {
            "latest": dict(self._latest),
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
        self._cpu.update(f"{cpu:.0f}%", cpu)
        self._ram.update(f"{ram:.0f}%", ram)
        self._wifi.update("Not connected" if wifi is None else f"{int(wifi)}%", wifi)
        memory_text = f"Available memory  {_memory(float(data.get('available', 0.0)))}"
        if self._memory.text() != memory_text:
            self._memory.setText(memory_text)
        network_text = (
            f"↓ {_rate(float(data.get('down', 0.0)))}   "
            f"↑ {_rate(float(data.get('up', 0.0)))}"
        )
        if self._network.text() != network_text:
            self._network.setText(network_text)
