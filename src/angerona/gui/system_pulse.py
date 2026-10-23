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


class _SystemPulseCollector:
    """Plain host counters and cache; this object never retains a Qt owner."""

    def __init__(self) -> None:
        self._last_net = None
        self._last_net_at = 0.0
        self._wifi_cache: int | None = None
        self._sample_index = 0

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
        self._memory.setWordWrap(True)
        self._memory.setStyleSheet("color:#94a3b8; font-size:11px;")
        root.addWidget(self._memory)
        self._network = QLabel("↓ --   ↑ --")
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
        self._sampler = _SystemPulseSampler(_SystemPulseCollector())
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
