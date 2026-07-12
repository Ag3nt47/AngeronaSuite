"""World View — deep-transparency host telemetry dialog.

Renders WorldViewEngine's three views on a 1 Hz refresh:
  1. Host-to-Suite comparison matrix (RSS / CPU / threads vs the Windows host).
  2. Telemetry saliency & blinding detector (internal EPS vs host activity).
  3. Local AI deep diagnostics (Ollama VRAM, tokens/sec, queue).

Ollama diagnostics run on a background QThread (not the GUI thread) to prevent
the HTTP timeout from causing a "Not Responding" freeze.
"""
from __future__ import annotations

from PySide6.QtCore import Qt, QThread, QTimer, Signal
from PySide6.QtWidgets import (QDialog, QFrame, QGridLayout, QHBoxLayout, QLabel,
                               QVBoxLayout, QWidget)

from angerona.telemetry.worldview import WorldViewEngine


class _OllamaWorker(QThread):
    """Fetches ollama_diagnostics() off the GUI thread."""
    result = Signal(dict)

    def __init__(self, engine: WorldViewEngine) -> None:
        super().__init__()
        self._engine = engine

    def run(self) -> None:
        try:
            data = self._engine.ollama_diagnostics()
        except Exception as exc:
            data = {"available": False, "reason": str(exc)}
        self.result.emit(data)


def _card(title: str) -> tuple[QFrame, QVBoxLayout]:
    f = QFrame()
    f.setStyleSheet("QFrame{background:#0f1720;border:1px solid #1e2a3a;border-radius:8px;}")
    lay = QVBoxLayout(f)
    t = QLabel(title); t.setStyleSheet("color:#f59e0b;font-weight:bold;")
    lay.addWidget(t)
    return f, lay


class WorldViewDialog(QDialog):
    def __init__(self, parent=None, engine: WorldViewEngine | None = None,
                 event_count_fn=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("World View — Host Telemetry")
        self.resize(720, 560)
        self.setStyleSheet("QDialog{background:#0a0e14;} QLabel{color:#c8d3e0;font-family:Consolas;}")
        self._engine = engine or WorldViewEngine()
        self._event_count_fn = event_count_fn or (lambda: 0)
        self._ollama_worker: _OllamaWorker | None = None

        root = QVBoxLayout(self)
        banner = QLabel(""); banner.setAlignment(Qt.AlignCenter)
        banner.setStyleSheet("font-weight:bold;padding:4px;")
        self._banner = banner
        root.addWidget(banner)

        mf, self._ml = _card("1 · HOST-TO-SUITE RESOURCE MATRIX")
        self._matrix = QLabel("…"); self._matrix.setTextFormat(Qt.RichText)
        self._ml.addWidget(self._matrix); root.addWidget(mf)

        ef, self._el = _card("2 · TELEMETRY SALIENCY / BLINDING DETECTOR")
        self._eps = QLabel("…"); self._eps.setTextFormat(Qt.RichText)
        self._el.addWidget(self._eps); root.addWidget(ef)

        of, self._ol = _card("3 · LOCAL AI DEEP DIAGNOSTICS (Ollama)")
        self._ollama = QLabel("…"); self._ollama.setTextFormat(Qt.RichText)
        self._ol.addWidget(self._ollama); root.addWidget(of)

        # Fast metrics (psutil only) refresh at 1 Hz on the GUI thread.
        # Ollama diagnostics use a background thread and poll every 8 s.
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh_fast)
        self._timer.start(1000)

        self._ollama_timer = QTimer(self)
        self._ollama_timer.timeout.connect(self._kick_ollama)
        self._ollama_timer.start(8000)

        self._refresh_fast()
        QTimer.singleShot(300, self._kick_ollama)  # first Ollama fetch shortly after open

    def closeEvent(self, event) -> None:
        self._timer.stop()
        self._ollama_timer.stop()
        if self._ollama_worker is not None:
            self._ollama_worker.quit()
            self._ollama_worker.wait(1000)
        super().closeEvent(event)

    def _refresh_fast(self) -> None:
        """GUI-thread refresh: only fast, non-blocking psutil calls."""
        # 1 · matrix
        m = self._engine.host_vs_suite_matrix()
        if m.get("available"):
            h, s = m["host"], m["suite"]
            self._matrix.setText(
                f"<b>HOST</b>  RAM {h['used_ram_pct']}% of {h['total_ram_gb']} GB · "
                f"CPU {h['cpu_pct']}% ({h['cpu_logical']} logical) · {h['processes']} procs<br>"
                f"<b>ANGERONA</b>  RSS {s['rss_mb']} MB ({s['rss_pct_of_host']}% of host) · "
                f"CPU {s['cpu_pct']}% · {s['threads']} module threads")
        else:
            self._matrix.setText(f"unavailable — {m.get('reason','')}")

        # 2 · EPS / blinding
        e = self._engine.eps_gauge(self._event_count_fn())
        colour = "#ef4444" if e["alarm"] else ("#f59e0b" if e["blinding_suspected"] else "#22c55e")
        self._eps.setText(
            f"internal <b style='color:{colour}'>{e['internal_eps']} EPS</b> · "
            f"host ctx-switch rate {e['host_ctx_switch_rate']}/s · "
            f"host active: {e['host_active']}")
        if e["alarm"]:
            self._banner.setText(e["banner"])
            self._banner.setStyleSheet("font-weight:bold;padding:4px;color:white;background:#b91c1c;")
        else:
            self._banner.setText("telemetry coherent")
            self._banner.setStyleSheet("font-weight:bold;padding:4px;color:#22c55e;background:#07130a;")

    def _kick_ollama(self) -> None:
        """Launch the Ollama worker if one isn't already running."""
        if self._ollama_worker is not None and self._ollama_worker.isRunning():
            return
        self._ollama_worker = _OllamaWorker(self._engine)
        self._ollama_worker.result.connect(self._on_ollama_result)
        self._ollama_worker.start()

    def _on_ollama_result(self, o: dict) -> None:
        """Slot — called on the GUI thread when the worker finishes."""
        if o.get("available"):
            self._ollama.setText(
                f"model <b>{o.get('model','?')}</b> · VRAM {o.get('vram_mb','?')} MB · "
                f"{o.get('tokens_per_sec','?')} tok/s · queue {o.get('queue','?')}")
        else:
            self._ollama.setText(f"Ollama offline — {o.get('reason','not running')}")
