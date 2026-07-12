"""analysis_worker.py — Manual "Analyze" deep-triage for the Alerts panel.

Adds an operator-triggered investigation that runs entirely off the GUI thread.
Local Ollama inference and (optional) cloud escalation both introduce seconds of
latency, so all network work happens inside a QThread worker; the main window
only ever touches Qt signals.

Dual-stage logic
----------------
Stage 1 (local): send a structured JSON prompt to Ollama (llama3:8b on
    loopback :11434) with the alert's PID, process name, ancestry chain, memory
    strings, and network connections. The model must return a verdict and a
    ``confidence_score`` (0-100).
Stage 2 (cloud, opt-in): if the local confidence is below CONFIDENCE_THRESHOLD
    (default 70) OR the local model flags the threat as unknown/novel, escalate
    to the existing Cloud CTI path (cloud_fallback.query_gemini_live) for a
    second opinion. Imported lazily so this module loads even where google-genai
    is absent.

All failures — malformed alert dicts, HTTP timeouts to :11434, dropped
connectivity mid-escalation — are caught and surfaced via the ``error`` signal.
A background failure never propagates into the core agent loop or the GUI thread.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from typing import Any, Optional

from PySide6.QtCore import QThread, Signal, Qt, QTimer
from PySide6.QtWidgets import (
    QWidget, QHBoxLayout, QVBoxLayout, QPushButton, QLabel, QSizePolicy,
)


# ── Tuning ────────────────────────────────────────────────────────────────────
OLLAMA_HOST          = "http://localhost:11434"
OLLAMA_MODEL         = "llama3:8b"
LOCAL_TIMEOUT_S      = 30.0     # manual analyze is user-initiated → can wait longer than triage's 5s
CONFIDENCE_THRESHOLD = 70       # below this (0-100) → escalate to cloud

_ANALYZE_SYSTEM_PROMPT = (
    "You are a Tier-3 SOC analyst performing deep triage on a single endpoint "
    "alert. Analyze the process, its ancestry, memory strings, and network "
    "connections. Respond with ONLY a JSON object, no prose, no markdown fences:\n"
    '{\n'
    '  "verdict": "SAFE" | "SUSPICIOUS" | "MALICIOUS" | "UNKNOWN",\n'
    '  "confidence_score": <integer 0-100>,\n'
    '  "reasoning": "<2-4 sentences>",\n'
    '  "recommended_actions": ["<step>", ...]\n'
    '}\n'
    "Set verdict to UNKNOWN and confidence_score below 70 if the behaviour is "
    "novel or you cannot determine intent from the evidence."
)


def _extract_json(text: str) -> Optional[dict[str, Any]]:
    """Tolerant JSON extraction — models often wrap output in prose/fences."""
    if not text:
        return None
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            return None
    return None


def _build_prompt(alert: dict) -> str:
    """Assemble the structured evidence block. Never raises on missing keys."""
    a = alert or {}
    evidence = {
        "pid":              a.get("pid", "unknown"),
        "process_name":     a.get("process_name") or a.get("target") or "unknown",
        "ancestry_chain":   a.get("ancestry") or a.get("lineage") or [],
        "memory_strings":   (a.get("memory_strings") or [])[:40],   # cap prompt size
        "network_conns":    (a.get("connections") or [])[:40],
        "alert_type":       a.get("type", "unknown"),
        "original_details": a.get("details", ""),
    }
    return "Triage this endpoint alert:\n" + json.dumps(evidence, indent=2, default=str)


class AnalysisWorker(QThread):
    """Runs dual-stage triage in the background. One-shot per instance.

    Signals:
        analysis_started()      — emitted the instant run() begins
        progress(str)           — human-readable stage updates for the UI
        finished(dict)          — final merged result payload
        error(str)              — any caught failure; UI should re-enable + show
    """

    analysis_started = Signal()
    progress         = Signal(str)
    finished         = Signal(dict)
    error            = Signal(str)

    def __init__(self, alert: dict, allow_cloud: bool = True, parent=None) -> None:
        super().__init__(parent)
        self._alert = alert or {}
        self._allow_cloud = allow_cloud

    # ── Stage 1: local Ollama ─────────────────────────────────────────────────
    def _query_ollama(self, prompt: str) -> dict[str, Any]:
        """Blocking Ollama call — safe because we're inside the QThread.

        Raises on transport failure so run() can route it to the error signal.
        """
        payload = json.dumps({
            "model": OLLAMA_MODEL,
            "messages": [
                {"role": "system", "content": _ANALYZE_SYSTEM_PROMPT},
                {"role": "user",   "content": prompt},
            ],
            "stream": False,
            "format": "json",       # ask Ollama to constrain output to JSON
            "keep_alive": "30m",
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{OLLAMA_HOST}/api/chat", data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=LOCAL_TIMEOUT_S) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        content = (data.get("message", {}) or {}).get("content", "")
        parsed = _extract_json(content)
        if parsed is None:
            raise ValueError("local model returned unparseable output")
        return parsed

    # ── Stage 2: cloud escalation (lazy import) ──────────────────────────────
    def _escalate_cloud(self, prompt: str) -> Optional[dict[str, Any]]:
        try:
            try:
                from angerona.engines.cloud_fallback import (
                    query_gemini_live, _CLOUD_SYSTEM_PROMPT)
            except Exception:
                from cloud_fallback import query_gemini_live, _CLOUD_SYSTEM_PROMPT
        except Exception as exc:
            self.progress.emit(f"Cloud escalation unavailable: {exc}")
            return None
        res = query_gemini_live(prompt, _CLOUD_SYSTEM_PROMPT)
        if "error" in res:
            self.progress.emit(f"Cloud escalation error: {res['error']}")
            return None
        return res.get("data")

    @staticmethod
    def _needs_escalation(local: dict) -> bool:
        try:
            conf = int(local.get("confidence_score", 0))
        except (TypeError, ValueError):
            conf = 0
        verdict = str(local.get("verdict", "UNKNOWN")).upper()
        return conf < CONFIDENCE_THRESHOLD or verdict in ("UNKNOWN", "NOVEL")

    # ── Thread body ───────────────────────────────────────────────────────────
    def run(self) -> None:
        self.analysis_started.emit()
        try:
            prompt = _build_prompt(self._alert)

            self.progress.emit("Stage 1 — querying local model (llama3:8b)…")
            local = self._query_ollama(prompt)

            result: dict[str, Any] = {
                "stage": "local",
                "local": local,
                "cloud": None,
                "final_verdict": local.get("verdict", "UNKNOWN"),
                "final_confidence": local.get("confidence_score", 0),
            }

            if self._allow_cloud and self._needs_escalation(local):
                self.progress.emit(
                    "Stage 2 — low local confidence; escalating to Cloud CTI…"
                )
                cloud = self._escalate_cloud(prompt)
                if cloud:
                    result["stage"] = "cloud"
                    result["cloud"] = cloud
                    result["final_verdict"] = cloud.get("verdict", result["final_verdict"])
                    # cloud confidence is 0.0-1.0 → normalise to 0-100
                    cc = cloud.get("confidence")
                    if isinstance(cc, (int, float)):
                        result["final_confidence"] = round(float(cc) * 100)

            self.progress.emit("Analysis complete.")
            self.finished.emit(result)

        except urllib.error.URLError as exc:
            self.error.emit(f"Local model unreachable on :11434 ({exc.reason}).")
        except TimeoutError:
            self.error.emit(f"Local model timed out after {LOCAL_TIMEOUT_S:.0f}s.")
        except Exception as exc:
            self.error.emit(f"Analysis failed: {exc}")


# ── UI: alert actions row (Allow · Block · Analyze) ───────────────────────────
class MarqueeLabel(QLabel):
    """A label that slowly scrolls long text upward so the operator can read the
    whole message inside a fixed-height box. Short text stays static.

    Addresses the doc's request: "any long string of text in a box, have it
    slowly rotate down so the user can read the rest of the message."
    """
    def __init__(self, text: str = "", parent=None) -> None:
        super().__init__(text, parent)
        self.setWordWrap(True)
        self.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.setMaximumHeight(48)
        self._full_text = text
        self._offset = 0
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)

    def setText(self, text: str) -> None:      # type: ignore[override]
        self._full_text = text
        super().setText(text)
        self._offset = 0
        # Only animate when the text visibly overflows the box.
        needs_scroll = self.fontMetrics().boundingRect(
            0, 0, self.width(), 10_000, int(Qt.TextWordWrap), text
        ).height() > self.maximumHeight()
        self._timer.start(120) if needs_scroll else self._timer.stop()

    def _tick(self) -> None:
        # Scroll forward through the message *in order*: advance a start offset,
        # dropping leading sentences as we go, then restart from the full text on
        # wrap. (The old version rotated sentence order — lines[offset:] +
        # lines[:offset] — which resequenced and thus garbled the message.)
        lines = self._full_text.split(". ")
        if len(lines) <= 1:
            self._timer.stop()
            return
        self._offset = (self._offset + 1) % len(lines)
        tail = lines[self._offset:] if self._offset else lines
        super().setText(". ".join(tail))


class AlertActionsRow(QWidget):
    """Drop-in actions row for the Alerts panel: Allow · Block · Analyze.

    The Analyze button disables itself and shows "Analyzing…" while the worker
    runs, so the operator can't spam the local GPU queue; it re-enables on
    finished OR error.
    """
    def __init__(self, alert: dict, on_allow=None, on_block=None, parent=None) -> None:
        super().__init__(parent)
        self._alert = alert
        self._worker: Optional[AnalysisWorker] = None

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)

        self._status = MarqueeLabel(alert.get("details", ""))
        self._status.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        root.addWidget(self._status)

        row = QHBoxLayout()
        self.btn_allow = QPushButton("Allow")
        self.btn_block = QPushButton("Block")
        self.btn_analyze = QPushButton("Analyze")
        for b in (self.btn_allow, self.btn_block, self.btn_analyze):
            row.addWidget(b)
        root.addLayout(row)

        if on_allow:
            self.btn_allow.clicked.connect(on_allow)
        if on_block:
            self.btn_block.clicked.connect(on_block)
        self.btn_analyze.clicked.connect(self._start_analysis)

    def _start_analysis(self) -> None:
        if self._worker and self._worker.isRunning():
            return
        self.btn_analyze.setEnabled(False)
        self.btn_analyze.setText("Analyzing…")

        # Keep a reference — a worker without one is garbage-collected mid-run.
        self._worker = AnalysisWorker(self._alert, allow_cloud=True, parent=self)
        self._worker.progress.connect(self._status.setText)
        self._worker.finished.connect(self._on_finished)
        self._worker.error.connect(self._on_error)
        self._worker.finished.connect(self._worker.deleteLater)
        self._worker.start()

    def _reset_button(self) -> None:
        self.btn_analyze.setEnabled(True)
        self.btn_analyze.setText("Analyze")

    def _on_finished(self, result: dict) -> None:
        self._reset_button()
        verdict = result.get("final_verdict", "UNKNOWN")
        conf = result.get("final_confidence", 0)
        src = "cloud" if result.get("cloud") else "local"
        detail = (result.get("cloud") or result.get("local") or {})
        reason = detail.get("reasoning") or detail.get("justification") or ""
        self._status.setText(f"[{verdict} · {conf}% · {src}] {reason}")

    def _on_error(self, msg: str) -> None:
        self._reset_button()
        self._status.setText(f"⚠ {msg}")
