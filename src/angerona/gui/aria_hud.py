"""gui/aria_hud.py — the ARIA HUD: a pulsing orb tied to the Angerona Score.

A small, self-contained JARVIS-style heads-up display: one glowing orb whose
colour and pulse cadence track the live Angerona Score, a one-line live status,
a posture sparkline (from ``core.posture_history``), and a chat box wired to the
ARIA assistant (``core.assistant``). Reads are live; every action the chat box
can trigger stays behind the assistant's confirm-then-execute gate.

The file is split so the *logic* is testable without a display:

    • :class:`OrbState` / :func:`orb_state` — pure score→visual mapping, self_test'd.
    • :class:`AriaHud` — the PySide6 widget, import-guarded so this module is
      importable (and testable) even where PySide6 isn't installed.

Additive and off by default: nothing constructs the widget until the main window
opts in. Local-first; no network here.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional


# ── Pure visual core (no Qt — fully testable) ─────────────────────────────────
# Tiers mirror core.posture_history._band_for so the HUD and the trend agree.
_TIERS = (
    # min_score, label,      color (hex), pulse_ms (smaller = faster = worse)
    (90, "STRONG",   "#2fe38a", 2200),
    (70, "GUARDED",  "#39b6ff", 1600),
    (50, "ELEVATED", "#ffb020", 1000),
    (0,  "CRITICAL", "#ff4d4d",  560),
)


@dataclass(frozen=True)
class OrbState:
    score: int
    label: str
    color: str
    pulse_ms: int     # full pulse period; faster (smaller) as posture worsens
    status_line: str


def orb_state(score: int, *, active_alerts: int = 0, band_hint: str = "",
              trend_delta: Optional[int] = None) -> OrbState:
    """Map a 0–100 Angerona Score to the orb's colour, pulse and status line.

    Worse posture → warmer colour and a faster pulse (the orb "beats harder"
    when the host is under pressure). Pure and deterministic."""
    s = max(0, min(100, int(score)))
    label, color, pulse = "CRITICAL", _TIERS[-1][2], _TIERS[-1][3]
    for min_score, lbl, col, pms in _TIERS:
        if s >= min_score:
            label, color, pulse = lbl, col, pms
            break
    arrow = ""
    if trend_delta is not None and trend_delta != 0:
        arrow = f"  {'▲' if trend_delta > 0 else '▼'}{abs(trend_delta)}"
    alert_txt = "no active alerts" if active_alerts == 0 else \
        f"{active_alerts} active alert{'s' if active_alerts != 1 else ''}"
    status = f"Angerona Score {s} · {band_hint or label} · {alert_txt}{arrow}"
    return OrbState(s, label, color, pulse, status)


def self_test() -> tuple[bool, str]:
    """Prove the score→visual mapping: correct tiers/colours, a strictly faster
    pulse as posture worsens, clamping, and a sensible status line."""
    try:
        assert orb_state(95).label == "STRONG"
        assert orb_state(75).label == "GUARDED"
        assert orb_state(55).label == "ELEVATED"
        assert orb_state(30).label == "CRITICAL"
        assert orb_state(90).label == "STRONG" and orb_state(89).label == "GUARDED", "tier boundary"

        # pulse strictly speeds up (period decreases) as score drops across tiers
        pulses = [orb_state(s).pulse_ms for s in (95, 75, 55, 30)]
        assert pulses == sorted(pulses, reverse=True) and len(set(pulses)) == 4, \
            "pulse must strictly quicken as posture worsens"

        # colours are distinct per tier
        assert len({orb_state(s).color for s in (95, 75, 55, 30)}) == 4, "distinct tier colours"

        # clamping
        assert orb_state(150).score == 100 and orb_state(-5).score == 0, "score clamped 0..100"

        # status line reflects alerts + trend
        st = orb_state(82, active_alerts=3, trend_delta=+5)
        assert "82" in st.status_line and "3 active alerts" in st.status_line and "▲5" in st.status_line
        assert "no active alerts" in orb_state(88, active_alerts=0).status_line

        return True, ("OK — tiers STRONG/GUARDED/ELEVATED/CRITICAL at 90/70/50 "
                      "boundaries; pulse strictly quickens 2200→560ms as score "
                      "falls; 4 distinct colours; score clamped; status line shows "
                      "score + alerts + trend arrow.")
    except AssertionError as exc:
        return False, f"FAIL — {exc}"
    except Exception as exc:  # pragma: no cover
        return False, f"ERROR — {type(exc).__name__}: {exc}"


# ── Qt widget (import-guarded; optional) ──────────────────────────────────────
try:
    from PySide6.QtCore import Qt, QTimer, Signal
    from PySide6.QtGui import QColor, QPainter, QRadialGradient
    from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                                   QLineEdit, QTextEdit)
    _HAVE_QT = True
except Exception:  # pragma: no cover - environment dependent
    _HAVE_QT = False


if _HAVE_QT:

    class _Orb(QWidget):
        """The pulsing orb. Colour/period come from an :class:`OrbState`."""

        def __init__(self, parent: Optional["QWidget"] = None) -> None:
            super().__init__(parent)
            self.setMinimumSize(160, 160)
            self._state = orb_state(100)
            self._phase = 0.0
            self._timer = QTimer(self)
            self._timer.timeout.connect(self._tick)
            self._timer.start(33)  # ~30 fps cosmetic animation

        def set_state(self, state: OrbState) -> None:
            self._state = state
            self.update()

        def _tick(self) -> None:
            # advance phase using the state's pulse period
            self._phase = (self._phase + 33.0 / max(1, self._state.pulse_ms)) % 1.0
            self.update()

        def paintEvent(self, _evt) -> None:  # noqa: N802 (Qt signature)
            import math
            p = QPainter(self)
            p.setRenderHint(QPainter.Antialiasing)
            w, h = self.width(), self.height()
            cx, cy = w / 2, h / 2
            base = min(w, h) * 0.34
            glow = 1.0 + 0.14 * math.sin(self._phase * 2 * math.pi)  # breathe
            r = base * glow
            col = QColor(self._state.color)
            grad = QRadialGradient(cx, cy, r)
            bright = QColor(col); bright.setAlpha(255)
            faint = QColor(col); faint.setAlpha(0)
            grad.setColorAt(0.0, bright)
            grad.setColorAt(0.55, col)
            grad.setColorAt(1.0, faint)
            p.setBrush(grad)
            p.setPen(Qt.NoPen)
            p.drawEllipse(int(cx - r), int(cy - r), int(2 * r), int(2 * r))
            p.setPen(QColor("#e8f4ff"))
            f = p.font(); f.setPointSize(20); f.setBold(True); p.setFont(f)
            p.drawText(self.rect(), Qt.AlignCenter, str(self._state.score))
            p.end()

    class AriaHud(QWidget):
        """The full HUD panel: orb + status line + sparkline + chat box.

        Wire it with callables so it stays decoupled from the rest of the app::

            hud = AriaHud(
                score_fn=lambda: score_engine.current(),
                alerts_fn=lambda: len(active_alerts),
                sparkline_fn=lambda: history.sparkline(32),
                trend_fn=lambda: history.trend()["delta"],
                ask_fn=lambda text: assistant_handle(text),   # returns str
            )
            hud.refresh()   # call from the main window's slow tick
        """

        submitted = Signal(str)

        def __init__(self, *, score_fn: Callable[[], int],
                     alerts_fn: Optional[Callable[[], int]] = None,
                     sparkline_fn: Optional[Callable[[], str]] = None,
                     trend_fn: Optional[Callable[[], int]] = None,
                     ask_fn: Optional[Callable[[str], str]] = None,
                     parent: Optional["QWidget"] = None) -> None:
            super().__init__(parent)
            self._score_fn = score_fn
            self._alerts_fn = alerts_fn or (lambda: 0)
            self._sparkline_fn = sparkline_fn or (lambda: "")
            self._trend_fn = trend_fn or (lambda: 0)
            self._ask_fn = ask_fn

            self._orb = _Orb(self)
            self._status = QLabel("ARIA online.")
            self._spark = QLabel("")
            self._spark.setStyleSheet("font-family: 'Fira Code', monospace; color:#7fd0ff;")
            self._log = QTextEdit(); self._log.setReadOnly(True)
            self._input = QLineEdit(); self._input.setPlaceholderText("Ask ARIA…")
            self._input.returnPressed.connect(self._on_submit)

            top = QHBoxLayout()
            top.addWidget(self._orb)
            col = QVBoxLayout()
            col.addWidget(self._status)
            col.addWidget(self._spark)
            top.addLayout(col)
            root = QVBoxLayout(self)
            root.addLayout(top)
            root.addWidget(self._log)
            root.addWidget(self._input)

            self.refresh()

        def refresh(self) -> None:
            """Pull live values and repaint. Safe to call every slow tick."""
            try:
                st = orb_state(self._score_fn(), active_alerts=self._alerts_fn(),
                               trend_delta=self._trend_fn())
                self._orb.set_state(st)
                self._status.setText(st.status_line)
                self._spark.setText(self._sparkline_fn())
            except Exception as exc:
                self._status.setText(f"HUD read error: {exc}")

        def _on_submit(self) -> None:
            text = self._input.text().strip()
            if not text:
                return
            self._input.clear()
            self._log.append(f"> {text}")
            self.submitted.emit(text)
            if self._ask_fn is not None:
                try:
                    self._log.append(str(self._ask_fn(text)))
                except Exception as exc:
                    self._log.append(f"[error] {exc}")


if __name__ == "__main__":
    ok, detail = self_test()
    print(f"[aria_hud] self_test: {'PASS' if ok else 'FAIL'} — {detail}")
    print(f"[aria_hud] PySide6 available: {_HAVE_QT}")
    raise SystemExit(0 if ok else 1)
