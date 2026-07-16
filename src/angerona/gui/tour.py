"""gui/tour.py — interactive "how to use" coach marks.

A guided tour overlay: it dims the window, highlights one UI area at a time,
and shows a callout (title + text + Next/Skip) with an arrow pointing at the
feature. Advance through the steps to learn the dashboard, ARIA, the console,
Setup, etc.

The positioning math (:func:`callout_rect`) is pure and self-tested; the overlay
widget itself is import-guarded so this module imports without a display.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class TourStep:
    title: str
    text: str
    target: object = None      # a QWidget to highlight (None = centre, no highlight)


def callout_rect(target: "tuple[int,int,int,int]", host: "tuple[int,int]",
                 callout: "tuple[int,int]", margin: int = 14) -> "tuple[int,int]":
    """Pick a top-left (x, y) for the callout so it sits beside the target and
    stays fully on-screen. Prefers below the target, then above, then right/left.
    Pure geometry so it can be unit-tested without Qt.

    target = (x, y, w, h) of the highlighted area (in host coords);
    host   = (W, H) window size; callout = (cw, ch) callout size."""
    tx, ty, tw, th = target
    cw, ch = callout
    W, H = host

    def _clamp(x, y):
        return (max(margin, min(x, W - cw - margin)),
                max(margin, min(y, H - ch - margin)))

    # below
    if ty + th + margin + ch <= H:
        return _clamp(tx, ty + th + margin)
    # above
    if ty - margin - ch >= 0:
        return _clamp(tx, ty - margin - ch)
    # right
    if tx + tw + margin + cw <= W:
        return _clamp(tx + tw + margin, ty)
    # left
    if tx - margin - cw >= 0:
        return _clamp(tx - margin - cw, ty)
    # fallback: centre
    return _clamp((W - cw) // 2, (H - ch) // 2)


def self_test() -> "tuple[bool, str]":
    try:
        W, H = 1000, 700
        cw, ch = 300, 140
        # target near top-left → callout goes below, on-screen
        x, y = callout_rect((20, 20, 200, 40), (W, H), (cw, ch))
        assert 0 <= x <= W - cw and 0 <= y <= H - ch and y >= 20 + 40, "below + on-screen"
        # target near bottom → callout goes above
        x2, y2 = callout_rect((20, H - 60, 200, 40), (W, H), (cw, ch))
        assert y2 + ch <= H and y2 < H - 60, "flips above when no room below"
        # target filling height → falls to right/left/centre, still on-screen
        x3, y3 = callout_rect((10, 0, 100, H), (W, H), (cw, ch))
        assert 0 <= x3 <= W - cw and 0 <= y3 <= H - ch, "stays on-screen when boxed in"
        return True, ("callout placement verified — prefers below, flips above near the "
                      "bottom, and always clamps fully on-screen.")
    except AssertionError as exc:
        return False, f"FAIL — {exc}"
    except Exception as exc:  # pragma: no cover
        return False, f"ERROR — {type(exc).__name__}: {exc}"


# ── Qt overlay (import-guarded) ───────────────────────────────────────────────
try:
    from PySide6.QtCore import QRect, Qt
    from PySide6.QtGui import QColor, QPainter, QPen
    from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget
    _HAVE_QT = True
except Exception:  # pragma: no cover
    _HAVE_QT = False


if _HAVE_QT:

    class CoachMarks(QWidget):
        """Overlay that walks the operator through `steps` (list of TourStep)."""

        def __init__(self, host: "QWidget", steps: "list[TourStep]") -> None:
            super().__init__(host)
            self._host = host
            self._steps = [s for s in steps if isinstance(s, TourStep)]
            self._i = 0
            self.setAttribute(Qt.WA_TransparentForMouseEvents, False)
            self.setGeometry(host.rect())

            self._callout = QFrame(self)
            self._callout.setObjectName("Panel")
            self._callout.setStyleSheet(
                "background:#0f141c; border:2px solid #1f9cff; border-radius:10px;")
            cl = QVBoxLayout(self._callout)
            self._title = QLabel("")
            self._title.setStyleSheet("font-size:15px; font-weight:800; color:#e8f4ff;")
            self._body = QLabel("")
            self._body.setWordWrap(True)
            self._body.setStyleSheet("color:#cbd5e1;")
            cl.addWidget(self._title)
            cl.addWidget(self._body)
            row = QHBoxLayout()
            self._step_lbl = QLabel("")
            self._step_lbl.setStyleSheet("color:#94a3b8; font-size:11px;")
            self._skip = QPushButton("Skip tour")
            self._next = QPushButton("Next →")
            self._skip.clicked.connect(self.close)
            self._next.clicked.connect(self._advance)
            row.addWidget(self._step_lbl)
            row.addStretch()
            row.addWidget(self._skip)
            row.addWidget(self._next)
            cl.addLayout(row)
            self._callout.setFixedWidth(320)

        # ── lifecycle ────────────────────────────────────────────────────────
        def start(self) -> None:
            if not self._steps:
                self.close(); return
            self.setGeometry(self._host.rect())
            self.show()
            self.raise_()
            self._render()

        def _advance(self) -> None:
            self._i += 1
            if self._i >= len(self._steps):
                self.close(); return
            self._render()

        def _target_rect(self) -> "Optional[QRect]":
            tgt = self._steps[self._i].target
            if tgt is None:
                return None
            try:
                top_left = tgt.mapTo(self._host, tgt.rect().topLeft())
                return QRect(top_left, tgt.size())
            except Exception:
                return None

        def _render(self) -> None:
            step = self._steps[self._i]
            self._title.setText(step.title)
            self._body.setText(step.text)
            self._step_lbl.setText(f"{self._i + 1} / {len(self._steps)}")
            self._next.setText("Done ✓" if self._i == len(self._steps) - 1 else "Next →")
            self._callout.adjustSize()
            tr = self._target_rect()
            hw, hh = self.width(), self.height()
            cw, ch = self._callout.width(), self._callout.height()
            if tr is None:
                x, y = (hw - cw) // 2, (hh - ch) // 2
            else:
                x, y = callout_rect((tr.x(), tr.y(), tr.width(), tr.height()),
                                    (hw, hh), (cw, ch))
            self._callout.move(int(x), int(y))
            self.update()

        # ── paint: dim + highlight + arrow ───────────────────────────────────
        def paintEvent(self, _evt) -> None:  # noqa: N802
            p = QPainter(self)
            p.setRenderHint(QPainter.Antialiasing)
            p.fillRect(self.rect(), QColor(0, 0, 0, 150))
            tr = self._target_rect()
            if tr is not None:
                # cut a bright hole/border around the target
                pad = 6
                hole = QRect(tr.x() - pad, tr.y() - pad, tr.width() + 2 * pad, tr.height() + 2 * pad)
                p.setCompositionMode(QPainter.CompositionMode_Clear)
                p.fillRect(hole, QColor(0, 0, 0, 0))
                p.setCompositionMode(QPainter.CompositionMode_SourceOver)
                p.setPen(QPen(QColor("#1f9cff"), 3))
                p.drawRoundedRect(hole, 8, 8)
                # arrow from callout toward the target centre
                c = self._callout.geometry().center()
                p.setPen(QPen(QColor("#1f9cff"), 2, Qt.DashLine))
                p.drawLine(c, hole.center())
            p.end()


def build_default_steps(mw) -> "list[TourStep]":
    """Build a tour for the main window from attributes it exposes (best-effort;
    a missing widget just centres that step's callout)."""
    g = lambda name: getattr(mw, name, None)
    return [
        TourStep("Welcome to Angerona",
                 "This 60-second tour points out the main areas. Use Next to move on, "
                 "or Skip any time."),
        TourStep("Your posture & threat level",
                 "These cards show modules running, alerts, and your live Threat level. "
                 "It stays Secure until a REAL detection fires.",
                 g("_cards")),
        TourStep("ARIA — your assistant",
                 "Ask ARIA anything, or tell her to do things (\"suspend pid 1234\", "
                 "\"trust my running apps\"). She types replies live and can talk by voice.",
                 g("aria_hud")),
        TourStep("The Console",
                 "Type commands (ps, kill, trust-running, guide) OR plain questions — "
                 "anything that isn't a command goes to ARIA.",
                 g("console")),
        TourStep("Test your defenses",
                 "RUN SELF-TEST checks your sensors; RUN RED TEAM SIMULATION fires a safe "
                 "drill. Results appear in the console and an after-action report.",
                 g("_selftest_btn")),
        TourStep("Setup & Help",
                 "The SETUP button runs the one-swoop wizard; HELP has tabs for every "
                 "feature. You can relaunch this tour from HELP any time.",
                 g("_help_btn")),
    ]


if __name__ == "__main__":
    ok, detail = self_test()
    print(f"[tour] self_test: {'PASS' if ok else 'FAIL'} — {detail}")
    raise SystemExit(0 if ok else 1)
