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
    from PySide6.QtWidgets import (QFrame, QHBoxLayout, QLabel, QPushButton,
                                   QScrollArea, QVBoxLayout, QWidget)
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
            self._title.setWordWrap(True)
            self._title.setStyleSheet("font-size:15px; font-weight:800; color:#e8f4ff;")
            self._body = QLabel("")
            self._body.setWordWrap(True)
            self._body.setAlignment(Qt.AlignTop | Qt.AlignLeft)
            self._body.setStyleSheet("color:#cbd5e1; font-size:12px;")
            # Scroll the body so long, detailed steps stay fully readable instead of
            # being clipped by a tight fixed box.
            self._scroll = QScrollArea()
            self._scroll.setWidgetResizable(True)
            self._scroll.setFrameShape(QFrame.NoFrame)
            self._scroll.setWidget(self._body)
            self._scroll.setMaximumHeight(300)
            self._scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
            self._scroll.setStyleSheet("background:transparent; border:none;")
            cl.addWidget(self._title)
            cl.addWidget(self._scroll, 1)
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
            self._callout.setFixedWidth(400)
            self._callout.setMaximumHeight(440)

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
    """Build a rich, click-through tour for the main window from the attributes it
    exposes. Every header control and panel gets its own step; a widget that isn't
    present just centres that step's callout (still readable), so the tour degrades
    gracefully. The callout scrolls, so steps can be as detailed as needed."""
    g = lambda name: getattr(mw, name, None)
    return [
        TourStep("Welcome to Angerona",
                 "This tour walks through every button and panel so you know exactly what "
                 "each one does. Press Next to move on, Skip to leave any time. Nothing here "
                 "changes your system — it's just a guided look around."),
        TourStep("Your dashboard cards",
                 "The cards across the top are your at-a-glance health: how many modules are "
                 "running, alerts seen in the last 24 hours, Critical count, and your live "
                 "Threat level. Threat level stays low until a REAL detection fires — routine "
                 "activity and drills don't inflate it. Click any card to drill into detail.",
                 g("cards")),
        TourStep("Modules panel",
                 "Every sensor and defense module, with a live health dot: green = healthy, "
                 "amber = degraded, red = failed, grey = off. Toggle a module on/off with its "
                 "checkbox, or click its name to open a full inspector (what it does, its last "
                 "events, a self-test, and an editable sandbox copy).",
                 g("modules_panel")),
        TourStep("Live Alerts & SOAR Queue",
                 "The right side has two tabs. LIVE ALERTS is the real-time event feed — click "
                 "any row for full detail plus Allow / Block / Analyze / Research actions. "
                 "SOAR QUEUE holds actions staged for your review before they run. Because ARIA "
                 "now lives in the console below, these stay visible while you chat.",
                 g("_right_tabs")),
        TourStep("ARIA — your assistant & the mic meter",
                 "This is ARIA. The glowing orb tracks your posture score; under it, the 🎤 bar "
                 "shows your live microphone level once voice is on — when it moves as you speak, "
                 "ARIA can hear you. Ask ARIA anything, or tell her to act (\"suspend pid 1234\", "
                 "\"trust my running apps\", \"install voice\"). Every change is confirm-then-execute.",
                 g("aria_hud")),
        TourStep("The ARIA Console",
                 "One prompt bar for everything. Type an incident-response command (ps, kill 1234, "
                 "suspend, trust-running, wd-restart, guide) OR just ask in plain language — anything "
                 "that isn't a command streams to ARIA, whose reply types in live. Try "
                 "\"what's my posture?\" or \"capabilities\".",
                 g("console")),
        TourStep("RUN SELF-TEST",
                 "Runs every module's self-test and an end-to-end pipeline check, so you know your "
                 "sensors actually work. Watch the colour wheel next to the buttons climb red → amber "
                 "→ green to 100%. Results print in the console; any failures offer a one-click fix.",
                 g("_selftest_btn")),
        TourStep("RUN RED TEAM SIMULATION",
                 "Fires an unannounced, non-destructive adversary drill against THIS machine — every "
                 "technique is a benign, reversible marker (no real exploit or persistence). A console "
                 "window shows the live kill-chain, a progress wheel, and an After-Action Report scoring "
                 "how much your defenses detected and remediated.",
                 g("_sim_btn")),
        TourStep("ECO MODE",
                 "One tap to pause the heavy background scanners and free up your machine, while the "
                 "core response path (SOAR, deception, watchdog, heartbeat) stays fully live. Tap again "
                 "to resume — modules wake one at a time, with a progress wheel, so there's no CPU spike.",
                 g("eco_btn")),
        TourStep("WORLD VIEW",
                 "A live map of your outbound connections and where in the world they terminate — handy "
                 "for spotting a process quietly talking to an unexpected country or host.",
                 g("_worldview_btn")),
        TourStep("ATT&CK MAP",
                 "The live MITRE ATT&CK heatmap — 86 techniques across 14 tactics. Cells light up as "
                 "Angerona detects, simulates, or remediates each technique, so you can see your coverage "
                 "and any blind spots at a glance. Click a cell for detail.",
                 g("_attack_btn")),
        TourStep("THREAT INTEL",
                 "The latest CISA KEV (Known Exploited Vulnerabilities) intel correlated to what's on THIS "
                 "host. The button pulses when there's something new that matches your machine.",
                 g("threat_intel_btn")),
        TourStep("FORENSICS",
                 "Deep-dive incident views: the provenance/kill-chain graph, blast-radius mapping for a "
                 "given PID, and the collision/evidence timeline — for after-the-fact investigation.",
                 g("_forensics_btn")),
        TourStep("SETUP & HELP",
                 "SETUP runs the one-swoop wizard (appearance, local AI, voice + microphone, Signal, Teams, "
                 "trusted apps, startup). HELP has a tab for every feature plus a 'Take the tour' button to "
                 "replay this walkthrough any time.",
                 g("_setup_btn")),
        TourStep("SETTINGS",
                 "Fine-grained control of everything: modules, AI keys, ARIA, voice + which microphone to "
                 "use, connectors, and appearance. The panels scroll, so nothing is hidden.",
                 g("_settings_btn")),
        TourStep("STOP — and you're set",
                 "STOP shuts every module down and closes Angerona cleanly (closing the window only hides "
                 "it to the tray). That's the whole dashboard — relaunch this tour any time from HELP ▸ Take "
                 "the tour. Stay safe out there.",
                 g("_stop_btn")),
    ]


if __name__ == "__main__":
    ok, detail = self_test()
    print(f"[tour] self_test: {'PASS' if ok else 'FAIL'} — {detail}")
    raise SystemExit(0 if ok else 1)
