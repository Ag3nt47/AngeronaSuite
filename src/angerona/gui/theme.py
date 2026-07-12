"""Theming engine — multiple appearance packages + custom accent tint.

Themes are palette dicts fed into one QSS template, so adding a theme is just
adding a palette. Two presets ship:

  • cyber : Modern Cyber/Infosec — dark, sharp geometric edges, neon accents.
  • crt   : Retro 1980s CRT — green phosphor on black, monospace.

A custom accent colour can override either theme's accent for easy tinting.
"""
from __future__ import annotations

from angerona.core.eventbus import Severity

SEVERITY_COLOR = {
    Severity.INFO: "#6b7280",
    Severity.LOW: "#3b82f6",
    Severity.MEDIUM: "#f97316",   # orange — was amber; easier to read on dark bg
    Severity.HIGH: "#ef4444",     # red    — was orange
    Severity.CRITICAL: "#b91c1c", # deep red, visually distinct from HIGH
}

# Font stacks — each theme picks either a UI-style or mono-style stack.
# Segoe UI: Windows system font — crisp, readable, zero-install.
# Fira Code: beautiful ligature monospace for code / console areas.
_CYBER_FONT = "'JetBrains Mono','Cascadia Mono','Fira Code','Consolas',monospace"
_CRT_FONT   = "'Cascadia Mono','Consolas','Courier New',monospace"
# Slate theme: Segoe UI for the UI surface, Fira Code in code panels.
# The QSS `font-family` on * sets the default; code-area widgets
# (CommandConsolePanel, etc.) override with their own QFont/setStyleSheet.
_SLATE_FONT = "'Segoe UI','Helvetica Neue','Arial',sans-serif"

THEMES = {
    "cyber": {
        "label": "Modern Cyber",
        "bg": "#0a0e14", "panel": "#0f141c", "panel2": "#141b26",
        "border": "#1b2735", "text": "#d6e2f0", "dim": "#5d6e84",
        "accent": "#1f9cff", "accent2": "#ff7a1a", "font": _CYBER_FONT,
        "radius": "10px",
        "alt_row": "#ffffff08",      # alternating table row tint
        "chip_h": "44px",
    },
    "crt": {
        "label": "Retro CRT Terminal",
        "bg": "#000a00", "panel": "#001200", "panel2": "#001a00",
        "border": "#00b347", "text": "#33ff66", "dim": "#1f8a3a",
        "accent": "#39ff14", "accent2": "#00ff66", "font": _CRT_FONT,
        "radius": "2px",
        "alt_row": "#00ff0008",
        "chip_h": "44px",
    },
    # ── Dark Slate ───────────────────────────────────────────────────────
    # A professional, calm palette for extended analyst sessions.
    # Inspired by Tailwind slate — bg=slate-950, panel=slate-900,
    # panel2=slate-800, accent=sky-400.  The accent is desaturated enough
    # to stay readable for hours without eye strain.
    "slate": {
        "label": "Dark Slate",
        "bg": "#020617", "panel": "#0f172a", "panel2": "#1e293b",
        "border": "#334155", "text": "#f1f5f9", "dim": "#94a3b8",
        "accent": "#38bdf8", "accent2": "#fb923c", "font": _SLATE_FONT,
        "radius": "8px",
        "alt_row": "#ffffff06",
        "chip_h": "44px",
    },
}


def available_themes():
    """[(key, label), ...] for the settings dropdown."""
    return [(k, v["label"]) for k, v in THEMES.items()]


def build_qss(name: str = "cyber", accent: str | None = None) -> str:
    p = dict(THEMES.get(name, THEMES["cyber"]))
    # Fill in optional keys that older theme dicts may not have.
    p.setdefault("alt_row", "#ffffff08")
    p.setdefault("chip_h",  "44px")
    if accent:
        p["accent"] = accent
    r = p["radius"]
    return f"""
/* ── Base ─────────────────────────────────────────────────────────────── */
* {{ font-family: {p['font']}; font-size: 13px; color: {p['text']}; }}
QMainWindow, QWidget {{ background: {p['bg']}; }}

/* ── Typography helpers ────────────────────────────────────────────────── */
#Brand     {{ font-size: 26px; font-weight: 800; letter-spacing: 6px; color: {p['accent']}; }}
#Tagline   {{ color: {p['dim']}; font-size: 11px; }}
#PageTitle {{ font-size: 20px; font-weight: 800; letter-spacing: 2px; color: {p['text']}; }}
#SectionTitle {{ font-size: 13px; font-weight: 700; letter-spacing: 1px;
                 color: {p['accent']}; padding: 2px 2px 6px 2px; }}
#Pill {{ border-radius: {r}; padding: 5px 14px; font-weight: 700; }}

/* ── Panels / cards ────────────────────────────────────────────────────── */
#Panel {{ background: {p['panel']}; border: 1px solid {p['border']};
          border-radius: {r}; }}
#Card  {{ background: {p['panel']}; border: 1px solid {p['border']};
          border-left: 3px solid {p['accent']}; border-radius: {r}; }}
#CardValue {{ font-size: 30px; font-weight: 800; color: {p['text']}; }}
#CardLabel {{ color: {p['dim']}; font-size: 11px; letter-spacing: 1px; }}

/* ── Tables — alternating zebra, compact header, hover row ────────────── */
QTableWidget {{
    background: {p['panel']};
    border: 1px solid {p['border']};
    border-radius: {r};
    gridline-color: {p['border']};
    alternate-background-color: {p['alt_row']};
}}
QTableWidget::item {{
    padding: 4px 6px;
    border: none;
}}
QTableWidget::item:alternate {{
    background: {p['alt_row']};
}}
QTableWidget::item:hover {{
    background: {p['accent']}15;
}}
QTableWidget::item:selected {{
    background: {p['accent']}33;
    color: {p['text']};
}}
QHeaderView::section {{
    background: {p['panel2']};
    color: {p['dim']};
    border: none;
    border-bottom: 2px solid {p['accent']}55;
    padding: 6px 8px;
    font-weight: 700;
    letter-spacing: 1px;
    font-size: 11px;
    text-transform: uppercase;
}}

/* ── Buttons ───────────────────────────────────────────────────────────── */
QPushButton#Primary {{
    background: {p['accent']}; color: {p['bg']};
    border: none; border-radius: {r};
    padding: 9px 16px; font-weight: 700;
}}
QPushButton#Primary:hover {{ background: {p['accent2']}; }}
QPushButton {{
    background: {p['panel2']};
    border: 1px solid {p['border']};
    border-radius: {r};
    padding: 7px 14px;
    color: {p['text']};
}}
QPushButton:hover {{
    background: {p['accent']}22;
    border-color: {p['accent']};
}}

/* ── Inputs ────────────────────────────────────────────────────────────── */
QLineEdit, QComboBox, QPlainTextEdit {{
    background: {p['bg']};
    border: 1px solid {p['border']};
    border-radius: {r};
    padding: 7px;
    color: {p['text']};
}}
QComboBox QAbstractItemView {{
    background: {p['panel']};
    color: {p['text']};
    selection-background-color: {p['accent']}44;
}}
QCheckBox::indicator {{ width: 18px; height: 18px; }}
QScrollBar:vertical  {{ background: {p['panel']}; width: 10px; }}
QScrollBar::handle:vertical {{ background: {p['border']}; border-radius: 5px; }}
QScrollBar:horizontal {{ background: {p['panel']}; height: 8px; }}
QScrollBar::handle:horizontal {{ background: {p['border']}; border-radius: 4px; }}

/* ── StatusStrip — background; chips get per-chip inline QSS each tick. */
#StatusStrip {{
    background: {p['panel']};
    border-top: 1px solid {p['border']};
    border-radius: 0px;
    min-height: {p['chip_h']};
}}

/* ── Splitter handles: 3px visible grab lines ─────────────────────────── */
QSplitter::handle:horizontal {{ background: {p['border']}; width: 3px; }}
QSplitter::handle:vertical   {{ background: {p['border']}; height: 3px; }}

/* ── ToolTips ──────────────────────────────────────────────────────────── */
QToolTip {{
    background: {p['panel2']};
    color: {p['text']};
    border: 1px solid {p['border']};
    padding: 4px 8px;
    border-radius: 4px;
}}
"""


# Monospace font string for code/console panels (overrides theme base font).
# Import this wherever a QFont or setStyleSheet needs a coding font.
MONO_FONT_FAMILY = "'Fira Code','Cascadia Mono','JetBrains Mono','Consolas',monospace"

# Back-compat: some modules import DARK_QSS directly.
DARK_QSS = build_qss("cyber")
