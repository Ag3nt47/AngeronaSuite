"""Privacy-safe, bounded operational activity for the main dashboard.

This surface deliberately shows only public EventBus fields and coarse module
health counts.  It is not a debugger, source viewer, raw telemetry viewer, or
model-reasoning display.  In particular, ``Event.details`` is never read.

``Event.message`` is a public-summary contract: producers must omit local
identities and put governed evidence in ``Event.details``.  The sanitizer here
is an additional display boundary, not permission to publish raw identifiers.
"""
from __future__ import annotations

from itertools import islice
import re
import time
from typing import Final

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QSizePolicy, QVBoxLayout

from angerona.core.privacy import redact_text


MAX_RECENT_REQUEST: Final = 16
MAX_DISPLAY_ROWS: Final = 5
MAX_MODULE_CHARS: Final = 48
MAX_MESSAGE_CHARS: Final = 112
_MAX_INPUT_CHARS: Final = 4096
_UNSET = object()

_CONTROL = re.compile(r"[\x00-\x1f\x7f]+")
_QUOTED_PATH = re.compile(
    r"(?i)\"(?:[A-Z]:[\\/]|\\\\|~/|/)[^\"\r\n]{0,4096}\"|"
    r"'(?:[A-Z]:[\\/]|\\\\|~/|/)[^'\r\n]{0,4096}'"
)
_DRIVE_PATH = re.compile(r"(?i)\b[A-Z]:[\\/][^\r\n]{0,4096}")
_UNC_PATH = re.compile(r"(?i)\\\\[^\\\s]+\\[^\r\n]{0,4096}")
_POSIX_PATH = re.compile(
    r"(?<![\w.:])(?:~?/)[^\r\n]{1,4096}"
)
_MAC_ADDRESS = re.compile(
    r"(?i)\b(?:(?:[0-9a-f]{2}[:-]){5}|(?:[0-9a-f]{2}[:-]){7})[0-9a-f]{2}\b|"
    r"\b(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}\b"
)
_IDENTITY_VALUE = (
    r"(?:\"[^\"\r\n]{1,4096}\"|'[^'\r\n]{1,4096}'|[^\r\n]{1,4096})"
)
_SSID_IDENTITY = re.compile(
    r"(?i)\b(?:bssid|ssid|network\s+name|wi-?fi\s+network|wireless\s+network)\b"
    r"\s*(?:(?:[:=]|\bis\b|\bnamed\b)\s*)?" + _IDENTITY_VALUE
)
_ADAPTER_IDENTITY = re.compile(
    r"(?i)\b(?:adapter|interface)(?:\s+name)?\b"
    r"\s*(?:(?:[:=]|\bis\b|\bnamed\b)\s*)?" + _IDENTITY_VALUE
)
_ACCOUNT_IDENTITY = re.compile(
    r"(?i)\b(?:user(?:name)?|account(?:\s+name)?|owner)\b"
    r"(?:\s*(?:[:=]|\bis\b|\bnamed\b)\s*|\s+)" + _IDENTITY_VALUE
)
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}")
_JWT = re.compile(
    r"\b[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
)
_PROVIDER_TOKEN = re.compile(
    r"(?i)\b(?:gh[pousr]_|github_pat_|sk-(?:proj-)?|AKIA|ASIA)"
    r"[A-Za-z0-9_-]{8,}\b"
)
_CREDENTIAL = re.compile(
    r"(?i)\b(?:password|passwd|pwd|secret|token|api[-_ ]?key|"
    r"authorization)\b(?:\s*[:=]\s*|\s+)"
    r"(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
_PRIVATE_REASONING = re.compile(
    r"(?i)\b(?:chain[- ]of[- ]thought|hidden reasoning|internal reasoning|"
    r"private reasoning|scratchpad|thought process)\b"
)

_SEVERITY = {
    0: "INFO",
    1: "LOW",
    2: "MEDIUM",
    3: "HIGH",
    4: "CRITICAL",
}
_DEGRADED_STATES = frozenset({"degraded", "critical", "failed"})


def _redact_local_identifiers(value: str) -> str:
    """Apply the dashboard's stricter local-identity display boundary."""
    text = _QUOTED_PATH.sub("[LOCAL_PATH]", value)
    text = _DRIVE_PATH.sub("[LOCAL_PATH]", text)
    text = _UNC_PATH.sub("[LOCAL_PATH]", text)
    text = _POSIX_PATH.sub("[LOCAL_PATH]", text)
    text = _MAC_ADDRESS.sub("[LOCAL_NETWORK_ID]", text)
    text = _SSID_IDENTITY.sub("SSID [LOCAL_NETWORK]", text)
    text = _ADAPTER_IDENTITY.sub("interface [LOCAL_INTERFACE]", text)
    return _ACCOUNT_IDENTITY.sub("account [LOCAL_USER]", text)


def _bounded(value: object, *, limit: int, fallback: str) -> str:
    """Return one redacted, plain-text line with a strict character bound."""
    try:
        raw = str(value if value is not None else "")[:_MAX_INPUT_CHARS]
    except Exception:
        raw = ""
    raw = _CONTROL.sub(" ", raw)
    # Remove credential forms before the shared helper so token-shaped hostnames
    # or punctuation cannot cause a partial replacement.
    raw = _CREDENTIAL.sub("[SENSITIVE]=[REDACTED]", raw)
    raw = _BEARER.sub("Bearer [REDACTED]", raw)
    raw = _JWT.sub("[SECRET]", raw)
    raw = _PROVIDER_TOKEN.sub("[SECRET]", raw)
    raw = _redact_local_identifiers(raw)
    text = redact_text(raw, limit=_MAX_INPUT_CHARS)
    # The shared egress formatter covers UNC/Windows-backslash paths.  This
    # local display has the stricter requirement of also hiding slash-form
    # Windows paths, POSIX paths, and home-relative paths.
    text = _redact_local_identifiers(text)
    text = " ".join(text.split()) or fallback
    maximum = max(1, int(limit))
    if len(text) > maximum:
        text = text[: maximum - 1].rstrip() + "…"
    return text


def safe_module_name(value: object) -> str:
    """Sanitize a module label for the public dashboard surface."""
    return _bounded(value, limit=MAX_MODULE_CHARS, fallback="unknown module")


def safe_activity_message(value: object) -> str:
    """Defense-in-depth sanitize a producer's identity-free public summary."""
    rendered = _bounded(
        value, limit=MAX_MESSAGE_CHARS, fallback="activity observed"
    )
    if _PRIVATE_REASONING.search(rendered):
        return "private model reasoning withheld"
    return rendered


def safe_event_summary(event: object) -> str:
    """Build a bounded summary from EventBus public fields only.

    ``details`` is intentionally absent from this function.  That makes the
    privacy boundary easy to audit and safe even when details contain raw
    paths, command lines, evidence, or credentials.
    """
    try:
        module = safe_module_name(getattr(event, "module", ""))
    except Exception:
        module = "unknown module"
    try:
        message = safe_activity_message(getattr(event, "message", ""))
    except Exception:
        message = "activity observed"
    try:
        severity = _SEVERITY.get(int(getattr(event, "severity", 0)), "EVENT")
    except Exception:
        severity = "EVENT"
    try:
        stamp = time.strftime(
            "%H:%M:%S", time.localtime(float(getattr(event, "ts", 0.0)))
        )
    except Exception:
        stamp = "--:--:--"
    return f"{stamp}  {severity:<8}  {module} — {message}"


class LiveDefenseActivityCard(QFrame):
    """Small revision-aware view of sanitized EventBus and module activity."""

    def __init__(self, bus, manager, parent=None) -> None:
        super().__init__(parent)
        self.bus = bus
        self.manager = manager
        self._last_bus_revision: object = _UNSET
        self._last_module_snapshot: object = _UNSET
        self._render_count = 0

        self.setObjectName("Card")
        self.setMinimumWidth(145)
        self.setMaximumWidth(390)
        explanation = (
            "Observable operations only: up to five sanitized summaries from a "
            "16-event EventBus window plus coarse module health counts. Raw event "
            "details, local identifiers, secrets, source code, and AI chain-of-"
            "thought are never displayed."
        )
        self.setToolTip(explanation)
        self.setAccessibleName("Live defense activity")
        self.setAccessibleDescription(explanation)

        root = QVBoxLayout(self)
        root.setContentsMargins(12, 10, 12, 10)
        root.setSpacing(4)

        title_row = QHBoxLayout()
        title = QLabel("LIVE DEFENSE ACTIVITY")
        title.setObjectName("SectionTitle")
        title.setTextFormat(Qt.PlainText)
        title.setMinimumWidth(0)
        title.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        self._state = QLabel("● EVENT BUS")
        self._state.setTextFormat(Qt.PlainText)
        self._state.setMinimumWidth(0)
        self._state.setStyleSheet(
            "color:#2fe38a; font-size:10px; font-weight:800;"
        )
        self._state.setToolTip(explanation)
        title_row.addWidget(title)
        title_row.addStretch(1)
        title_row.addWidget(self._state)
        root.addLayout(title_row)

        self.summary = QLabel("Modules --/-- running · -- degraded")
        self.summary.setTextFormat(Qt.PlainText)
        self.summary.setMinimumWidth(0)
        self.summary.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        self.summary.setStyleSheet("color:#94a3b8; font-size:11px;")
        self.summary.setAccessibleName("Defense module health summary")
        root.addWidget(self.summary)

        self.rows: list[QLabel] = []
        for index in range(MAX_DISPLAY_ROWS):
            row = QLabel("")
            row.setTextFormat(Qt.PlainText)
            row.setWordWrap(False)
            row.setMinimumWidth(0)
            row.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
            row.setStyleSheet(
                "color:#cbd5e1; font-family:Consolas,monospace; font-size:10px;"
            )
            row.setAccessibleName(f"Sanitized defense activity {index + 1}")
            row.setToolTip(explanation)
            row.hide()
            self.rows.append(row)
            root.addWidget(row)
        root.addStretch(1)

        self.refresh()

    @staticmethod
    def _module_snapshot(manager) -> tuple[tuple[tuple[int, str, str], ...], int, int, int]:
        """Capture only the coarse state needed for counts and change detection."""
        try:
            modules = list(getattr(manager, "modules", {}).values())
        except Exception:
            modules = []
        states: list[tuple[int, str, str]] = []
        running = 0
        degraded = 0
        for module in modules:
            try:
                status = str(getattr(module, "status", "unknown"))[:32].casefold()
            except Exception:
                status = "unknown"
            try:
                health_state = str(
                    getattr(module, "health_state", "unknown")
                )[:32].casefold()
            except Exception:
                health_state = "unknown"
            running += status == "running"
            degraded += health_state in _DEGRADED_STATES
            states.append((id(module), status, health_state))
        states.sort(key=lambda item: item[0])
        return tuple(states), running, degraded, len(modules)

    def _revision(self) -> int | None:
        try:
            return int(self.bus.revision())
        except Exception:
            return None

    def _render_events(self) -> None:
        try:
            recent = self.bus.recent(MAX_RECENT_REQUEST)
            summaries = [
                safe_event_summary(event)
                for event in islice(iter(recent), MAX_DISPLAY_ROWS)
            ]
        except Exception:
            summaries = ["--:--:--  EVENT     EventBus activity unavailable"]
        if not summaries:
            summaries = ["--:--:--  IDLE      Waiting for observable activity"]
        for index, row in enumerate(self.rows):
            if index < len(summaries):
                row.setText(summaries[index])
                row.setToolTip(summaries[index])
                row.show()
            else:
                row.clear()
                row.setToolTip(self.toolTip())
                row.hide()

    def refresh(self) -> bool:
        """Render changes; return ``False`` when both revisions are unchanged."""
        revision = self._revision()
        module_snapshot, running, degraded, total = self._module_snapshot(self.manager)
        bus_changed = revision != self._last_bus_revision
        modules_changed = module_snapshot != self._last_module_snapshot
        if not bus_changed and not modules_changed:
            return False

        if modules_changed:
            self.summary.setText(
                f"Modules {running}/{total} running · {degraded} degraded"
            )
            self._last_module_snapshot = module_snapshot
        if bus_changed:
            self._render_events()
            self._last_bus_revision = revision
        self._render_count += 1
        return True
