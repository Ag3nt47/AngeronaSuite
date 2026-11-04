"""Presentation of a first-party breach projection and external review reports."""
from __future__ import annotations

import json
import html
import weakref
from unicodedata import category
from dataclasses import asdict

from PySide6.QtCore import QEvent, QIODevice, QObject, QSaveFile, Qt, QThread, QTimer, Signal
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import (
    QDialog, QDialogButtonBox, QFileDialog, QGridLayout, QLabel, QPlainTextEdit, QPushButton,
    QApplication, QMessageBox, QToolButton, QVBoxLayout, QWidget,
)
from shiboken6 import isValid

from angerona.core.breach_state import BreachActionAvailability, BreachDisplaySnapshot
from angerona.gui.header_controls import motion_allowed
from angerona.gui.native_retirement import native_retirement_proven, native_start_failed, poll_native_retirement, retain_native_retirement


_REVIEW_CHAR_LIMIT = 96000
_REVIEW_BLOCK_LIMIT = 4000
_REVIEW_COPY_LIMIT = 2 * 1024**2
_REVIEW_EXPORT_LIMIT = 64 * 1024**2
_REPORT_EXPORT_WORKERS = set()
_REPORT_EXPORT_ADMISSION = True
_REVIEW_PRIORITY_KEYS = (
    "state", "message", "case_id", "request_id", "tool", "version", "commit", "sha256",
    "native_state", "tool_state", "scan_progress", "coverage_incomplete", "match_counts",
    "containment_state", "provenance", "report", "details", "native", "zero_breach",
    "coverage", "findings", "references",
)


def _review_projection(data, *, nodes=1024, characters=60000, items=256, depth=12, string=4096):
    """Bound traversal and output without serializing the whole retained report."""
    remaining = [nodes, characters]
    active, counts, locations = set(), {}, []

    def omit(path, reason, count=1):
        counts[reason] = counts.get(reason, 0) + count
        if len(locations) < 24:
            locations.append(dict(path=path[:200], reason=reason, omitted=count))

    def visit(value, path, level):
        if remaining[0] <= 0:
            omit(path, "node budget")
            return None
        remaining[0] -= 1
        if type(value) is str:
            take = min(len(value), string, max(0, remaining[1] // 6 - 2))
            result = value[:take]
            if take < len(value):
                omit(path, "string characters", len(value) - take)
            remaining[1] -= len(json.dumps(result, ensure_ascii=True))
            return result
        if type(value) in (dict, list, tuple):
            if level >= depth or id(value) in active:
                omit(path, "depth or cycle")
                return None
            active.add(id(value))
            try:
                if type(value) is dict:
                    result = {}
                    keys = [key for key in _REVIEW_PRIORITY_KEYS if key in value]
                    inspected = 0
                    for key in value:
                        inspected += 1
                        if len(keys) >= items or inspected > items * 2:
                            break
                        if type(key) is str and key not in _REVIEW_PRIORITY_KEYS:
                            keys.append(key)
                    for key in keys[:items]:
                        if remaining[0] <= 0 or remaining[1] < 16:
                            break
                        if len(key) > 160:
                            continue
                        encoded = json.dumps(key, ensure_ascii=True)
                        if len(encoded) > remaining[1]:
                            continue
                        remaining[1] -= len(encoded)
                        result[key] = visit(value[key], path + "." + key, level + 1)
                    if len(result) < len(value):
                        omit(path, "object members", len(value) - len(result))
                    return result
                result = []
                for index, item in enumerate(value):
                    if index >= items or remaining[0] <= 0 or remaining[1] < 16:
                        break
                    result.append(visit(item, path + f"[{index}]", level + 1))
                if len(result) < len(value):
                    omit(path, "array items", len(value) - len(result))
                return result
            finally:
                active.remove(id(value))
        if value is None or type(value) in (bool, int, float):
            try:
                encoded = json.dumps(value, allow_nan=False)
            except (TypeError, ValueError, OverflowError):
                omit(path, "unsupported or non-finite values")
                return None
            if len(encoded) <= remaining[1]:
                remaining[1] -= len(encoded)
                return value
        omit(path, "unsupported values or scalar budget")
        return None

    return visit(data, "$", 0), counts, locations


def _review_overview(report):
    """Select real workflow/scanner statuses; do not derive a clean-host claim."""
    if type(report) is not dict:
        return {}
    result = {key: report[key] for key in ("state", "message", "request_id", "case_id", "tool",
                                          "coverage_incomplete", "match_counts", "report") if key in report}
    workflow = report.get("scan_progress")
    if type(workflow) is dict:
        result["workflow"] = {key: workflow[key] for key in (
            "stage", "finished", "total", "native_state", "tool_state") if key in workflow}
    details = report.get("details")
    details = details if type(details) is dict else {}
    scanners = {}
    for name in ("native", "zero_breach"):
        source = report.get(name, details.get(name))
        if type(source) is dict:
            scanners[name] = {key: source[key] for key in (
                "state", "error", "coverage_incomplete", "match_counts", "report") if key in source}
    if scanners:
        result["scanners"] = scanners
    return result


_SCAN_STATES = {
    "cancelled": "Cancelled before all selected checks finished.",
    "complete": "Finished its recorded checks.",
    "completed": "Finished its recorded checks.",
    "disabled": "This check was not selected or was disabled.",
    "error": "Stopped with an error.",
    "failed": "Stopped with an error.",
    "findings": "Returned findings for review.",
    "held": "Held before it could finish.",
    "incomplete": "Ended with gaps in coverage.",
    "not-scanned": "No scan result was recorded.",
    "not-started": "Did not start.",
    "preview": "Preview only. No scan ran.",
    "queued": "Waiting to start.",
    "references": "Returned references for context.",
    "running": "Still running.",
    "stopping": "Stopping and retaining available evidence.",
    "timed-out": "Reached the scan time limit.",
    "unavailable": "Could not run or report a result.",
    "withdrawn": "Returned withdrawn entries for context.",
}
_NATIVE_EVIDENCE_NAMES = {
    "chromium-hsts": "Browser security record",
    "hosts-override": "Local address override",
    "selected-path-signature": "File signature in a selected location",
    "ifeo-debugger": "Windows image debugger configuration",
    "silent-process-exit-monitor": "Windows exit-monitor configuration",
    "windows-temp-file": "Windows temporary-file advisory",
}
_WINDOWS_TEMP_REASON_TEXT = {
    "platform-unavailable": "The Windows temporary-file check was unavailable on this platform.",
    "setting-unverified": "The configured Windows temporary-folder setting could not be verified.",
    "scope-unverified": "The configured Windows temporary folder could not be verified as a plain local folder on a fixed drive.",
    "scan-unconfirmed": "The scan did not verify a completed sample.",
    "scan-limited": "The scanner reported a limit without a more specific recorded reason.",
    "cancelled": "The sample was cancelled.",
    "rejected": "The file scanner declined the configured folder during validation.",
    "deadline": "The sample reached its time limit.",
    "directory-limit": "The sample reached its limit for folders it could visit.",
    "directory-queue-limit": "The sample reached its limit for folders it could queue.",
    "directory-entry-limit": "The sample reached its limit for items listed in folders.",
    "byte-budget": "The sample hit its total data limit.",
    "file-budget": "The sample reached its file-count limit.",
    "per-file-budget": "At least one file exceeded the size limit for a single file.",
    "signature-limit": "The sample reached its limit for recorded signature matches.",
    "signatures-unavailable": "Signature checks were unavailable.",
}
_TOOLKIT_ROW_NAMES = {
    "tool-finding": "Finding",
    "reference": "Reference",
    "withdrawn": "Withdrawn entry",
}
_TECHNICAL_TERMS = (
    "An indicator is a pattern or known value checked against local evidence. "
    "An advisory is something Angerona observed for review. A reference gives context. "
    "A withdrawn entry is no longer an active indicator in its source. "
    "A coverage gap is a check or source that could not be fully reviewed. "
    "HSTS is a browser instruction to use a secure connection for a website."
)


def _report_mapping(value):
    return value if type(value) is dict else {}


def _summary_literal(value, limit=220):
    if type(value) is not str:
        return ""
    cleaned = "".join(" " if category(char)[0] == "C" else char for char in value[:limit])
    cleaned = " ".join(cleaned.split())
    return cleaned + "…" if cleaned and len(value) > limit else cleaned


def _recorded_token(value):
    return value if type(value) is str and len(value) <= 40 else ""


def _scan_state(report):
    return _SCAN_STATES.get(_recorded_token(report.get("state")), "Status was not recorded.")


def _native_summary(native):
    lines = ["Native Angerona advisories", _scan_state(native)]
    artifact_checks = _report_mapping(_report_mapping(native.get("coverage")).get("artifact_checks"))
    temp_check = _report_mapping(artifact_checks.get("windows-temp"))
    checked, skipped = temp_check.get("checked"), temp_check.get("skipped")
    if (_recorded_token(native.get("state")) != "disabled"
            and _recorded_token(temp_check.get("state")) == "completed"
            and type(checked) is int and 0 <= checked <= 64 and type(skipped) is int and skipped == 0):
        label = "file" if checked == 1 else "files"
        lines.append(f"The Windows temporary-file sample checked {checked} {label}.")
    counts = _report_mapping(native.get("finding_counts"))
    advisory, omitted = counts.get("advisory"), counts.get("omitted")
    rows = native.get("findings")
    if (type(advisory) is int and type(omitted) is int and 0 <= omitted <= advisory <= 2**31 - 1
            and type(rows) in (list, tuple) and advisory - omitted == len(rows)):
        label = "advisory" if advisory == 1 else "advisories"
        lines.append(f"This scan recorded {advisory} native {label}.")
        if omitted:
            lines.append(f"The native report omitted {omitted} advisory rows from its bounded list.")
    elif _recorded_token(native.get("state")) != "disabled":
        lines.append("A count of native advisories was not recorded.")
    shown = 0
    if type(rows) in (list, tuple):
        for item in rows[:64]:
            if (type(item) is not dict or type(item.get("classification")) is not str
                    or item["classification"] != "advisory"
                    or item.get("response_authorized") is not False):
                continue
            kind = item.get("evidence_type")
            title = _NATIVE_EVIDENCE_NAMES.get(kind) if type(kind) is str else None
            if type(kind) is str and kind == "windows-temp-file":
                summary = "Review the technical details for this sampled file."
            else:
                summary = _summary_literal(item.get("summary"))
            if title and summary:
                lines.append(f"• {title} — {summary}")
                shown += 1
                if shown == 4:
                    break
        if shown < len(rows):
            lines.append("The technical report has more native row detail.")
    return lines


def _toolkit_summary(toolkit):
    lines = ["Zero-Breach toolkit findings and references", _scan_state(toolkit)]
    state = _recorded_token(toolkit.get("state"))
    if state in _SCAN_STATES and state != "disabled":
        lines.append(
            "When Zero-Breach runs through Angerona, its temporary-folder setting points to a private scan folder. "
            "It may miss your configured Windows temporary folder if it is outside the other locations the toolkit checks."
        )
    counts = _report_mapping(toolkit.get("match_counts"))
    names = ("total", "tool_findings", "references", "withdrawn", "displayed", "omitted")
    if (all(type(counts.get(name)) is int and 0 <= counts[name] <= 4000 for name in names)
            and counts["total"] == counts["tool_findings"] + counts["references"] + counts["withdrawn"]
            and counts["total"] == counts["displayed"] + counts["omitted"]):
        findings, references, withdrawn = (counts[key] for key in names[1:4])
        finding_label = "finding" if findings == 1 else "findings"
        reference_label = "contextual reference" if references == 1 else "contextual references"
        withdrawn_label = "withdrawn entry" if withdrawn == 1 else "withdrawn entries"
        lines.append(f"{findings} {finding_label}, {references} {reference_label}, and {withdrawn} {withdrawn_label}.")
        if counts["omitted"]:
            lines.append(f"The toolkit report omitted {counts['omitted']} rows from its bounded list.")
    elif state != "disabled":
        lines.append("Toolkit classification counts were not recorded.")
    rows = toolkit.get("findings")
    if type(rows) in (list, tuple):
        examples = {kind: [] for kind in _TOOLKIT_ROW_NAMES}
        for item in rows[:200]:
            if type(item) is not dict:
                continue
            kind = _recorded_token(item.get("classification"))
            if kind not in examples or len(examples[kind]) >= 3:
                continue
            label = next((text for key in ("indicator", "artifact", "check", "family")
                          if (text := _summary_literal(item.get(key), 160))), "")
            if label:
                examples[kind].append(label)
        for kind, labels in examples.items():
            lines.extend(f"• {_TOOLKIT_ROW_NAMES[kind]} — {label}" for label in labels)
        if sum(map(len, examples.values())) < len(rows):
            lines.append("The technical report has more toolkit row detail.")
    return lines


def _scan_coverage(report, native, toolkit):
    lines = ["Coverage gaps"]
    for label, source in (("Native Angerona", native), ("Zero-Breach", toolkit)):
        state = _recorded_token(source.get("state"))
        if state == "disabled":
            continue
        incomplete = source.get("coverage_incomplete")
        if incomplete is True:
            lines.append(f"• {label} reported incomplete coverage.")
        elif incomplete is not False:
            lines.append(f"• {label} did not report whether coverage was complete.")
        elif state not in ("complete", "completed", "findings", "references", "withdrawn"):
            lines.append(f"• {label} did not finish its selected work.")

    native_coverage = _report_mapping(native.get("coverage"))
    for key, label in (("processes", "Process inventory"), ("connections", "Connection inventory"),
                       ("memory", "Memory sampling"), ("persistence", "Startup configuration")):
        entry = native_coverage.get(key)
        record = _report_mapping(entry)
        status = _recorded_token(record.get("status"))
        if (record.get("complete") is False or status in ("partial", "unavailable", "failed")
                or _recorded_token(entry) in ("disabled", "no-processes")):
            lines.append(f"• {label} was limited or unavailable.")
    artifact_coverage = _report_mapping(native_coverage.get("artifact_checks"))
    for key, label in (("browser", "Native browser records"), ("hosts", "Native hosts-file check"),
                       ("selected", "Native selected-file checks"),
                       ("windows-launch", "Native Windows launch configuration"),
                       ("windows-temp", "Native Windows temporary-file sample")):
        entry = _report_mapping(artifact_coverage.get(key))
        state = _recorded_token(entry.get("state"))
        checked, skipped = entry.get("checked"), entry.get("skipped")
        if state in ("partial", "unavailable") or (type(skipped) is int and skipped > 0):
            if key == "windows-temp":
                line = f"• {label} was incomplete."
                if type(checked) is int and 0 <= checked <= 64:
                    unit = "file" if checked == 1 else "files"
                    line += f" Checked {checked} {unit}."
                reason = _WINDOWS_TEMP_REASON_TEXT.get(_recorded_token(entry.get("reason")))
                if reason:
                    line += f" {reason}"
                lines.append(line)
            elif type(checked) is int and type(skipped) is int and 0 <= checked < 2**31 and 0 <= skipped < 2**31:
                lines.append(f"• {label} had limits. Checked {checked} and skipped {skipped}.")
            else:
                lines.append(f"• {label} was limited or unavailable.")

    skipped = _report_mapping(toolkit.get("coverage")).get("not_checked")
    if type(skipped) is str and len(skipped) <= 8192:
        try:
            skipped = json.loads(skipped)
        except (ValueError, RecursionError):
            skipped = None
    if type(skipped) in (list, tuple):
        for item in skipped[:4]:
            row = _report_mapping(item)
            check = _summary_literal(row.get("check")) or _summary_literal(item)
            reason = _summary_literal(row.get("reason"))
            if check:
                lines.append(f"• Toolkit skipped {check}." + (f" {reason}" if reason else ""))
        if len(skipped) > 4:
            lines.append("• More skipped checks are available in technical details.")
    error = _summary_literal(report.get("error"))
    if error:
        lines.append(f"• Reported problem — {error}")
    if len(lines) == 1:
        lines.append("No coverage gaps were listed for the recorded checks.")
    return lines


def _plain_scan_summary(report):
    report = _report_mapping(report)
    details = _report_mapping(report.get("details"))
    native = _report_mapping(report.get("native")) or _report_mapping(details.get("native"))
    toolkit = (_report_mapping(details.get("zero_breach")) or _report_mapping(report.get("zero_breach"))
               or _report_mapping(report.get("partial_result")))
    if not toolkit and _recorded_token(report.get("active_action")) == "scan":
        toolkit = report
    sections = (
        ["Spyware Scan summary", _scan_state(report)],
        _native_summary(native), _toolkit_summary(toolkit), _scan_coverage(report, native, toolkit),
        ["These results describe recorded checks and leads. They cannot establish that the PC is infection-free."],
    )
    return "\n\n".join("\n".join(section) for section in sections)


def _render_review_json(data):
    preview, counts, locations = _review_projection(data)
    if not counts:
        rendered = json.dumps(preview, indent=2, ensure_ascii=True, allow_nan=False)
        if len(rendered) <= _REVIEW_CHAR_LIMIT and rendered.count("\n") + 1 < _REVIEW_BLOCK_LIMIT - 10:
            return rendered
    overview, summary_counts, _summary_locations = _review_projection(
        _review_overview(data), nodes=128, characters=4096, items=32, depth=6, string=512)
    display = dict(kind="Bounded review preview", omission_counts=counts,
                   omitted_locations=locations, overview_omissions=summary_counts,
                   original_access="Copy complete JSON (2 MiB limit) or Export complete JSON (64 MiB limit); the retained report is unchanged.",
                   authority="A display excerpt does not change findings, coverage, completion, trust or response authority.")
    envelope = dict(review_display=display, overview=overview, report_preview=preview)
    rendered = json.dumps(envelope, indent=2, ensure_ascii=True, allow_nan=False)
    if len(rendered) > _REVIEW_CHAR_LIMIT or rendered.count("\n") + 1 >= _REVIEW_BLOCK_LIMIT - 10:
        display["format"] = "Compact JSON preserves the display bounds; no serialized text is cut."
        rendered = json.dumps(envelope, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
    if len(rendered) > _REVIEW_CHAR_LIMIT:
        # Fixed-size valid JSON fallback; never slice a serialized document.
        rendered = json.dumps(dict(review_display=dict(
            kind="Preview budget exceeded", omitted=True,
            original_access=display["original_access"], authority=display["authority"]),
            overview=overview), indent=2, ensure_ascii=True, allow_nan=False)
    return rendered


def _complete_report_chunks(data, limit):
    """Bound explicit full-report export; a limit failure never yields success."""
    active, visited = set(), [0]

    def check(value, depth):
        visited[0] += 1
        if visited[0] > 250000 or depth > 64:
            raise ValueError("Complete JSON exceeds the supported node/depth limit; use the preserved backend original.")
        if type(value) is str:
            # Bound the largest encoder chunk before encoding it. This is a
            # conservative bound; export allows a larger limit than clipboard.
            if len(value) > limit // 6:
                raise ValueError("A value exceeds this complete-JSON size limit; use export or the preserved backend original.")
            return
        if value is None or type(value) in (bool, int, float):
            json.dumps(value, allow_nan=False)
            return
        if type(value) not in (dict, list, tuple) or id(value) in active:
            raise ValueError("Complete JSON is unavailable for unsupported or cyclic data; the retained original is unchanged.")
        active.add(id(value))
        try:
            if type(value) is dict:
                for key, item in value.items():
                    if type(key) is not str:
                        raise ValueError("Complete JSON requires exact string object keys; non-string keys could be coerced or collide. The retained original is unchanged.")
                    check(key, depth + 1)
                    check(item, depth + 1)
            else:
                for item in value:
                    check(item, depth + 1)
        finally:
            active.remove(id(value))

    check(data, 0)
    written = 0
    encoder = json.JSONEncoder(indent=2, ensure_ascii=True, allow_nan=False)
    for part in encoder.iterencode(data):
        chunk = part.encode("ascii")
        written += len(chunk)
        if written > limit:
            raise ValueError("Complete JSON exceeds this size limit; no partial report is copied or committed.")
        yield chunk


def _detach_export_report(data):
    """Capture exact plain input on Qt; never invoke arbitrary copy hooks."""
    active, visited, characters = set(), [0], [0]

    def clone(value, depth):
        visited[0] += 1
        if visited[0] > 250000 or depth > 64:
            raise ValueError("Complete JSON exceeds the supported node/depth limit; the retained original is unchanged.")
        if type(value) is str:
            characters[0] += len(value)
            if len(value) > _REVIEW_EXPORT_LIMIT // 6 or characters[0] > _REVIEW_EXPORT_LIMIT:
                raise ValueError("Complete JSON exceeds the export bounds; the retained original is unchanged.")
            return value
        if value is None or type(value) in (bool, int, float):
            json.dumps(value, allow_nan=False)
            return value
        if type(value) not in (dict, list, tuple) or id(value) in active:
            raise ValueError("Complete JSON is unavailable for unsupported or cyclic data; the retained original is unchanged.")
        active.add(id(value))
        try:
            if type(value) is dict:
                result = {}
                for key, item in value.items():
                    if type(key) is not str:
                        raise ValueError("Complete JSON requires exact string object keys; the retained original is unchanged.")
                    result[clone(key, depth + 1)] = clone(item, depth + 1)
                return result
            return [clone(item, depth + 1) for item in value]
        finally:
            active.remove(id(value))

    return clone(data, 0)


class _ReportExportWorker(QThread):
    """Retained independently of a reusable/deleted report window."""

    retired = Signal()

    def __init__(self, report, filename):
        super().__init__()
        self.report, self.filename = report, filename
        self.outcome = (False, "Report export did not complete.")
        self._start_attempted = False

    def start(self, *args, **kwargs):
        if self._start_attempted:
            raise RuntimeError("An export native generation cannot restart")
        self._start_attempted = True
        return super().start(*args, **kwargs)

    def run(self):
        output = QSaveFile(self.filename)
        output.setDirectWriteFallback(False)
        try:
            if self.isInterruptionRequested():
                raise OSError("Export cancelled before opening the destination.")
            if not output.open(QIODevice.OpenModeFlag.WriteOnly):
                raise OSError(output.errorString())
            for chunk in _complete_report_chunks(self.report, _REVIEW_EXPORT_LIMIT):
                if self.isInterruptionRequested():
                    raise OSError("Export cancelled; no partial report was committed.")
                if output.write(chunk) != len(chunk):
                    raise OSError(output.errorString())
            if self.isInterruptionRequested():
                raise OSError("Export cancelled; no partial report was committed.")
            if not output.commit():
                raise OSError(output.errorString())
        except Exception as error:
            output.cancelWriting()
            self.outcome = (False, "Complete report was not exported. " + str(error)[:1000])
        else:
            self.outcome = (True, "Complete retained report exported as JSON. Display omissions were not exported.")
        finally:
            self.report = None


def active_report_exports():
    """Exact retained QThreads for the existing GUI shutdown retirement owner."""
    return tuple(_REPORT_EXPORT_WORKERS)


def hold_report_exports():
    """Close admission and request atomic cancellation; never assert retirement."""
    global _REPORT_EXPORT_ADMISSION
    _REPORT_EXPORT_ADMISSION = False
    for worker in tuple(_REPORT_EXPORT_WORKERS):
        if isValid(worker):
            worker.requestInterruption()


def _retire_report_export(worker):
    try:
        worker.retired.emit()
    finally:
        _REPORT_EXPORT_WORKERS.discard(worker)
        worker.deleteLater()


def report_export_retirement_proven(worker):
    return native_retirement_proven(worker)


def poll_report_export_retirement(worker):
    return poll_native_retirement(worker)


class BreachOutline(QWidget):
    """Cheap client-edge outline; it never intercepts pointer or focus input."""

    def __init__(self, parent):
        super().__init__(parent)
        self._color = QColor("#ef4444")
        self.setObjectName("ConfirmedBreachOutline")
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        parent.installEventFilter(self)
        self.hide()

    def set_color(self, color):
        self._color = QColor(color)
        self.setGeometry(self.parentWidget().rect())
        self.show()
        self.raise_()
        self.update()

    def eventFilter(self, watched, event):  # noqa: N802
        if watched is self.parentWidget() and event.type() == QEvent.Type.Resize:
            self.setGeometry(watched.rect())
        return False

    def paintEvent(self, _event):  # noqa: N802
        painter = QPainter(self)
        painter.setPen(QPen(self._color, 3))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawRect(self.rect().adjusted(1, 1, -2, -2))
        painter.end()


class AfterActionReportDialog(QDialog):
    """Literal evidence/provenance view; availability comes from a typed router."""

    action_requested = Signal(str)

    def __init__(self, report, parent=None, *, confirmed=False, availability=(), scanner_review=False):
        super().__init__(parent)
        self.setWindowTitle("Angerona — After-action report")
        self.resize(860, 650)
        self.setMinimumSize(520, 380)
        self._report = report
        self._confirmed = bool(confirmed)
        self._scanner_review = scanner_review is True
        self._view = "investigate"
        layout = QVBoxLayout(self)
        from angerona.gui.action_progress import ActionActivities, ActionProgressView
        self._activities = ActionActivities(self)
        self._export_handles = {}
        self.progress_view = ActionProgressView(self._activities, self)
        layout.addWidget(self.progress_view)
        self.notice = QLabel(self._case_notice(report) if confirmed
                             else "Review the recorded checks and any leads from this run." if self._scanner_review
                             else "External scanner evidence — review findings and coverage before taking action.")
        self.notice.setTextFormat(Qt.TextFormat.PlainText)
        self.notice.setWordWrap(True)
        layout.addWidget(self.notice)
        self.text = QPlainTextEdit()
        self.text.setReadOnly(True)
        self.text.setUndoRedoEnabled(False)
        self.text.document().setMaximumBlockCount(_REVIEW_BLOCK_LIMIT)
        self.summary_text = self.technical_details_button = self._technical_panel = None
        if self._scanner_review:
            self.summary_text = QPlainTextEdit()
            self.summary_text.setReadOnly(True)
            self.summary_text.setUndoRedoEnabled(False)
            self.summary_text.setTabChangesFocus(True)
            self.summary_text.setAccessibleName("Plain-English spyware scan summary")
            layout.addWidget(self.summary_text, 1)
            self.technical_details_button = QToolButton()
            self.technical_details_button.setCheckable(True)
            self.technical_details_button.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
            self.technical_details_button.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
            layout.addWidget(self.technical_details_button)
            self._technical_panel = QWidget()
            technical = QVBoxLayout(self._technical_panel)
            technical.setContentsMargins(0, 0, 0, 0)
            definitions = QLabel(_TECHNICAL_TERMS)
            definitions.setWordWrap(True)
            definitions.setTextFormat(Qt.TextFormat.PlainText)
            technical.addWidget(definitions)
            self.text.setAccessibleName("Bounded technical JSON preview")
            self.text.setTabChangesFocus(True)
            technical.addWidget(self.text, 1)
            layout.addWidget(self._technical_panel, 2)
            self.technical_details_button.toggled.connect(self._show_technical_details)
            self._show_technical_details(False)
            self._refresh_scan_summary()
        else:
            layout.addWidget(self.text, 1)
        self.actions = {}
        buttons = QGridLayout()
        grants = {getattr(item, "action", ""): item for item in availability}
        for index, (action, label) in enumerate((
            ("investigate", "Investigate"), ("trace", "Trace"), ("isolate", "Isolate"),
            ("patch", "Patch"), ("kill", "Kill"), ("lift_lockdown", "Lift Lockdown"),
            ("review_resolved", "Mark reviewed / resolved"),
        )):
            button = QPushButton(label)
            self.actions[action] = button
            local_review = action in {"investigate", "trace"}
            grant = grants.get(action)
            button.setEnabled(local_review or bool(confirmed and getattr(grant, "enabled", False)))
            if not local_review:
                button.setToolTip(getattr(grant, "reason", "") or
                                  "A validated target and authorized installed response adapter are required.")
            if action == "investigate":
                button.clicked.connect(self.show_investigation)
            elif action == "trace":
                button.clicked.connect(self.show_trace)
            else:
                button.clicked.connect(lambda _checked=False, selected=action: self.action_requested.emit(selected))
            buttons.addWidget(button, index // 3, index % 3)
        layout.addLayout(buttons)
        original_buttons = QGridLayout()
        self.copy_original_button = QPushButton("Copy complete JSON")
        self.copy_original_button.setToolTip("Copy the complete retained report, not the preview; 2 MiB limit.")
        self.copy_original_button.clicked.connect(self.copy_complete_report)
        self.export_original_button = QPushButton("Export complete JSON…")
        self.export_original_button.setToolTip("Save the complete retained report as JSON to a chosen file; 64 MiB limit.")
        self.export_original_button.clicked.connect(self.export_complete_report)
        original_buttons.addWidget(self.copy_original_button, 0, 0)
        original_buttons.addWidget(self.export_original_button, 0, 1)
        layout.addLayout(original_buttons)
        self.review_status = QLabel("The preview is bounded; the complete retained report is available through Copy or Export.")
        self.review_status.setTextFormat(Qt.TextFormat.PlainText)
        self.review_status.setWordWrap(True)
        layout.addWidget(self.review_status)
        close = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close.rejected.connect(self.reject)
        layout.addWidget(close)
        self.show_investigation()
        self.outline = BreachOutline(self)
        if confirmed:
            self.outline.set_color("#ef4444")

    def _show_technical_details(self, expanded):
        button = self.technical_details_button
        if button is None:
            return
        label = "Hide technical details" if expanded else "Show technical details"
        button.setText(label)
        button.setAccessibleName(label)
        button.setArrowType(Qt.ArrowType.DownArrow if expanded else Qt.ArrowType.RightArrow)
        self._technical_panel.setVisible(expanded)

    def _refresh_scan_summary(self):
        if self.summary_text is not None:
            summary = _plain_scan_summary(self._report)
            if self.summary_text.toPlainText() != summary:
                self.summary_text.setPlainText(summary)

    def _display(self, data):
        self.text.setPlainText(_render_review_json(data))

    def copy_complete_report(self):
        try:
            encoded = b"".join(_complete_report_chunks(self._report, _REVIEW_COPY_LIMIT))
        except (TypeError, ValueError, OverflowError, RecursionError) as error:
            self.review_status.setText("Complete report was not copied. " + str(error)[:1000])
            return False
        QApplication.clipboard().setText(encoded.decode("ascii"))
        self.review_status.setText("Complete retained report copied as JSON. Display omissions were not copied.")
        return True

    def export_complete_report(self):
        if not _REPORT_EXPORT_ADMISSION or len(_REPORT_EXPORT_WORKERS) >= 2 or self._export_handles:
            self.review_status.setText("Export is held while an existing export retires or Angerona is stopping.")
            return False
        filename, _selected_filter = QFileDialog.getSaveFileName(
            self, "Export complete after-action report", "Angerona-after-action.json", "JSON reports (*.json)")
        if not filename:
            return False
        try:
            retained = _detach_export_report(self._report)
            worker = _ReportExportWorker(retained, filename)
            handle = self._activities.begin("report-export", "Exporting the complete retained report…", replace=True)
            self._export_handles[worker] = handle
            _REPORT_EXPORT_WORKERS.add(worker)
            retain_native_retirement(worker, _retire_report_export)
            worker.retired.connect(self._export_finished, Qt.ConnectionType.DirectConnection)
            self.export_original_button.setEnabled(False)
            worker.start()
        except Exception as error:
            if "worker" in locals():
                worker.admission_error = type(error).__name__
                worker.retirement_uncertain = True
                worker.requestInterruption()
                native_start_failed(worker)
                self._activities.finish(self._export_handles.get(worker))
                self.review_status.setText("Export launch failed; its exact native owner is retained because retirement is unproved. "
                                          "No successful export is claimed. Review before retrying.")
                return False
            self.export_original_button.setEnabled(True)
            self.review_status.setText("Complete report was not exported. " + str(error)[:1000])
            return False
        self.review_status.setText("Exporting the captured complete report; the previous destination remains intact until atomic commit.")
        return True

    def _export_finished(self):
        worker = self.sender()
        handle = self._export_handles.pop(worker, None)
        if handle is None:
            return
        self._activities.finish(handle)
        self.review_status.setText(worker.outcome[1])
        self.export_original_button.setEnabled(True)

    @staticmethod
    def _case_notice(report):
        report = report if type(report) is dict else {}
        case = str(report.get("case_id", "unavailable"))[:160]
        state = str(report.get("containment_state", "unknown"))[:160]
        return f"Confirmed breach · case {case} · containment: {state}"

    def show_investigation(self):
        if self._scanner_review and self._view == "investigate" and not self.text.document().isEmpty():
            return
        self._view = "investigate"
        self._display(self._report)

    def show_trace(self):
        if self.technical_details_button is not None:
            self.technical_details_button.setChecked(True)
            if self._view == "trace":
                return
        self._view = "trace"
        report = self._report if type(self._report) is dict else {}
        selected = {key: report[key] for key in (
            "case_id", "request_id", "tool", "version", "commit", "sha256", "report",
            "provenance", "coverage", "references", "details",
        ) if key in report}
        self._display(dict(review="Evidence and provenance trace; this does not contact a remote target.",
                           trace=selected))

    def update_report(self, report, availability=(), *, confirmed=False):
        from angerona.gui.component_heartbeat import _update_details_text
        position = self.text.verticalScrollBar().value()
        selection = self.text.textCursor()
        self._report = report
        self._confirmed = bool(confirmed)
        self._refresh_scan_summary()
        selected_report = report if type(report) is dict else {}
        self.notice.setText(self._case_notice(report) if confirmed
                            else "Review the recorded checks and any leads from this run." if self._scanner_review
                            else "Retained review record — current state: " + str(selected_report.get("state", "unknown"))[:80])
        previous = self.text.toPlainText()
        view = self._view
        # Render into a temporary plain string, then update the retained
        # document rather than resetting the reader's scroll and selection.
        if view == "trace":
            selected = {key: selected_report[key] for key in ("case_id", "request_id", "tool", "version", "commit", "sha256", "report",
                                                      "provenance", "coverage", "references", "details") if key in selected_report}
            data = dict(review="Evidence and provenance trace; this does not contact a remote target.", trace=selected)
        else:
            data = report
        rendered = _render_review_json(data)
        if rendered != previous:
            # Incremental edits may temporarily contain parts of both bounded
            # documents. Keep a finite 2x ceiling so Qt cannot discard the prefix.
            document = self.text.document()
            document.setMaximumBlockCount(_REVIEW_BLOCK_LIMIT * 2)
            try:
                _update_details_text(self.text, rendered)
            finally:
                document.setMaximumBlockCount(_REVIEW_BLOCK_LIMIT)
            self.text.setTextCursor(selection)
            self.text.verticalScrollBar().setValue(position)
        grants = {item.action: item for item in availability if type(item) is BreachActionAvailability}
        for action, button in self.actions.items():
            if action in {"investigate", "trace"}:
                continue
            grant = grants.get(action)
            button.setEnabled(bool(confirmed and grant is not None and grant.enabled))
            button.setToolTip(grant.reason if grant else "A validated target and authorized installed response adapter are required.")


def _valid_projection(snapshot):
    if (type(snapshot) is not BreachDisplaySnapshot or type(snapshot.active) is not bool
            or type(snapshot.sequence) is not int or not 0 <= snapshot.sequence <= 2**63 - 1):
        return False
    for name, bound in (("state", 80), ("summary", 4096), ("case_id", 160), ("containment_state", 160)):
        value = getattr(snapshot, name)
        if type(value) is not str or len(value) > bound or "\x00" in value:
            return False
    if snapshot.active and not snapshot.case_id:
        return False
    if type(snapshot.details) is not tuple or len(snapshot.details) > 64:
        return False
    if any(type(row) is not tuple or len(row) != 2 or any(type(value) is not str or len(value) > 4096 for value in row)
           for row in snapshot.details):
        return False
    if type(snapshot.actions) is not tuple or len(snapshot.actions) > 16:
        return False
    return all(type(item) is BreachActionAvailability and type(item.action) is str and type(item.enabled) is bool
               and type(item.confirmation_required) is bool and type(item.reason) is str and len(item.reason) <= 2000
               and item.action in {"investigate", "trace", "isolate", "patch", "kill", "lift_lockdown", "review_resolved"}
               for item in snapshot.actions)


class BreachDisplayBridge(QObject):
    """Memory-only projection; it accepts no external report dictionaries."""

    def __init__(self, window):
        super().__init__(window)
        self.window = window
        self.snapshot = None
        self._outlines = weakref.WeakKeyDictionary()
        self._orange = False
        self._last_alert_case = ""
        self._closed = False
        self._label_signature = None
        self._needs_restore = False
        self.dialog = None
        self.poll_timer = QTimer(self)
        self.poll_timer.setInterval(500)
        self.poll_timer.timeout.connect(self.poll)
        self.flash_timer = QTimer(self)
        self.flash_timer.setInterval(1000)
        self.flash_timer.timeout.connect(self._flash)

    @property
    def active(self):
        return self.snapshot is not None and self.snapshot.active

    def poll(self):
        if self._closed:
            return
        controller = getattr(self.window.manager, "_breach_state_controller", None)
        if controller is not None:
            try:
                self.apply(controller.snapshot())
            except Exception:
                # Collector loss cannot silently clear an existing breach.
                pass
        self._sync_visibility()

    def apply(self, snapshot):
        if self._closed or not _valid_projection(snapshot):
            return False
        previous = self.snapshot
        if previous is not None and snapshot.sequence < previous.sequence:
            return False
        changed = previous != snapshot
        self.snapshot = snapshot
        if not changed:
            self._sync_visibility()
            return True
        self._sync_summary_views(snapshot)
        if self.active:
            if changed:
                self._orange = False
            self._paint_warning()
            if self._last_alert_case != snapshot.case_id:
                self._last_alert_case = snapshot.case_id
                if bool(getattr(self.window.config, "breach_alert_popup_enabled", True)):
                    self.open_report()
            elif changed and self.dialog is not None and isValid(self.dialog):
                self.dialog.update_report(self._report(), self._available_actions(), confirmed=True)
        else:
            self.flash_timer.stop()
            for outline in tuple(self._outlines.values()):
                if isValid(outline):
                    outline.hide()
            self._needs_restore = True
            if self.window.isVisible():
                self.restore_posture()
            if changed and self.dialog is not None and isValid(self.dialog):
                self.dialog.update_report(self._report(), (), confirmed=False)
        self._sync_visibility()
        return True

    def _sync_summary_views(self, snapshot):
        cards = getattr(self.window, "cards", None)
        if callable(getattr(cards, "set_breach_override", None)):
            cards.set_breach_override(snapshot, open_report=self.open_report)
        footer = getattr(self.window, "_dashboard_footer", None)
        if callable(getattr(footer, "set_breach_override", None)):
            footer.set_breach_override(snapshot)
        if not snapshot.active:
            reader = getattr(self.window, "_posture_reader", None)
            if callable(getattr(reader, "request", None)):
                reader.request()

    def _owned_windows(self):
        owned = [self.window]
        app = QApplication.instance()
        if app is not None:
            for candidate in app.topLevelWidgets()[:64]:
                if candidate is not self.window and isinstance(candidate, QDialog) and self.window.isAncestorOf(candidate):
                    owned.append(candidate)
        return owned

    def _sync_visibility(self):
        if self._closed:
            return
        visible = any(widget.isVisible() for widget in self._owned_windows())
        attached = getattr(self.window.manager, "_breach_state_controller", None) is not None
        if visible or attached:
            if not self.poll_timer.isActive():
                self.poll_timer.start()
        else:
            self.poll_timer.stop()
        if visible:
            if self.active:
                self._paint_warning()
            elif self._needs_restore and self.window.isVisible():
                self.restore_posture()
        animate = self.active and visible and motion_allowed(getattr(self.window, "config", None))
        if animate:
            if not self.flash_timer.isActive():
                self.flash_timer.start()
        else:
            self.flash_timer.stop()
            if self.active:
                self._orange = False
                self._paint_warning()

    def _paint_warning(self):
        windows = [window for window in self._owned_windows() if window.isVisible()]
        if not windows:
            return
        color = "#fb923c" if self._orange else "#ef4444"
        label = self.window.posture_lbl
        signature = (color, self.snapshot.summary, self.snapshot.containment_state)
        if self.window.isVisible() and signature != self._label_signature:
            self._label_signature = signature
            label.setText("⚠️Breached⚠️")
            label.setAccessibleName("Confirmed breach. Open after-action report.")
            label.setStyleSheet(f"color:{color};font-weight:900;font-size:12px;letter-spacing:1px;")
            label.setToolTip("<qt>Confirmed breach — " + html.escape(self.snapshot.summary)
                             + "<br>Containment: " + html.escape(self.snapshot.containment_state) + "</qt>")
        for window in windows:
            outline = self._outlines.get(window)
            if outline is None or not isValid(outline):
                existing = getattr(window, "outline", None)
                outline = existing if isinstance(existing, BreachOutline) else BreachOutline(window)
                self._outlines[window] = outline
            if outline._color.name() != color or not outline.isVisible() or outline.geometry() != window.rect():
                outline.set_color(color)

    def _flash(self):
        if self._closed:
            return
        if not self.active or not motion_allowed(getattr(self.window, "config", None)):
            self._sync_visibility()
            return
        self._orange = not self._orange
        self._paint_warning()

    def restore_posture(self):
        self._label_signature = None
        self._needs_restore = False
        posture = getattr(self.window, "_last_posture", None)
        label = self.window.posture_lbl
        if type(posture) is dict and all(name in posture for name in ("score", "label", "color")):
            label.setText(f"POSTURE {posture['score']} · {posture['label']}")
            label.setStyleSheet(f"color:{posture['color']}; font-weight:800; font-size:11px; letter-spacing:1px;")
            label.setToolTip(getattr(self.window, "_last_posture_tooltip", "Composite security posture (0–100)."))
        else:
            label.setText("POSTURE —")
            label.setStyleSheet("")
        label.setAccessibleName("Security posture")

    def _report(self):
        return dict(asdict(self.snapshot), provenance="Angerona verified breach controller") if self.snapshot is not None else {}

    def _available_actions(self):
        controller = getattr(self.window.manager, "_breach_state_controller", None)
        if not callable(getattr(controller, "request_action", None)):
            return ()
        return self.snapshot.actions

    def open_report(self):
        if self._closed or self.snapshot is None:
            return None
        if self.dialog is None or not isValid(self.dialog):
            self.dialog = AfterActionReportDialog(self._report(), self.window, confirmed=self.active,
                                                  availability=self._available_actions())
            self.dialog.action_requested.connect(self._request_action)
        else:
            self.dialog.update_report(self._report(), self._available_actions(), confirmed=self.active)
        self.dialog.show()
        self.dialog.raise_()
        return self.dialog

    def _request_action(self, action):
        if self._closed:
            return
        snapshot = self.snapshot
        grant = next((item for item in self._available_actions() if item.action == action and item.enabled), None)
        if snapshot is None or grant is None:
            return
        if grant.confirmation_required and QMessageBox.question(
                self.dialog or self.window, "Confirm breach response",
                f"Request {action.replace('_', ' ')} for case {snapshot.case_id}?\n{grant.reason}",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return
        controller = getattr(self.window.manager, "_breach_state_controller", None)
        if controller is not None:
            try:
                current = controller.snapshot()
            except Exception:
                current = None
            available = next((item for item in current.actions if item.action == action and item.enabled), None) if _valid_projection(current) else None
            if not _valid_projection(current) or current.case_id != snapshot.case_id or available is None:
                if self.dialog is not None:
                    self.dialog.notice.setText("Response availability changed; review the current case before retrying.")
                return
            try:
                queued = controller.request_action(snapshot.case_id, action)
            except Exception:
                if self.dialog is not None:
                    self.dialog.notice.setText("Response request outcome is unavailable; review the case journal.")
                return
            if self.dialog is not None:
                self.dialog.notice.setText("Response request queued; its verified outcome will appear in this case."
                                           if queued else "Response was not queued; review the current case and response status.")

    def shutdown(self):
        self._closed = True
        self.poll_timer.stop()
        self.flash_timer.stop()
        if self.dialog is not None and isValid(self.dialog):
            self.dialog.close()
