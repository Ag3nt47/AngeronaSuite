"""Composable panels for the single-screen dashboard.

Everything lives on one screen (mirroring the original Angerona dashboard):
  • DashboardCards  — summary stat cards + threat pill
  • ModulesPanel    — module list with enable toggles + live status (click to inspect)
  • ModuleInspector — per-module detail + live feed + controls
  • AlertsPanel     — live event/alert feed
  • StatusStrip     — bottom matrix of every module's status (like the original)
  • SettingsDialog  — settings, opened from the header button
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import platform
import re
import stat
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import quote

from PySide6.QtCore import QRegularExpression, Qt, QTimer, Signal
from PySide6.QtGui import (QAction, QColor, QFont, QGuiApplication, QKeySequence,
                           QRegularExpressionValidator, QShortcut, QTextCursor,
                           QTextFormat)
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QFileDialog, QGridLayout, QFrame, QGroupBox,
    QHBoxLayout, QHeaderView, QLabel, QLineEdit, QListWidget, QListWidgetItem,
    QMenu, QMessageBox, QPlainTextEdit, QPushButton, QScrollArea,
    QSplitter, QTableWidget, QTableWidgetItem, QTabWidget, QVBoxLayout, QWidget,
    QTextEdit,
)

HELP_TEXT_SHORT = (
    "Cloud providers are optional. Keys entered in the API Keys tab are protected "
    "by your operating-system account and used only after an explicit cloud action."
)
HELP_TEXT_FULL = """ANGERONA — API KEY SETUP

Angerona runs fully local by default (Ollama). Cloud keys are OPTIONAL and are
used only for an explicit online consult/research action or the separately
enabled 'Cloud CTI Escalation' second-opinion on CRITICAL events. Keys are
stored in Angerona's current-user protected credential store and are NEVER
committed or sent anywhere except the provider you choose.

WHERE TO GET KEYS
  • Gemini (free tier):   https://aistudio.google.com/app/apikey
  • Groq (free tier):     https://console.groq.com/keys
  • OpenAI:               https://platform.openai.com/api-keys
  • Anthropic (Claude):   https://console.anthropic.com/settings/keys
  • OpenRouter:           https://openrouter.ai/keys

HOW TO ADD THEM
  1. Open the provider link above and create an API key.
  2. Copy the key.
  3. In the 'API Keys' tab, paste it into the matching field.
     - Gemini supports a comma-separated POOL of keys for rotation, e.g.
       key1,key2,key3
  4. Click 'Save keys' or the main Settings 'Save'. They're protected by the
     operating-system credential store and loaded live.
  5. The Cloud CTI Escalation module picks them up within ~30 seconds — no
     restart needed. Its health/Overview tab will show it active.

SECURITY NOTES
  • Windows uses user-bound DPAPI; macOS uses Keychain; Linux uses Secret Service.
    Keys leave only for the provider you explicitly choose.
  • Remove a key anytime by clearing its field and saving.
  • Without any key, Angerona stays 100% local — nothing is sent externally.
"""

from angerona import __version__
from angerona.core.capability_assurance import assess_capability, cached_declaration_anchor
from angerona.core.eventbus import Severity
from angerona.core.threat import active_threat_events, threat_label
from angerona.gui.animations import begin_loading, finish_loading
from angerona.gui.dashboard_details import (
    ConsoleDetailDialog,
    FuturisticDetailDialog,
    FuturisticHeader,
    ModuleResourceDialog,
)
from angerona.gui.theme import SEVERITY_COLOR, available_themes


_AUTHENTICODE_SCRIPT = (
    "(Get-AuthenticodeSignature -LiteralPath "
    "$env:ANGERONA_AUTHENTICODE_PATH).Status"
)


def _authenticode_status(path: str) -> str:
    """Return Authenticode status without embedding *path* in PowerShell code."""
    env = os.environ.copy()
    env["ANGERONA_AUTHENTICODE_PATH"] = os.fspath(path)
    return subprocess.check_output(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command",
         _AUTHENTICODE_SCRIPT],
        timeout=4, stderr=subprocess.DEVNULL, text=True, env=env,
    ).strip()

THREAT = {
    Severity.INFO: ("Calm", "#22c55e"),
    Severity.LOW: ("Low", "#3b82f6"),
    Severity.MEDIUM: ("Elevated", "#f97316"),   # orange — was amber
    Severity.HIGH: ("High", "#ef4444"),          # red    — was orange
    Severity.CRITICAL: ("Critical", "#b91c1c"), # deep red
}

STATUS_COLOR = {"running": "#22c55e", "stopped": "#6b7280", "error": "#ef4444"}
HEALTH_COLOR = {"ok": "#22c55e", "degraded": "#f59e0b", "critical": "#ef4444",
                "failed": "#b91c1c", "off": "#6b7280"}


# Per-module avatar icons (by category).
CATEGORY_AVATAR = {
    "Integrity": "\U0001F9EC",   # 🧬
    "Processes": "⚙",        # ⚙
    "Network": "\U0001F310",     # 🌐
    "Signatures": "\U0001F9EA",  # 🧪
    "AI": "\U0001F916",          # 🤖
    "Deception": "\U0001FA9F",   # 🪟 (trap-like)
    "Forensics": "\U0001F52C",   # 🔬
    "Response": "\U0001F6E1",    # 🛡
    "General": "\U0001F4E1",     # 📡
}


def _avatar(category: str) -> str:
    return CATEGORY_AVATAR.get(category, CATEGORY_AVATAR["General"])


def _capability_contract(module) -> dict:
    """Return one module's serialisable v12 contract without UI assumptions."""
    contract = getattr(module, "_angerona_contract", None)
    if contract is None:
        return {}
    try:
        return contract.as_dict()
    except Exception:
        return {}


_CAPABILITY_SUMMARY_FIELDS = (
    "capability_id",
    "description",
    "implementation_version",
    "maturity",
    "metadata_gaps",
    "metadata_level",
    "mode",
    "response_authority",
    "supported_platforms",
)


def _capability_summary(module) -> dict:
    """Read the immutable fields used by live tables without recursive copies.

    ``CapabilityContract.as_dict()`` deliberately builds an independent,
    serialisable deep copy for exports and the JSON inspector.  Repeating that
    recursive conversion for every module on every 1.5-second status tick is
    unnecessary: live tables only read this small immutable projection.
    """
    contract = getattr(module, "_angerona_contract", None)
    if contract is None:
        return {}
    try:
        return {
            field: getattr(contract, field)
            for field in _CAPABILITY_SUMMARY_FIELDS
        }
    except Exception:
        return {}


_PERCENT_SORT_ROLE = Qt.UserRole + 31


class _PercentTableItem(QTableWidgetItem):
    """Display a percentage while sorting by its numeric value."""

    def __init__(self, score: int | None) -> None:
        self.score = -1 if score is None else max(0, min(100, int(score)))
        super().__init__("—" if score is None else f"{self.score}%")
        self.setData(_PERCENT_SORT_ROLE, self.score)

    def __lt__(self, other) -> bool:
        if isinstance(other, _PercentTableItem):
            return self.score < other.score
        return super().__lt__(other)


def _assurance_color(score: int) -> str:
    if score >= 100:
        return "#22c55e"
    if score >= 90:
        return "#38bdf8"
    if score >= 70:
        return "#f59e0b"
    if score >= 50:
        return "#f97316"
    return "#ef4444"


def _manager_enabled(manager, module) -> bool:
    try:
        return bool(manager.is_enabled(module.name))
    except Exception:
        return bool(getattr(module, "enabled_by_default", False))


def _fast_assurance_operational(
    module, health_summary: tuple[str, int, str],
) -> dict[str, object]:
    """Build a non-blocking live assurance input from already-read health."""
    status, health, health_state = health_summary
    thread = getattr(module, "_thread", None)
    try:
        thread_alive = bool(thread is not None and thread.is_alive())
    except Exception:
        thread_alive = False
    return {
        "status": status,
        "health": health,
        "health_state": health_state,
        "thread_alive": thread_alive,
        "first_cycle_complete": bool(getattr(module, "first_cycle_complete", False)),
        "event_overflow_count": int(getattr(module, "_bus_overflow_count", 0)),
        "crash_count": int(getattr(module, "_crash_count", 0)),
    }


def _module_assurance(manager, module, operational=None):
    return assess_capability(
        module,
        contract=getattr(module, "_angerona_contract", None),
        operational=operational,
        platform=getattr(manager, "platform", None),
        enabled=_manager_enabled(manager, module),
        source_anchor=cached_declaration_anchor(module),
    )


def _assurance_tooltip(assurance) -> str:
    lines = [
        f"Assurance {assurance.score}% — weakest verified dimension; not attack coverage."
    ]
    for item in assurance.reasons[:12]:
        location = (
            f" [{item.source_path}:{item.source_line}]"
            if item.source_path and item.source_line
            else " [source unavailable]"
        )
        lines.append(f"• {item.reason}{location}")
    if len(assurance.reasons) > 12:
        lines.append(f"• …and {len(assurance.reasons) - 12} more; click for all evidence.")
    if not assurance.reasons:
        lines.append("Click to inspect the five scored dimensions and their meaning.")
    return "\n".join(lines)


def _source_editing_allowed() -> bool:
    """Live source editing is a development-only, unprivileged capability."""
    return bool(
        not getattr(sys, "frozen", False)
        and os.environ.get("ANGERONA_DEVELOPMENT_MODE", "").strip() == "1"
        and os.environ.get("ANGERONA_ENFORCE_KEY_ACL", "").strip() != "1"
    )


_HEALTH_SOURCE_MAX_BYTES = 512 * 1024
_HEALTH_SOURCE_MAX_LINES = 20_000
_HEALTH_SOURCE_CONTEXT = 24
_ANGERONA_REPOSITORY_URL = "https://github.com/Ag3nt47/AngeronaSuite"


def _source_checkout_root() -> Path | None:
    """Return the exact current checkout root, not a packaged-path guess."""
    if getattr(sys, "frozen", False):
        return None
    try:
        this_file = Path(__file__).resolve(strict=True)
        root = this_file.parents[3]
        expected = root / "src" / "angerona" / "gui" / "pages.py"
        if not (root / ".git").exists():
            return None
        if expected.resolve(strict=True) != this_file:
            return None
        return root
    except (IndexError, OSError, RuntimeError):
        return None


def _trusted_repository_source(relative_path: object) -> Path | None:
    """Resolve one evidence path without accepting absolute/external paths."""
    root = _source_checkout_root()
    if root is None or not isinstance(relative_path, str):
        return None
    normalized = relative_path.replace("\\", "/")
    if not normalized.startswith("src/angerona/"):
        return None
    relative = Path(normalized)
    if relative.is_absolute() or ".." in relative.parts:
        return None
    try:
        candidate = root.joinpath(relative).resolve(strict=True)
        candidate.relative_to(root)
        if not candidate.is_file() or candidate.suffix.casefold() != ".py":
            return None
        # Reject descendant links/junctions.  The checkout root itself may be
        # a managed worktree junction, but evidence must not traverse another
        # redirect after entering that root.
        current = root
        for part in relative.parts:
            current = current / part
            if current.is_symlink():
                return None
            is_junction = getattr(current, "is_junction", None)
            if callable(is_junction) and is_junction():
                return None
        return candidate
    except (OSError, RuntimeError, ValueError):
        return None


def _repository_relative_source(path: object) -> str:
    """Return a safe repository-relative source name or an empty string."""
    root = _source_checkout_root()
    if root is None:
        return ""
    try:
        candidate = Path(os.fspath(path)).resolve(strict=True)
        relative = candidate.relative_to(root).as_posix()
    except (OSError, RuntimeError, TypeError, ValueError):
        return ""
    return relative if _trusted_repository_source(relative) == candidate else ""


def _read_trusted_source(
    relative_path: object,
    expected_sha256: object = None,
) -> tuple[str | None, str | None]:
    """Read a bounded regular source file, returning text or a safe reason."""
    candidate = _trusted_repository_source(relative_path)
    if candidate is None:
        return None, "Source is unavailable or outside the trusted Angerona checkout."
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd: int | None = None
    try:
        fd = os.open(candidate, flags)
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            return None, "The source evidence target is not a regular file."
        if metadata.st_size > _HEALTH_SOURCE_MAX_BYTES:
            return None, (
                f"Source exceeds the {_HEALTH_SOURCE_MAX_BYTES // 1024} KiB "
                "read-only evidence limit."
            )
        chunks: list[bytes] = []
        remaining = _HEALTH_SOURCE_MAX_BYTES + 1
        while remaining > 0:
            chunk = os.read(fd, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > _HEALTH_SOURCE_MAX_BYTES:
            return None, "Source changed or exceeded the bounded read limit."
        if expected_sha256 is not None:
            expected_digest = str(expected_sha256).casefold()
            if not re.fullmatch(r"[0-9a-f]{64}", expected_digest):
                return None, "Verified source digest is unavailable for this health evidence."
            if hashlib.sha256(raw).hexdigest() != expected_digest:
                return None, "Source changed after this health evidence was recorded."
        # Revalidate the pathname after the descriptor-bound read.  This keeps
        # a concurrent replacement from being presented as current evidence.
        if _trusted_repository_source(relative_path) != candidate:
            return None, "Source identity changed while evidence was being read."
        return raw.decode("utf-8", errors="replace"), None
    except (OSError, RuntimeError):
        return None, "Source could not be read safely from the trusted checkout."
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def _health_source_context(
    relative_path: object, source_line: object, source_sha256: object = None,
) -> tuple[str | None, int | None, str | None]:
    """Return numbered bounded context and its zero-based highlighted block."""
    try:
        line_number = int(source_line)
    except (TypeError, ValueError):
        return None, None, "No exact source line was recorded for this health state."
    if line_number < 1 or line_number > _HEALTH_SOURCE_MAX_LINES:
        return None, None, "The recorded source line is outside the bounded display range."
    if not re.fullmatch(r"[0-9a-f]{64}", str(source_sha256 or "").casefold()):
        return None, None, "Verified source digest is unavailable for this health evidence."
    source, error = _read_trusted_source(relative_path, source_sha256)
    if source is None:
        return None, None, error
    lines = source.splitlines()
    if len(lines) > _HEALTH_SOURCE_MAX_LINES:
        return None, None, "Source contains too many lines for the read-only evidence view."
    if line_number > len(lines):
        return None, None, "The recorded line no longer exists in the checked-out source."
    start = max(1, line_number - _HEALTH_SOURCE_CONTEXT)
    end = min(len(lines), line_number + _HEALTH_SOURCE_CONTEXT)
    rendered = "\n".join(
        f"{number:6d} | {lines[number - 1]}"
        for number in range(start, end + 1)
    )
    return rendered, line_number - start, None


# Short codes for status-strip chips.  Modules that expose a .CODE class attr
# (all Phase-2c/2d/3 modules) use it directly; legacy modules use this table.
_FALLBACK_CODES: dict[str, str] = {
    "File Integrity Monitor": "FIM",
    "Process Monitor":        "PROC",
    "Network Monitor":        "NET",
    "Packet Sniffer":         "PCAP",
    "YARA Scanner":           "YARA",
    "AI Triage (Ollama)":     "AITR",
    "Cloud CTI Escalation":   "CTI",
    "Active Deception":       "DEC",
    "Forensics Capture":      "FOR",
    "SOAR Automation":        "SOAR",
    "Posture Hardening":      "HARD",
    "Watchdog Monitor":       "WDOG",
}


def _short_code(mod) -> str:
    """Return a 2-5 char code for a status-strip chip."""
    code = getattr(mod, "CODE", None)
    if code:
        return str(code)
    return _FALLBACK_CODES.get(
        mod.name,
        "".join(w[0] for w in mod.name.split() if w not in {"Monitor", "Module"})[:5].upper()
        or mod.name[:4].upper(),
    )


def _sev_item(sev: Severity) -> QTableWidgetItem:
    item = QTableWidgetItem(sev.label)
    item.setForeground(QColor(SEVERITY_COLOR.get(sev, "#e5e7eb")))
    return item


# Non-modal dialog registry: keep references so garbage-collection doesn't close
# windows the user left open, while letting them click back to the main window.
_OPEN_DIALOGS: list = []


def _emit_if_accepting(owner, signal_name: str, *args) -> bool:
    """Best-effort delivery from a Python worker to a live Qt owner.

    Shiboken raises ``RuntimeError`` when a daemon worker reaches a bound signal
    after the widget's C++ object has been deleted.  That exception used to
    escape ``threading.Thread`` workers (and, on an error path, trigger a second
    failing emit).  Treat a closed/deleted view exactly like a cancelled result.
    Slots also check the flag because an already-queued signal can arrive after
    ``closeEvent`` but before deferred deletion.
    """
    try:
        if not bool(getattr(owner, "_accept_async_results", False)):
            return False
        getattr(owner, signal_name).emit(*args)
        return True
    except RuntimeError:
        return False


def _show_nonmodal(dlg):
    """Show a dialog NON-modally (user can click out and return later)."""
    try:
        dlg.setModal(False)
        # These windows are produced by factories and are never reused after
        # close. Deleting them prevents hidden timers, tables, and parent-owned
        # widget trees from accumulating over a long dashboard session.
        if not bool(getattr(dlg, "_angerona_preserve_on_close", False)):
            dlg.setAttribute(Qt.WA_DeleteOnClose, True)
    except Exception:
        pass
    _OPEN_DIALOGS.append(dlg)
    def _drop(*_):
        try:
            _OPEN_DIALOGS.remove(dlg)
        except ValueError:
            pass
    try:
        dlg.finished.connect(_drop)
    except Exception:
        pass
    dlg.show()
    dlg.raise_()
    try:
        dlg.activateWindow()
    except Exception:
        pass
    return dlg


def _show_nonmodal_from(source: QWidget, factory, color: str = "#38bdf8"):
    """Create and show a detail window through MainWindow's real-window reveal."""
    owner: QWidget | None = source.window()
    opener = None
    while owner is not None:
        opener = getattr(owner, "_reveal_window_from", None)
        if callable(opener):
            break
        owner = owner.parentWidget()

    def _show():
        dialog = factory()
        return _show_nonmodal(dialog)

    if callable(opener):
        return opener(source, _show, color)
    return _show()


def _copy_event_to_clipboard(event) -> None:
    """Copy a bus Event's full record to the clipboard as readable text."""
    try:
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(getattr(event, "ts", time.time())))
        sev = getattr(event, "severity", None)
        sev = sev.label if hasattr(sev, "label") else str(sev)
        rec = {
            "time": ts, "module": getattr(event, "module", ""), "severity": sev,
            "message": getattr(event, "message", ""), "details": getattr(event, "details", {}),
        }
        QGuiApplication.clipboard().setText(json.dumps(rec, indent=2, default=str))
    except Exception:
        pass


def _soar_queue_path():
    from angerona.core.data_paths import data_dir
    d = data_dir() / "shared_logs"
    d.mkdir(parents=True, exist_ok=True)
    return d / "soar_queue.json"


def _soar_queue_state_path():
    return _soar_queue_path().with_name("soar_queue_state.json")


_SOAR_QUEUE_CACHE_LOCK = threading.RLock()
_SOAR_QUEUE_CACHE_KEY: tuple | None = None
_SOAR_QUEUE_CACHE_VALUE: tuple[dict, ...] = ()
_SOAR_STATE_LIMIT = 5_000
_SOAR_STATE_MAX_BYTES = 4 * 1024 * 1024

_SOAR_PENDING = "PENDING REVIEW"
_SOAR_APPROVED = "APPROVED — execution required"
_SOAR_DISMISSED = "DISMISSED — no host action taken"
_SOAR_SUBMITTED = "SUBMITTED — Adversary Combat receipt pending"
_SOAR_EXECUTED = "EXECUTED — verified Adversary Combat receipt"
_SOAR_RECEIPT_TIMEOUT_SECONDS = 120.0


def _event_record_identity(event, bus=None) -> str:
    """Return a stable presentation identity without trusting timestamps.

    A locally verified EventBus HMAC is the strongest available identity.  A
    deterministic record fingerprint is used for persisted/legacy events that
    cannot be verified by this panel; the prefix keeps the weaker provenance
    explicit instead of presenting an unsigned digest as authentication.
    """
    signature = str(getattr(event, "hmac_sig", "") or "").casefold()
    if (
        re.fullmatch(r"[0-9a-f]{64}", signature)
        and bus is not None
        and getattr(bus, "integrity_enabled", False)
    ):
        try:
            if bus.verify(event):
                return f"verified:{signature}"
        except Exception:
            pass
    canonical = json.dumps(
        {
            "details": getattr(event, "details", {}) or {},
            "message": str(getattr(event, "message", "")),
            "module": str(getattr(event, "module", "")),
            "severity": int(getattr(event, "severity", Severity.INFO)),
            "ts": float(getattr(event, "ts", 0.0)),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return "record:" + hashlib.sha256(canonical).hexdigest()


def _event_row_identities(events, bus=None) -> list[str]:
    """Disambiguate exact duplicate records with a stable ordered ordinal."""
    counts: dict[str, int] = {}
    identities: list[str] = []
    for event in events:
        base = _event_record_identity(event, bus)
        ordinal = counts.get(base, 0)
        counts[base] = ordinal + 1
        identities.append(f"{base}:{ordinal}")
    return identities


def _is_integrity_alert(event) -> bool:
    """Fail closed for alerts whose purpose is reporting trust failure."""
    module = str(getattr(event, "module", "")).casefold()
    message = str(getattr(event, "message", "")).casefold()
    details = getattr(event, "details", {}) or {}
    if "integrity" in module or "tamper" in module:
        return True
    if isinstance(details, dict) and any(
        details.get(key) is True
        for key in (
            "integrity_failure", "tamper_detected", "hmac_invalid",
            "signature_invalid", "ledger_corrupt",
        )
    ):
        return True
    return any(
        marker in message
        for marker in (
            "integrity verification failed", "hmac verification failed",
            "signature verification failed", "tamper detected",
            "ledger corruption",
        )
    )


def _alert_suppression_scope(event) -> tuple[str, str, str]:
    """Scope Allow to one detector rule/pattern, never an entire module."""
    details = getattr(event, "details", {}) or {}
    rule_id = ""
    if isinstance(details, dict):
        for key in ("rule_id", "signature_id", "technique_id", "detection_id"):
            value = str(details.get(key, "") or "").strip()
            if value:
                rule_id = value[:160]
                break
    module = str(getattr(event, "module", ""))[:200]
    if rule_id:
        return module, f"rule:{rule_id}", f"{module} · rule {rule_id}"
    digest = hashlib.sha256(
        str(getattr(event, "message", "")).encode("utf-8", errors="replace")
    ).hexdigest()
    return module, f"message:{digest}", f"{module} · this exact message pattern"


def _soar_archive_root() -> Path:
    return _soar_queue_path().parent / "soar_history_archive"


def _archive_soar_history() -> Path | None:
    """Move queue history into a recoverable, all-or-nothing archive folder."""
    sources = tuple(
        path for path in (_soar_queue_path(), _soar_queue_state_path())
        if path.exists()
    )
    if not sources:
        return None
    root = _soar_archive_root()
    root.mkdir(parents=True, exist_ok=True)
    archive = root / (
        time.strftime("%Y%m%d-%H%M%S", time.gmtime()) + "-" + uuid.uuid4().hex
    )
    archive.mkdir(mode=0o700)
    moved: list[tuple[Path, Path]] = []
    try:
        manifest: dict[str, object] = {
            "archived_at": time.time(),
            "files": {},
            "format": "angerona-soar-recoverable-archive-v1",
        }
        for source in sources:
            raw = source.read_bytes()
            destination = archive / source.name
            os.replace(source, destination)
            moved.append((source, destination))
            manifest["files"][source.name] = {  # type: ignore[index]
                "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        receipt = archive / "archive_receipt.json"
        with receipt.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(manifest, handle, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        return archive
    except Exception as exc:
        rollback_errors: list[str] = []
        for source, destination in reversed(moved):
            try:
                os.replace(destination, source)
            except Exception as rollback_exc:
                rollback_errors.append(str(rollback_exc))
        message = f"SOAR archive failed: {exc}"
        if rollback_errors:
            message += "; rollback also failed: " + "; ".join(rollback_errors)
        raise RuntimeError(message) from exc


def _restore_soar_archive(archive: Path) -> None:
    """Restore one archive only when it cannot overwrite newer queue data."""
    archive = Path(archive)
    if archive.parent != _soar_archive_root() or not archive.is_dir():
        raise ValueError("SOAR archive path is outside the recoverable archive root")
    destinations = (_soar_queue_path(), _soar_queue_state_path())
    if any(path.exists() for path in destinations):
        raise RuntimeError("new SOAR history exists; refusing to overwrite it")
    available = tuple(
        (archive / path.name, path)
        for path in destinations
        if (archive / path.name).exists()
    )
    if not available:
        raise RuntimeError("the archive has no recoverable SOAR history")
    moved: list[tuple[Path, Path]] = []
    try:
        for source, destination in available:
            os.replace(source, destination)
            moved.append((source, destination))
    except Exception as exc:
        rollback_errors: list[str] = []
        for source, destination in reversed(moved):
            try:
                os.replace(destination, source)
            except Exception as rollback_exc:
                rollback_errors.append(str(rollback_exc))
        message = f"SOAR restore failed: {exc}"
        if rollback_errors:
            message += "; rollback also failed: " + "; ".join(rollback_errors)
        raise RuntimeError(message) from exc


def _invalidate_soar_queue_cache() -> None:
    global _SOAR_QUEUE_CACHE_KEY, _SOAR_QUEUE_CACHE_VALUE
    _SOAR_QUEUE_CACHE_KEY = None
    _SOAR_QUEUE_CACHE_VALUE = ()


def _soar_record_id(record: dict) -> str:
    """Return a stable identity for new and legacy queue records."""
    value = str(record.get("request_id", "")).strip().casefold()
    if re.fullmatch(r"[0-9a-f]{32}", value):
        return value
    legacy = {
        "ts": record.get("ts", 0),
        "origin_module": record.get("origin_module", ""),
        "severity": record.get("severity", ""),
        "message": record.get("message", ""),
    }
    return hashlib.sha256(
        json.dumps(legacy, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()[:32]


def _soar_authorization_digest(record: dict) -> str:
    """Bind a live-session approval to every response-authorizing field."""
    authority = {
        "request_id": _soar_record_id(record),
        "ts": record.get("ts"),
        "origin_module": record.get("origin_module"),
        "origin_ts": record.get("origin_ts"),
        "origin_hmac": record.get("origin_hmac"),
        "origin_severity": record.get("origin_severity"),
        "origin_message_sha256": record.get("origin_message_sha256"),
        "severity": record.get("severity"),
        "message": record.get("message"),
        "details": record.get("details"),
        "action": record.get("action"),
    }
    canonical = json.dumps(
        authority,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _event_process_snapshot(event) -> dict:
    """Bind a proposed process action to the process instance seen now.

    A PID alone is unsafe because Windows can reuse it between review and
    execution.  ``create_time`` makes later execution fail closed if that
    process has exited and the PID now belongs to something else.
    """
    details = getattr(event, "details", {}) or {}
    pid = details.get("pid") if isinstance(details, dict) else None
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        return {"kind": "review_only", "reason": "alert has no process target"}
    snapshot = {
        "kind": "suspend_process",
        "pid": pid,
        "name": str(details.get("name") or details.get("process_name") or ""),
        "exe": str(
            details.get("exe")
            or details.get("image")
            or details.get("process_path")
            or ""
        ),
    }
    try:
        import psutil

        process = psutil.Process(pid)
        with process.oneshot():
            snapshot["create_time"] = float(process.create_time())
            snapshot["name"] = str(process.name() or snapshot["name"])
            try:
                snapshot["exe"] = str(process.exe() or snapshot["exe"])
            except Exception:
                pass
    except Exception as exc:
        # Keep the item reviewable, but do not later execute without a process
        # instance identity captured at the operator's Block click.
        snapshot["kind"] = "review_only"
        snapshot["reason"] = f"process target unavailable: {exc}"
    return snapshot


def _new_soar_queue_record(event) -> dict:
    """Build a detached, process-identity-bound containment request."""
    details = getattr(event, "details", {}) or {}
    # Round-trip to detach the queue record from the Event's legacy mutable
    # details mapping. The record is evidence only; execution later binds back
    # to the original live EventBus object and verifies its HMAC.
    try:
        details = json.loads(json.dumps(details, default=str))
    except Exception:
        details = {"unavailable": "event details could not be serialized"}
    message = str(getattr(event, "message", ""))
    return {
        "request_id": uuid.uuid4().hex,
        "ts": time.time(),
        "origin_module": getattr(event, "module", ""),
        "origin_ts": float(getattr(event, "ts", 0.0)),
        "origin_hmac": str(getattr(event, "hmac_sig", "") or ""),
        "origin_severity": int(getattr(event, "severity", Severity.INFO)),
        "origin_message_sha256": hashlib.sha256(
            message.encode("utf-8", errors="replace")
        ).hexdigest(),
        "severity": getattr(getattr(event, "severity", None), "label", ""),
        "message": message[:400],
        "details": details,
        "action": _event_process_snapshot(event),
        "status": _SOAR_PENDING,
    }


def _append_soar_queue_record(record: dict) -> bool:
    try:
        with _SOAR_QUEUE_CACHE_LOCK:
            with open(_soar_queue_path(), "a", encoding="utf-8") as f:
                f.write(json.dumps(record, default=str) + "\n")
                f.flush()
                os.fsync(f.fileno())
            _invalidate_soar_queue_cache()
        return True
    except Exception:
        return False


def _persist_soar_queue(event) -> bool:
    """Append a Block→SOAR request to persisted review history."""
    try:
        return _append_soar_queue_record(_new_soar_queue_record(event))
    except Exception:
        return False


def _tail_json_records(path: Path, limit: int) -> list[dict]:
    """Read only the newest bounded JSONL suffix, even when history is huge."""
    wanted = max(0, min(int(limit), _SOAR_STATE_LIMIT))
    if wanted == 0:
        return []
    block = 64 * 1024
    chunks: list[bytes] = []
    newline_count = 0
    with path.open("rb") as handle:
        handle.seek(0, os.SEEK_END)
        position = handle.tell()
        while position > 0 and newline_count <= wanted:
            take = min(block, position)
            position -= take
            handle.seek(position)
            data = handle.read(take)
            chunks.append(data)
            newline_count += data.count(b"\n")
    raw_lines = b"".join(reversed(chunks)).splitlines()[-wanted:]
    records: list[dict] = []
    for raw in raw_lines:
        if not raw.strip() or len(raw) > 1024 * 1024:
            continue
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeError, ValueError, TypeError):
            continue
        if isinstance(value, dict):
            records.append(value)
    return records


def _read_soar_queue_state() -> dict[str, dict]:
    path = _soar_queue_state_path()
    try:
        if not path.exists() or path.stat().st_size > _SOAR_STATE_MAX_BYTES:
            return {}
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError, TypeError):
        return {}
    if not isinstance(value, dict) or len(value) > _SOAR_STATE_LIMIT:
        return {}
    allowed = {
        "status", "reviewed_at", "approved_at", "dismissed_at",
        "submitted_at", "executed_at", "execution_result", "execution_error",
        "receipt_hmac", "receipt_action_ids", "receipt_postcondition_verified",
    }
    out: dict[str, dict] = {}
    for request_id, updates in value.items():
        key = str(request_id).strip().casefold()
        if not re.fullmatch(r"[0-9a-f]{32}", key) or not isinstance(updates, dict):
            continue
        clean = {name: item for name, item in updates.items() if name in allowed}
        if clean:
            out[key] = clean
    return out


def _write_soar_queue_state(state: dict[str, dict]) -> None:
    path = _soar_queue_state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(
        state, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str
    )
    if len(payload.encode("utf-8")) > _SOAR_STATE_MAX_BYTES:
        raise ValueError("SOAR state exceeds its bounded storage budget")
    temp = path.with_name(f"{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    try:
        with temp.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


def _update_soar_queue_record(request_id: str, **updates) -> bool:
    """Atomically update one persisted review record.

    Persisted approval is presentation/audit state only. ``SoarPanel`` also
    requires a same-session in-memory approval before execution, so editing the
    JSONL file cannot manufacture response authority.
    """
    allowed = {
        "status", "reviewed_at", "approved_at", "dismissed_at",
        "submitted_at", "executed_at", "execution_result", "execution_error",
        "receipt_hmac", "receipt_action_ids", "receipt_postcondition_verified",
    }
    if not updates or not set(updates) <= allowed:
        return False
    request_id = str(request_id).strip().casefold()
    try:
        path = _soar_queue_path()
        with _SOAR_QUEUE_CACHE_LOCK:
            records = _tail_json_records(path, _SOAR_STATE_LIMIT) if path.exists() else []
            active_ids = [_soar_record_id(record) for record in records]
            if request_id not in active_ids:
                return False
            state = _read_soar_queue_state()
            state = {key: state[key] for key in active_ids if key in state}
            current = dict(state.get(request_id, {}))
            current.update(updates)
            state[request_id] = current
            _write_soar_queue_state(state)
            _invalidate_soar_queue_cache()
        return True
    except Exception:
        return False


def _read_soar_queue(limit: int = 500) -> list:
    """Read the bounded queue, reusing the parse while the file is unchanged.

    The dashboard calls this every two seconds. A queue normally changes only
    when an operator presses Block or Clear, so reparsing the same 500 JSON
    records on every refresh is pure UI overhead. The cache key includes path,
    nanosecond mtime, byte size, and limit; callers still receive a fresh list.
    """
    global _SOAR_QUEUE_CACHE_KEY, _SOAR_QUEUE_CACHE_VALUE
    out = []
    try:
        p = _soar_queue_path()
        if not p.exists():
            return out
        st = p.stat()
        state_path = _soar_queue_state_path()
        try:
            state_stat = state_path.stat()
            state_key = (state_stat.st_mtime_ns, state_stat.st_size)
        except OSError:
            state_key = (0, 0)
        key = (str(p), st.st_mtime_ns, st.st_size, state_key, int(limit))
        with _SOAR_QUEUE_CACHE_LOCK:
            if key == _SOAR_QUEUE_CACHE_KEY:
                return list(_SOAR_QUEUE_CACHE_VALUE)
        state = _read_soar_queue_state()
        for record in _tail_json_records(p, limit):
            updates = state.get(_soar_record_id(record))
            if updates:
                record.update(updates)
            out.append(record)
        with _SOAR_QUEUE_CACHE_LOCK:
            _SOAR_QUEUE_CACHE_KEY = key
            _SOAR_QUEUE_CACHE_VALUE = tuple(out)
    except Exception:
        pass
    return list(out)


def _soar_origin_event(record: dict, bus):
    """Resolve a queue artifact back to its authoritative live bus event."""
    if bus is None:
        raise PermissionError("the live EventBus is unavailable")
    origin_hmac = str(record.get("origin_hmac", "") or "")
    if getattr(bus, "integrity_enabled", False) and not re.fullmatch(
        r"[0-9a-f]{64}", origin_hmac.casefold()
    ):
        raise PermissionError(
            "authenticated EventBus evidence requires a bound origin HMAC"
        )
    origin_module = str(record.get("origin_module", ""))
    origin_digest = str(record.get("origin_message_sha256", ""))
    try:
        origin_ts = float(record.get("origin_ts", -1.0))
        origin_severity = int(record.get("origin_severity", -1))
    except (TypeError, ValueError) as exc:
        raise PermissionError("the queue record has invalid origin evidence") from exc
    for event in bus.recent(500):
        signature = str(getattr(event, "hmac_sig", "") or "")
        message = str(getattr(event, "message", ""))
        metadata_matches = (
            getattr(event, "module", "") == origin_module
            and float(getattr(event, "ts", -2.0)) == origin_ts
            and int(getattr(event, "severity", -2)) == origin_severity
            and hashlib.sha256(
                message.encode("utf-8", errors="replace")
            ).hexdigest() == origin_digest
        )
        if origin_hmac:
            matches = signature == origin_hmac and metadata_matches
        else:
            matches = metadata_matches
        if not matches:
            continue
        if getattr(bus, "integrity_enabled", False) and not bus.verify(event):
            raise PermissionError("origin event integrity verification failed")
        return event
    raise PermissionError(
        "the signed origin event is no longer in the live evidence ring; "
        "review remains available, but execution is refused"
    )


def _soar_process_preflight(record: dict, bus, manager):
    """Return the still-identical process or fail closed before containment."""
    from angerona.core.eventbus import is_remote_observe_only
    from angerona.core.process_allowlist import is_event_allowed
    from angerona.core.threat import event_disposition

    request_id = _soar_record_id(record)
    if _verified_combat_receipt(bus, request_id) is not None:
        raise PermissionError("this containment request already has a Combat receipt")

    event = _soar_origin_event(record, bus)
    if is_remote_observe_only(event):
        raise PermissionError(
            "remote observe-only evidence cannot authorize a local response"
        )
    if event_disposition(event) not in {"active", "practice"}:
        raise PermissionError(
            "this is exposure/health evidence, not an active or practice threat"
        )
    if is_event_allowed(event):
        raise PermissionError("the target is trusted by the process allowlist")

    action = record.get("action", {})
    if not isinstance(action, dict) or action.get("kind") != "suspend_process":
        reason = action.get("reason", "no supported process action") \
            if isinstance(action, dict) else "no supported process action"
        raise PermissionError(f"review-only item: {reason}")
    pid = action.get("pid")
    captured_at = action.get("create_time")
    if (
        isinstance(pid, bool)
        or not isinstance(pid, int)
        or pid <= 0
        or isinstance(captured_at, bool)
        or not isinstance(captured_at, (int, float))
    ):
        raise PermissionError("the process target has no safe instance identity")
    event_details = getattr(event, "details", {}) or {}
    if not isinstance(event_details, dict) or event_details.get("pid") != pid:
        raise PermissionError(
            "the queued target does not match the signed origin event"
        )
    if pid in {os.getpid(), os.getppid()}:
        raise PermissionError("Angerona refuses to suspend itself or its parent")

    soar = getattr(manager, "modules", {}).get("SOAR Automation") \
        if manager is not None else None
    if soar is None or getattr(soar, "status", "") != "running":
        raise PermissionError("SOAR Automation is not running")
    protected = getattr(soar, "_is_protected_process", None)
    if not callable(protected) or protected(pid):
        raise PermissionError("the target is a protected system process")

    import psutil

    process = psutil.Process(pid)
    with process.oneshot():
        if abs(float(process.create_time()) - float(captured_at)) > 0.01:
            raise PermissionError("PID reuse detected; the original process has exited")
        expected_name = str(action.get("name", "")).strip().casefold()
        current_name = str(process.name() or "").strip().casefold()
        if expected_name and current_name != expected_name:
            raise PermissionError("process identity changed after review was staged")
        expected_exe = str(action.get("exe", "")).strip()
        if expected_exe:
            try:
                current_exe = str(process.exe() or "").strip()
            except Exception as exc:
                raise PermissionError(
                    "the process executable can no longer be verified"
                ) from exc
            if os.path.normcase(os.path.abspath(current_exe)) != os.path.normcase(
                os.path.abspath(expected_exe)
            ):
                raise PermissionError("process executable changed after staging")
    return process, event


def _verified_combat_receipt(bus, request_id: str):
    """Return a locally authenticated, structurally complete Combat receipt."""
    if bus is None or not getattr(bus, "integrity_enabled", False):
        return None
    for event in reversed(bus.recent(500)):
        if getattr(event, "module", "") != "Adversary Combat":
            continue
        details = getattr(event, "details", {}) or {}
        if (
            not isinstance(details, dict)
            or details.get("queue_request_id") != request_id
            or not bus.verify(event)
        ):
            continue
        succeeded = details.get("action_succeeded") is True
        action_ids = details.get("action_ids")
        actions = details.get("actions")
        if succeeded:
            if (
                details.get("postcondition_verified") is not True
                or not isinstance(action_ids, list)
                or not action_ids
                or not all(isinstance(value, str) and value for value in action_ids)
                or not isinstance(actions, list)
                or "suspend_process" not in actions
            ):
                continue
        elif not (
            details.get("action_succeeded") is False
            and isinstance(action_ids, list)
            and not action_ids
            and isinstance(actions, list)
            and not actions
        ):
            continue
        return event
    return None


def _reconcile_soar_submission_receipts(
    records: list[dict], bus, *, timeout_seconds: float = _SOAR_RECEIPT_TIMEOUT_SECONDS
) -> bool:
    """Close submitted queue items only from signed Combat results or timeout."""
    changed = False
    now = time.time()
    for record in records:
        if not str(record.get("status", "")).upper().startswith("SUBMITTED"):
            continue
        request_id = _soar_record_id(record)
        receipt = _verified_combat_receipt(bus, request_id)
        if receipt is not None:
            details = getattr(receipt, "details", {}) or {}
            succeeded = details.get("action_succeeded") is True
            changed = _update_soar_queue_record(
                request_id,
                status=(
                    _SOAR_EXECUTED
                    if succeeded
                    else "FAILED — verified Combat receipt reported no action"
                ),
                executed_at=float(getattr(receipt, "ts", now)),
                execution_result=(
                    str(getattr(receipt, "message", ""))[:1000]
                    if succeeded
                    else ""
                ),
                execution_error=(
                    ""
                    if succeeded
                    else str(getattr(receipt, "message", ""))[:1000]
                ),
                receipt_hmac=str(getattr(receipt, "hmac_sig", "") or ""),
                receipt_action_ids=list(details.get("action_ids", [])),
                receipt_postcondition_verified=(
                    details.get("postcondition_verified") is True
                ),
            ) or changed
            continue
        try:
            submitted_at = float(record.get("submitted_at", 0.0))
        except (TypeError, ValueError, OverflowError):
            submitted_at = 0.0
        if submitted_at > 0 and now - submitted_at >= max(1.0, timeout_seconds):
            changed = _update_soar_queue_record(
                request_id,
                status="FAILED — Combat receipt timeout; verify Action history",
                executed_at=now,
                execution_error=(
                    "No verified Combat completion receipt arrived before the "
                    "queue timeout. The request remains closed to resubmission."
                ),
            ) or changed
    return changed


def _execute_approved_soar_record(record: dict, bus, manager) -> str:
    """Submit one verified process suspension to Combat's durable journal."""
    from angerona.core.eventbus import Event as BusEvent
    from angerona.core.response_contract import authorize_response

    process, origin = _soar_process_preflight(record, bus, manager)
    pid = int(process.pid)
    name = str(process.name() or "process")
    combat = (
        getattr(manager, "modules", {}).get("Adversary Combat")
        if manager is not None
        else None
    )
    policy = combat.policy() if combat is not None else None
    if (
        combat is None
        or getattr(combat, "status", "") != "running"
        or policy is None
        or not policy.enabled
        or not callable(getattr(combat, "response_ready", None))
        or not combat.response_ready()
    ):
        raise PermissionError("Adversary Combat is not armed")
    action = record.get("action", {})
    response = authorize_response(
        ("suspend_process",),
        pid=pid,
        process_create_time=action.get("create_time"),
    )
    if not response:
        raise PermissionError("the exact Combat response contract is invalid")
    bus.publish(BusEvent(
        module="SOAR Operator Request",
        severity=Severity.HIGH,
        message=(
            f"Operator-approved exact process suspension request for {name} (pid {pid})."
        ),
        details={
            "pid": pid,
            "process_create_time": float(action["create_time"]),
            "exe": str(action.get("exe") or ""),
            "operator_approved": True,
            "queue_request_id": _soar_record_id(record),
            "trigger_module": getattr(origin, "module", ""),
            "trigger_ts": getattr(origin, "ts", 0.0),
            "active_attack": True,
            "detector_policy": "operator-approved-exact-soar-request",
            **response,
        },
    ))
    return (
        f"Submitted exact suspension for {name} (pid {pid}) to Adversary Combat. "
        "Review Action history for the verified receipt and Undo control."
    )


def _section(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setObjectName("SectionTitle")
    return lbl


class _ClickableSection(QLabel):
    """Section title that clearly advertises an expanded detail destination."""

    clicked = Signal()

    def __init__(self, text: str, tooltip: str) -> None:
        super().__init__(f"{text}   ›")
        self.setObjectName("SectionTitle")
        self.setCursor(Qt.PointingHandCursor)
        self.setToolTip(tooltip)

    def mousePressEvent(self, event) -> None:  # noqa: N802 - Qt signature
        if event.button() == Qt.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)


# ── Stat cards ───────────────────────────────────────────────────────────────
# Modules whose events are internal chatter, excluded from alert/threat counts.
NOISE_MODULES = ("Self-Test", "Status", "Console")


def _sev_color(sev) -> str:
    """Colour for a Severity, reusing the dashboard THREAT palette."""
    return THREAT.get(sev, ("", "#e5e7eb"))[1]


def _mitre_of(ev) -> str:
    """Best-effort extract of a MITRE/technique id from an event's details, so a
    threat can be matched to a stage-able remediation. Empty string if none."""
    d = getattr(ev, "details", None) or {}
    for key in ("mitre_id", "mitre", "technique_id", "technique", "tid", "ttp"):
        val = d.get(key)
        if val:
            return str(val)
    return ""


class StatCard(QFrame):
    """A dashboard summary tile. Now clickable — emits `clicked` on left press."""

    clicked = Signal()

    def __init__(self, label: str) -> None:
        super().__init__()
        self.setObjectName("Card")
        self.setCursor(Qt.PointingHandCursor)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 14, 18, 14)
        self.value = QLabel("—")
        self.value.setObjectName("CardValue")
        self._rendered: tuple[str, str] | None = None
        lay.addWidget(self.value)
        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        cap = QLabel(label)
        cap.setObjectName("CardLabel")
        row.addWidget(cap)
        row.addStretch(1)
        chevron = QLabel("›")          # ›  affordance: this tile opens a view
        chevron.setStyleSheet("color:#6b7280; font-size:14px; font-weight:bold;")
        row.addWidget(chevron)
        lay.addLayout(row)

    def set(self, text: str, color: str = "#ffffff") -> None:
        rendered = (str(text), str(color))
        if rendered == self._rendered:
            return
        self._rendered = rendered
        self.value.setText(text)
        self.value.setStyleSheet(f"color: {color};")

    def mousePressEvent(self, e) -> None:       # noqa: N802 (Qt signature)
        if e.button() == Qt.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(e)


class DashboardCards(QWidget):
    count_loaded = Signal(object, object)

    def __init__(self, bus, storage, manager) -> None:
        super().__init__()
        self.bus, self.storage, self.manager = bus, storage, manager
        self._accept_async_results = True
        self._count_worker: threading.Thread | None = None
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(14)
        self.c_modules = StatCard("Modules running")
        self.c_alerts = StatCard("Alerts (24h)")
        self.c_crit = StatCard("Active critical (10m)")
        self.c_threat = StatCard("Threat level")
        for c in (self.c_modules, self.c_alerts, self.c_crit, self.c_threat):
            lay.addWidget(c)
        # Each tile opens its own focused detail window.
        self.c_modules.clicked.connect(self._open_modules)
        self.c_alerts.clicked.connect(self._open_alerts)
        self.c_crit.clicked.connect(self._open_critical)
        self.c_threat.clicked.connect(self._open_threat)
        # Use the recorder's committed in-memory revision so this timer never
        # waits behind a SQLite writer/checkpoint on the GUI thread.
        self._last_storage_revision: int = -1
        self._cached_count: int = 0
        self._count_load_busy = False
        self.count_loaded.connect(self._apply_count)

    def refresh(self) -> None:
        running = sum(1 for m in self.manager.modules.values() if m.status == "running")
        self.c_modules.set(f"{running}/{len(self.manager.modules)}")
        revision = self.storage.revision()
        if revision != self._last_storage_revision and not self._count_load_busy:
            self._count_load_busy = True

            def _load_count(_revision=revision) -> None:
                try:
                    count = self.storage.try_count_since(time.time() - 86400)
                    _emit_if_accepting(self, "count_loaded", _revision, count)
                except Exception:
                    _emit_if_accepting(self, "count_loaded", _revision, None)

            self._count_worker = threading.Thread(
                target=_load_count, name="DashboardCountReader", daemon=True
            )
            self._count_worker.start()
        self.c_alerts.set(str(self._cached_count))

        events = self.bus.recent(200)
        crit = sum(
            1 for e in active_threat_events(events)
            if e.severity == Severity.CRITICAL
        )
        self.c_crit.set(str(crit), "#ef4444" if crit else "#ffffff")

        label, color = threat_label(events)
        self.c_threat.set(label, color)

    def _apply_count(self, revision, count) -> None:
        if not self._accept_async_results:
            return
        self._count_load_busy = False
        if count is None:
            return
        self._cached_count = int(count)
        self._last_storage_revision = int(revision)
        self.c_alerts.set(str(self._cached_count))

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt signature
        self._accept_async_results = False
        super().closeEvent(event)

    # ── Drill-down windows ───────────────────────────────────────────────────
    def _open_modules(self) -> None:
        _show_nonmodal_from(
            self.c_modules,
            lambda: ModulesStatusWindow(self.manager, self.bus, self.window()),
            "#22c55e",
        )

    def _open_alerts(self) -> None:
        _show_nonmodal_from(
            self.c_alerts,
            lambda: EventsWindow(
                "Alerts — last 24 hours",
                self.bus,
                self.storage,
                min_sev=Severity.LOW,
                parent=self.window(),
            ),
            "#38bdf8",
        )

    def _open_critical(self) -> None:
        _show_nonmodal_from(
            self.c_crit,
            lambda: EventsWindow(
                "Active critical threats — last 10 minutes",
                self.bus,
                self.storage,
                min_sev=Severity.CRITICAL,
                window_s=600,
                active_only=True,
                parent=self.window(),
            ),
            "#ef4444",
        )

    def _open_threat(self) -> None:
        # Resolve Center: list CRITICAL/HIGH alerts with Allow/Block/Research/Apply/
        # Ignore so the operator can clear false positives and get back to Secure.
        from angerona.gui.resolve_center import ResolveCenter
        _show_nonmodal_from(
            self.c_threat,
            lambda: ResolveCenter(
                self.bus, self.storage, self.manager, self.window()
            ),
            "#fb923c",
        )


# ── Shared helper: fill a table with events ───────────────────────────────────
_EVENT_PATH_KEYS = (
    "artifact_paths",
    "artifact_path",
    "file_path",
    "filepath",
    "path",
    "file",
    "target_path",
    "source_path",
    "destination_path",
    "quarantine_path",
    "old_path",
    "new_path",
    "process_path",
    "exe",
    "image",
    "location",
    "registry_path",
)


def _event_artifact_paths(event, limit: int = 8) -> list[str]:
    """Return bounded, de-duplicated paths supplied by an alert's sensor.

    This stays read-only: looking up an executable from the current PID could
    show a later process after PID reuse instead of the alert's real evidence.
    """
    details = getattr(event, "details", None)
    if not isinstance(details, dict):
        return []
    bounded_limit = max(1, min(32, int(limit)))
    paths: list[str] = []
    seen: set[str] = set()
    for key in _EVENT_PATH_KEYS:
        raw = details.get(key)
        if raw in (None, ""):
            continue
        values = raw if isinstance(raw, (list, tuple, set)) else (raw,)
        for value in values:
            if not isinstance(value, (str, os.PathLike)):
                continue
            text = os.fspath(value).strip()
            if not text:
                continue
            text = text[:4096]
            identity = os.path.normcase(text)
            if identity in seen:
                continue
            seen.add(identity)
            paths.append(text)
            if len(paths) >= bounded_limit:
                return paths
    return paths


def _event_path_display(event) -> tuple[str, str]:
    paths = _event_artifact_paths(event)
    if not paths:
        return "Not provided", "This sensor did not provide a file or artifact path."
    visible = "  ·  ".join(paths[:3])
    if len(paths) > 3:
        visible += f"  (+{len(paths) - 3} more)"
    return visible, "\n".join(paths)


def _fill_event_table(table: QTableWidget, events: list) -> None:
    header = table.horizontalHeader()
    sort_column = header.sortIndicatorSection()
    sort_order = header.sortIndicatorOrder()
    sorting = table.isSortingEnabled()
    table.setSortingEnabled(False)
    table.setRowCount(0)
    for ev in events:
        r = table.rowCount()
        table.insertRow(r)
        event_ts = float(getattr(ev, "ts", time.time()))
        when = time.strftime("%m-%d %H:%M:%S", time.localtime(event_ts))
        sev = getattr(ev, "severity", Severity.INFO)
        sev_item = _SeverityItem(sev)
        time_item = _TimestampItem(event_ts)
        time_item.setText(when)
        table.setItem(r, 0, time_item)
        table.setItem(r, 1, sev_item)
        table.setItem(r, 2, QTableWidgetItem(getattr(ev, "module", "")))
        table.setItem(r, 3, QTableWidgetItem(getattr(ev, "message", "")))
        if table.columnCount() >= 5:
            path_text, path_tooltip = _event_path_display(ev)
            path_item = QTableWidgetItem(path_text)
            path_item.setToolTip(path_tooltip)
            table.setItem(r, 4, path_item)
        table.item(r, 0).setData(Qt.UserRole, ev)
    table.setSortingEnabled(sorting)
    if sorting:
        table.sortItems(sort_column, sort_order)


# ── Alerts / Critical drill-down window ───────────────────────────────────────
class EventsWindow(QDialog):
    """A standalone window listing events at/above a severity over the last 24h.
    Used for both the Alerts tile (min_sev=LOW) and Critical tile (CRITICAL)."""
    MAX_ROWS = 500

    def __init__(self, title, bus, storage, min_sev=Severity.LOW,
                 window_s=86400, active_only=False, parent=None) -> None:
        super().__init__(parent)
        self.bus, self.storage = bus, storage
        self.min_sev, self.window_s = min_sev, window_s
        self.active_only = bool(active_only)
        self.setWindowTitle(title)
        self.setMinimumSize(760, 520)
        if parent:
            self.setStyleSheet(parent.styleSheet())
        root = QVBoxLayout(self)
        root.addWidget(
            FuturisticHeader(
                title,
                "Newest-first event evidence with full alert actions and bounded "
                "24-hour retrieval.",
                "#ef4444" if min_sev >= Severity.CRITICAL else "#38bdf8",
                self,
            )
        )
        self.count_lbl = QLabel("")
        self.count_lbl.setStyleSheet("color:#9aa4b2;")
        root.addWidget(self.count_lbl)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(
            ["Time", "Severity", "Module", "Message", "File / artifact path"]
        )
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.setSortingEnabled(True)
        self.table.sortItems(0, Qt.DescendingOrder)
        # Click a row → open the full Alert detail window (Allow/Block/Analyze/
        # Research), so the Alerts & Critical dashboard boxes expose the same
        # actions as the main Live Alerts feed.
        self.table.cellClicked.connect(self._open_detail)
        root.addWidget(self.table)

        hint = QLabel("Click a row for full detail + actions (Allow · Block · Analyze · Research)")
        hint.setStyleSheet("color:#6b7280; font-size:11px;")
        root.addWidget(hint)

        row = QHBoxLayout()
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self._refresh)
        close = QPushButton("Close")
        close.clicked.connect(self.close)
        row.addStretch(1)
        row.addWidget(refresh)
        row.addWidget(close)
        root.addLayout(row)
        self._refresh()

    def _open_detail(self, row: int, _col: int) -> None:
        item = self.table.item(row, 0)
        if item is None:
            return
        ev = item.data(Qt.UserRole)
        if ev is not None:
            _show_nonmodal_from(
                self.table,
                lambda: AlertDetailDialog(ev, self.window()),
                _sev_color(getattr(ev, "severity", Severity.INFO)),
            )

    def _events(self) -> list:
        now = time.time()
        try:
            evs = self.storage.try_recent_in_window(
                now - self.window_s, now, self.min_sev, self.MAX_ROWS
            )
            if evs is None:
                evs = self.bus.recent(self.MAX_ROWS)
        except Exception:
            evs = self.bus.recent(self.MAX_ROWS)
        out = [e for e in evs
               if now - self.window_s <= getattr(e, "ts", 0) <= now
               and getattr(e, "severity", Severity.INFO) >= self.min_sev
               and getattr(e, "module", "") not in NOISE_MODULES]
        out.sort(key=lambda e: getattr(e, "ts", 0), reverse=True)
        if self.active_only:
            out = active_threat_events(out, window=self.window_s)
            out.sort(key=lambda e: getattr(e, "ts", 0), reverse=True)
        return out

    def _refresh(self) -> None:
        evs = self._events()
        _fill_event_table(self.table, evs)
        qualifier = "most recent " if len(evs) >= self.MAX_ROWS else ""
        duration = (
            f"{self.window_s / 60:g} minutes" if self.window_s < 3600
            else f"{self.window_s / 3600:g}h"
        )
        self.count_lbl.setText(f"Showing {qualifier}{len(evs)} event(s) in the last "
                               f"{duration}")


# ── Modules status drill-down window ──────────────────────────────────────────
class ModulesStatusWindow(QDialog):
    """Searchable Capability Center for every discovered module contract."""

    def __init__(self, manager, bus, parent=None) -> None:
        super().__init__(parent)
        self.manager, self.bus = manager, bus
        self.setWindowTitle("Capability Center — modules")
        self.setMinimumSize(1040, 620)
        if parent:
            self.setStyleSheet(parent.styleSheet())
        root = QVBoxLayout(self)
        root.addWidget(
            FuturisticHeader(
                "Capability Center · Live Contracts",
                "Search operational truth, platform coverage, authority, maturity, "
                "loss state, and implementation versions for all capabilities.",
                "#22c55e",
                self,
            )
        )
        self.summary = QLabel("")
        self.summary.setStyleSheet("color:#9aa4b2;")
        root.addWidget(self.summary)

        filters = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search name, category, capability ID…")
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self._refresh)
        filters.addWidget(self.search, 2)
        self.mode_filter = QComboBox()
        self.mode_filter.addItems(
            ["All modes", "unknown", "observe", "detect", "protect", "respond"]
        )
        self.mode_filter.currentIndexChanged.connect(self._refresh)
        filters.addWidget(self.mode_filter)
        self.maturity_filter = QComboBox()
        self.maturity_filter.addItems(
            ["All maturity", "stable", "preview", "experimental", "compatibility"]
        )
        self.maturity_filter.currentIndexChanged.connect(self._refresh)
        filters.addWidget(self.maturity_filter)
        self.status_filter = QComboBox()
        self.status_filter.addItems(
            ["All status", "running", "stopped", "unavailable", "error", "restarting"]
        )
        self.status_filter.currentIndexChanged.connect(self._refresh)
        filters.addWidget(self.status_filter)
        self.assurance_filter = QComboBox()
        self.assurance_filter.addItems(
            ["All assurance", "Below 100%", "100%", "Below 70%"]
        )
        self.assurance_filter.currentIndexChanged.connect(self._refresh)
        filters.addWidget(self.assurance_filter)
        root.addLayout(filters)

        self.table = QTableWidget(0, 9)
        self.table.setHorizontalHeaderLabels(
            [
                "Module", "Status", "Health", "Assurance", "Mode", "Platforms",
                "Maturity", "Authority", "Impl.",
            ]
        )
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.setSortingEnabled(True)
        self.table.cellClicked.connect(self._open_module)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._context_menu)
        root.addWidget(self.table)

        row = QHBoxLayout()
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self._refresh)
        close = QPushButton("Close")
        close.clicked.connect(self.close)
        row.addStretch(1)
        row.addWidget(refresh)
        row.addWidget(close)
        root.addLayout(row)

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh)
        self._timer.start(1500)
        self._last_snapshot = None
        self._refresh()

    def _refresh(self) -> None:
        mods = sorted(self.manager.modules.items())
        try:
            subscriber_metrics = self.bus.subscriber_metrics()
        except Exception:
            subscriber_metrics = ()
        subscriber_failures = sum(item.failures for item in subscriber_metrics)
        subscriber_slo_violations = sum(
            item.budget_violations for item in subscriber_metrics
        )
        query = self.search.text().strip().casefold()
        mode_filter = self.mode_filter.currentText()
        maturity_filter = self.maturity_filter.currentText()
        status_filter = self.status_filter.currentText()
        assurance_filter = self.assurance_filter.currentText()
        visible: list[tuple[str, object, dict, tuple[str, int, str], object]] = []
        for name, mod in mods:
            contract = _capability_summary(mod)
            haystack = " ".join(
                (
                    name,
                    str(getattr(mod, "category", "")),
                    str(contract.get("capability_id", "")),
                    str(contract.get("description", "")),
                )
            ).casefold()
            if query and query not in haystack:
                continue
            if mode_filter != "All modes" and contract.get("mode") != mode_filter:
                continue
            if maturity_filter != "All maturity" and contract.get("maturity") != maturity_filter:
                continue
            health_summary = mod.health_summary()
            if status_filter != "All status" and health_summary[0] != status_filter:
                continue
            assurance = _module_assurance(
                self.manager,
                mod,
                _fast_assurance_operational(mod, health_summary),
            )
            if assurance_filter == "Below 100%" and assurance.score >= 100:
                continue
            if assurance_filter == "100%" and assurance.score != 100:
                continue
            if assurance_filter == "Below 70%" and assurance.score >= 70:
                continue
            visible.append((name, mod, contract, health_summary, assurance))
        snapshot = tuple(
            (name, getattr(mod, "name", name), health_summary[0],
             health_summary[1], health_summary[2],
             assurance.score,
             tuple((item.dimension, item.score, item.state) for item in assurance.dimensions),
             contract.get("mode"), contract.get("maturity"),
             contract.get("response_authority"), contract.get("implementation_version"),
             getattr(mod, "_bus_overflow_count", 0))
            for name, mod, contract, health_summary, assurance in visible
        ) + (("__subscriber_slo__", subscriber_failures, subscriber_slo_violations),)
        if snapshot == self._last_snapshot:
            return
        self._last_snapshot = snapshot
        selected = self._selected_module()
        selected_name = getattr(selected, "name", "") if selected is not None else ""
        header = self.table.horizontalHeader()
        sort_column = header.sortIndicatorSection()
        sort_order = header.sortIndicatorOrder()
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        running = 0
        overflowed = 0
        native = 0
        sub_full_assurance = 0
        for name, mod, contract, health_summary, assurance in visible:
            r = self.table.rowCount()
            self.table.insertRow(r)
            status, health_value, health_state = health_summary
            running += (status == "running")
            name_item = QTableWidgetItem(getattr(mod, "name", name))
            name_item.setData(Qt.UserRole, name)
            self.table.setItem(r, 0, name_item)
            st_item = QTableWidgetItem(status)
            st_item.setForeground(QColor(STATUS_COLOR.get(status, "#e5e7eb")))
            self.table.setItem(r, 1, st_item)
            h_item = _PercentTableItem(health_value if status == "running" else None)
            h_item.setForeground(QColor(HEALTH_COLOR.get(health_state, "#e5e7eb")))
            self.table.setItem(r, 2, h_item)
            assurance_item = _PercentTableItem(assurance.score)
            assurance_item.setForeground(QColor(_assurance_color(assurance.score)))
            assurance_item.setToolTip(_assurance_tooltip(assurance))
            assurance_item.setData(Qt.UserRole, assurance.as_dict())
            self.table.setItem(r, 3, assurance_item)
            self.table.setItem(r, 4, QTableWidgetItem(str(contract.get("mode", "legacy"))))
            self.table.setItem(
                r, 5, QTableWidgetItem(", ".join(contract.get("supported_platforms", ())))
            )
            self.table.setItem(r, 6, QTableWidgetItem(str(contract.get("maturity", "compatibility"))))
            self.table.setItem(
                r, 7, QTableWidgetItem(str(contract.get("response_authority", "none")))
            )
            self.table.setItem(
                r, 8, QTableWidgetItem(str(contract.get("implementation_version", "?")))
            )
            overflowed += int(getattr(mod, "_bus_overflow_count", 0) > 0)
            native += int(contract.get("metadata_level") == "native")
            sub_full_assurance += int(assurance.score < 100)
        self.table.setSortingEnabled(True)
        self.table.sortItems(sort_column, sort_order)
        if selected_name:
            for row in range(self.table.rowCount()):
                item = self.table.item(row, 0)
                if item is not None and item.data(Qt.UserRole) == selected_name:
                    self.table.selectRow(row)
                    break
        self.summary.setText(
            f"Showing {len(visible)}/{len(mods)} · {running} running · "
            f"{native} native contracts · {sub_full_assurance} below 100% assurance · "
            f"{overflowed} with evidence-loss history · "
            f"subscriber failures/SLO {subscriber_failures}/{subscriber_slo_violations}"
        )

    def _selected_module(self):
        row = self.table.currentRow()
        item = self.table.item(row, 0) if row >= 0 else None
        name = item.data(Qt.UserRole) if item is not None else None
        return self.manager.modules.get(name) if name else None

    def _context_menu(self, position) -> None:
        item = self.table.itemAt(position)
        if item is None:
            return
        self.table.selectRow(item.row())
        module = self._selected_module()
        if module is None:
            return
        menu = QMenu(self)
        inspect_action = menu.addAction("Inspect capability")
        assurance_action = menu.addAction("Explain assurance score")
        test_action = menu.addAction("Run safe self-test")
        restart_action = menu.addAction("Restart module")
        enabled = self.manager.is_enabled(module.name)
        toggle_action = menu.addAction("Disable" if enabled else "Enable")
        menu.addSeparator()
        copy_action = menu.addAction("Copy capability ID")
        selected = menu.exec(self.table.viewport().mapToGlobal(position))
        if selected == inspect_action:
            self._open_module(item.row(), 0)
        elif selected == assurance_action:
            self._open_module(item.row(), 3)
        elif selected == test_action:
            def _test_inspector():
                inspector = ModuleInspector(
                    self.manager, self.bus, module, self.window()
                )
                QTimer.singleShot(0, inspector._selftest)
                return inspector

            _show_nonmodal_from(self.table, _test_inspector, "#22c55e")
        elif selected == restart_action:
            module.stop()
            module.start()
            self._refresh()
        elif selected == toggle_action:
            self.manager.set_enabled(module.name, not enabled)
            self._refresh()
        elif selected == copy_action:
            contract = _capability_contract(module)
            QGuiApplication.clipboard().setText(str(contract.get("capability_id", module.name)))

    def _open_module(self, row: int, column: int) -> None:
        item = self.table.item(row, 0)
        name = item.data(Qt.UserRole) if item is not None else None
        module = self.manager.modules.get(name) if name else None
        if module is None:
            return
        if column in {2, 3}:
            try:
                operational = module.operational_snapshot()
            except Exception:
                operational = {
                    "status": "snapshot-error",
                    "health": 0,
                    "health_note": "Module operational snapshot is unavailable.",
                    "health_evidence": None,
                }
            if column == 2:
                try:
                    health = max(0, min(100, int(operational.get("health", 0))))
                except (TypeError, ValueError):
                    health = 0
                if health < 100:
                    evidence = operational.get("health_evidence")
                    if not isinstance(evidence, dict):
                        evidence = {
                            "reason": str(
                                operational.get("health_note")
                                or f"Module reports {health}% health without a diagnostic reason."
                            )[:1000],
                            "source_state": "unavailable",
                            "source_path": None,
                            "source_line": None,
                            "source_sha256": None,
                            "source_provenance": "unavailable",
                        }
                    _show_nonmodal_from(
                        self.table,
                        lambda: ModuleHealthEvidenceDialog(
                            module.name, evidence, self.window()
                        ),
                        "#ef4444",
                    )
                    return
            else:
                assurance = _module_assurance(self.manager, module, operational)
                _show_nonmodal_from(
                    self.table,
                    lambda: ModuleAssuranceDialog(
                        module.name, assurance, self.window()
                    ),
                    _assurance_color(assurance.score),
                )
                return
        _show_nonmodal_from(
            self.table,
            lambda: ModuleInspector(
                self.manager, self.bus, module, self.window()
            ),
            "#22c55e",
        )


# ── Threat drill-down window (with fix / harden actions) ──────────────────────
class ThreatWindow(QDialog):
    """Lists the HIGH/CRITICAL events currently driving the threat level, with
    per-threat detail and two remediation actions wired to Posture Hardening:
      • Attempt fix  — stage a review-gated remediation for the selected threat.
      • Harden system — stage remediations for all open weaknesses.
    Nothing that changes the OS runs without an explicit confirmation."""

    _action_done = Signal(str)

    def __init__(self, bus, storage, manager, parent=None) -> None:
        super().__init__(parent)
        self.bus, self.storage, self.manager = bus, storage, manager
        self._accept_async_results = True
        self._action_worker: threading.Thread | None = None
        self.setWindowTitle("Threat level — triggering threats")
        self.setMinimumSize(820, 640)
        if parent:
            self.setStyleSheet(parent.styleSheet())
        root = QVBoxLayout(self)

        label, color = threat_label(self.bus.recent(200))
        root.addWidget(FuturisticHeader(
            f"Threat level: {label}",
            "Only the HIGH / CRITICAL events driving posture are shown; select one to inspect or stage a fix",
            color,
            self,
        ))

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Time", "Severity", "Module", "Message"])
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.cellClicked.connect(self._on_select)
        root.addWidget(self.table)

        self.detail = QPlainTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setMaximumHeight(180)
        self.detail.setPlaceholderText("Select a threat to inspect its details.")
        root.addWidget(self.detail)

        controls = QHBoxLayout()
        self.fix_btn = QPushButton("Generate advisory + vetted plan")
        self.fix_btn.clicked.connect(self._attempt_fix)
        self.apply_btn = QPushButton("Apply vetted typed fixes…")
        self.apply_btn.clicked.connect(self._apply_fix)
        self.apply_btn.setEnabled(False)
        self.harden_btn = QPushButton("Harden system")
        self.harden_btn.clicked.connect(self._harden)
        self.blast_btn = QPushButton("Blast radius")
        self.blast_btn.clicked.connect(self._open_blast)
        self.collision_btn = QPushButton("Shark vs Shield")
        self.collision_btn.clicked.connect(self._open_collision)
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self._refresh)
        controls.addWidget(self.fix_btn)
        controls.addWidget(self.apply_btn)
        controls.addWidget(self.harden_btn)
        controls.addWidget(self.blast_btn)
        controls.addWidget(self.collision_btn)
        controls.addStretch(1)
        controls.addWidget(refresh)
        root.addLayout(controls)

        self.status_lbl = QLabel("")
        self.status_lbl.setWordWrap(True)
        root.addWidget(self.status_lbl)

        self._action_done.connect(self._on_action_done)
        self._selected_mitre = ""
        self._busy = False
        self._refresh()

    # ── data ─────────────────────────────────────────────────────────────────
    def _threats(self) -> list:
        evs = active_threat_events(self.bus.recent(300))
        evs.sort(key=lambda e: getattr(e, "ts", 0), reverse=True)
        return evs

    def _refresh(self) -> None:
        _fill_event_table(self.table, self._threats())
        if self.table.rowCount() == 0:
            self.detail.setPlainText("No active HIGH/CRITICAL threats. You're clear.")

    def _posture(self):
        """Find the Posture Hardening module by capability (name-independent)."""
        for m in self.manager.modules.values():
            if hasattr(m, "generate_remediation") and hasattr(m, "weaknesses"):
                return m
        return None

    def _selected_event(self):
        row = self.table.currentRow()
        if row < 0:
            return None
        cell = self.table.item(row, 0)
        return cell.data(Qt.UserRole) if cell else None

    # ── interactions ─────────────────────────────────────────────────────────
    def _on_select(self, *_):
        ev = self._selected_event()
        if not ev:
            return
        self._selected_mitre = _mitre_of(ev)
        lines = [
            f"Module:    {getattr(ev, 'module', '')}",
            f"Severity:  {getattr(ev, 'severity', Severity.INFO).label}",
            f"Time:      {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(getattr(ev, 'ts', 0)))}",
            f"Technique: {self._selected_mitre or '(none detected)'}",
            "",
            getattr(ev, "message", ""),
        ]
        details = getattr(ev, "details", None)
        if details:
            try:
                lines += ["", "Details:", json.dumps(details, indent=2, default=str)]
            except Exception:
                lines += ["", f"Details: {details}"]
        self.detail.setPlainText("\n".join(lines))
        self.apply_btn.setEnabled(False)

    def _guard(self) -> bool:
        if self._busy:
            self.status_lbl.setText("Working… please wait for the current action to finish.")
            return False
        posture = self._posture()
        if posture is None:
            self.status_lbl.setText("[!] Posture Hardening module is not available.")
            return False
        return True

    def _run_async(self, fn) -> None:
        self._busy = True
        self.fix_btn.setEnabled(False)
        self.harden_btn.setEnabled(False)
        self.status_lbl.setText("Working…")

        def work():
            try:
                msg = fn()
            except Exception as exc:               # never let a worker crash the app
                msg = f"[!] Action failed: {exc}"
            _emit_if_accepting(self, "_action_done", msg)

        self._action_worker = threading.Thread(
            target=work, name="ThreatActionWorker", daemon=True
        )
        self._action_worker.start()

    def _on_action_done(self, msg: str) -> None:
        if not self._accept_async_results:
            return
        self._busy = False
        self.fix_btn.setEnabled(True)
        self.harden_btn.setEnabled(True)
        self.status_lbl.setText(msg)

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt signature
        self._accept_async_results = False
        super().closeEvent(event)

    def _attempt_fix(self) -> None:
        if not self._guard():
            return
        ev = self._selected_event()
        if not ev:
            self.status_lbl.setText("Select a threat first.")
            return
        mitre = _mitre_of(ev)
        posture = self._posture()
        if not mitre:
            self.status_lbl.setText(
                "This threat has no MITRE technique id, so it can't be auto-staged. "
                "Open the Posture Hardening module to review weaknesses manually.")
            return

        def do():
            res = posture.generate_remediation(mitre)
            if isinstance(res, dict) and res.get("ok", True) and not res.get("error"):
                self._selected_mitre = mitre
                plan = posture.apply_vetted_remediation(apply=False)
                return (
                    f"[+] Saved an inert local-AI advisory for {mitre}. "
                    f"A vetted typed plan contains {len(plan.get('plan', []))} item(s); "
                    "use 'Apply vetted typed fixes' for host changes."
                )
            return f"[!] Could not stage a fix for {mitre}: {res}"

        self._run_async(do)
        # The Apply button invokes only the reviewed typed remediation library.
        self.apply_btn.setEnabled(True)

    def _apply_fix(self) -> None:
        if not self._guard():
            return
        mitre = self._selected_mitre
        if not mitre:
            self.status_lbl.setText("Generate an advisory and vetted plan first.")
            return
        from PySide6.QtWidgets import QMessageBox
        if QMessageBox.question(
                self, "Apply vetted typed remediations?",
                f"Apply the reviewed typed remediation library for current open "
                f"weaknesses (selected technique: {mitre})? No local-AI text or "
                "arbitrary PowerShell will execute.\n\nProceed?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
            return
        posture = self._posture()

        def do():
            res = posture.apply_vetted_remediation(apply=True)
            return (
                "[+] Vetted typed remediation run completed: "
                f"applied={res.get('applied', 0)}, skipped={res.get('skipped', 0)}, "
                f"failed={res.get('failed', 0)}."
            )

        self._run_async(do)

    def _harden(self) -> None:
        if not self._guard():
            return
        posture = self._posture()

        def do():
            try:
                weaknesses = posture.weaknesses(status="VULNERABLE")
            except Exception:
                weaknesses = posture.weaknesses()
            if not weaknesses:
                return "[+] No open weaknesses on record — nothing to harden."
            staged = 0
            for w in weaknesses:
                try:
                    posture.generate_remediation(w["mitre_id"])
                    staged += 1
                except Exception:
                    pass
            return (f"[+] Generated inert advisories for {staged}/{len(weaknesses)} "
                    "open weakness(es). Host changes require the vetted typed plan.")

        self._run_async(do)

    # ── blast radius + collision view ────────────────────────────────────────
    def _prov(self):
        """Find the Provenance Graph module by capability (name-independent)."""
        for m in self.manager.modules.values():
            if hasattr(m, "ancestry") and hasattr(m, "subtree"):
                return m
        return None

    def _open_blast(self) -> None:
        ev = self._selected_event()
        pid = None
        if ev is not None:
            d = getattr(ev, "details", None) or {}
            for k in ("pid", "process_id", "target_pid"):
                if d.get(k):
                    try:
                        pid = int(d[k])
                        break
                    except (TypeError, ValueError):
                        pass
        if pid is None:
            self.status_lbl.setText("Select a threat that carries a PID to map its blast radius.")
            return
        prov = self._prov()
        if prov is None:
            self.status_lbl.setText("[!] Provenance Graph module is not available.")
            return
        BlastRadiusDialog(prov, pid, self).exec()

    def _open_collision(self) -> None:
        CollisionView(self).exec()


# ── Blast-radius provenance tree ─────────────────────────────────────────────
_MAX_VISIBLE_FAMILY_NODES = 500


def _bounded_provenance_nodes(value, limit: int) -> tuple[list[dict], bool]:
    """Snapshot an arbitrary provenance result without flooding Qt with rows."""
    if value is None:
        return [], False
    if isinstance(value, dict):
        values = iter((value,))
    else:
        try:
            values = iter(value)
        except TypeError:
            values = iter((value,))

    nodes: list[dict] = []
    truncated = False
    for raw in values:
        if len(nodes) >= limit:
            truncated = True
            break
        if isinstance(raw, dict):
            # Detach from the live graph so a concurrent retention pass cannot
            # mutate a row while Qt is rendering it.
            node = dict(raw)
            meta = node.get("meta")
            if isinstance(meta, dict):
                node["meta"] = dict(meta)
        else:
            node = {"id": str(raw), "kind": "unknown", "label": str(raw), "meta": {}}
        nodes.append(node)
    return nodes, truncated


def build_blast_tree(prov, target_pid: int) -> dict:
    """Core data logic for a PID blast radius (blueprint contract):
    {'origin': <ancestry, root-cause chain>, 'blast_radius': <subtree spawned>}.
    Both are lists of provenance node dicts ({id, kind, label, ts, meta}).
    The GUI snapshot is bounded because constructing thousands of native tree
    items synchronously can exhaust or crash the Windows Qt paint path.
    """
    pid = int(target_pid)
    if pid <= 0:
        raise ValueError("PID must be greater than zero")
    origin, origin_truncated = _bounded_provenance_nodes(
        prov.ancestry(pid), _MAX_VISIBLE_FAMILY_NODES
    )
    blast, blast_truncated = _bounded_provenance_nodes(
        prov.subtree(pid), _MAX_VISIBLE_FAMILY_NODES
    )
    return {
        "origin": origin,
        "blast_radius": blast,
        "origin_truncated": origin_truncated,
        "blast_radius_truncated": blast_truncated,
    }


class BlastRadiusDialog(QDialog):
    """Renders build_blast_tree(pid) as a hierarchical tree: the upstream origin
    chain that led to the process, and the downstream blast radius it spawned
    (child processes, files written, network connections opened)."""

    def __init__(self, prov, pid: int, parent=None) -> None:
        super().__init__(parent)
        self.prov, self.pid = prov, pid
        self.setWindowTitle(f"Blast radius — PID {pid}")
        self.setMinimumSize(680, 560)
        if parent:
            self.setStyleSheet(parent.styleSheet())
        from PySide6.QtWidgets import QTreeWidget, QTreeWidgetItem
        self._QTreeWidgetItem = QTreeWidgetItem
        root = QVBoxLayout(self)
        head = QLabel(f"Blast radius — PID {pid}")
        head.setObjectName("PageTitle")
        root.addWidget(head)
        self.summary = QLabel("")
        self.summary.setStyleSheet("color:#9aa4b2;")
        root.addWidget(self.summary)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Node", "Kind", "Detail"])
        self.tree.setColumnWidth(0, 300)
        self.tree.setUniformRowHeights(True)
        root.addWidget(self.tree)

        row = QHBoxLayout()
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self._refresh)
        close = QPushButton("Close")
        close.clicked.connect(self.close)
        row.addStretch(1)
        row.addWidget(refresh)
        row.addWidget(close)
        root.addLayout(row)
        self._refresh()

    def _node_item(self, node: dict):
        label = node.get("label", node.get("id", "?"))
        kind = node.get("kind", "")
        meta = node.get("meta") or {}
        if isinstance(meta, dict):
            detail = ", ".join(f"{k}={v}" for k, v in meta.items())
        else:
            detail = str(meta)
        if not detail:
            detail = node.get("id", "")
        detail = str(detail)[:4096]
        it = self._QTreeWidgetItem([str(label), str(kind), str(detail)])
        colour = {"file": "#f59e0b", "net": "#38bdf8"}.get(str(kind).lower(), "#e5e7eb")
        it.setForeground(0, QColor(colour))
        return it

    def _refresh(self) -> None:
        self.tree.clear()
        Item = self._QTreeWidgetItem
        try:
            tree = build_blast_tree(self.prov, self.pid)
            origin, blast = tree["origin"], tree["blast_radius"]
        except Exception as exc:
            message = f"Process family tree unavailable: {str(exc)[:500]}"
            self.tree.addTopLevelItem(
                Item([message, "Error", "No application crash occurred."])
            )
            self.summary.setText(message)
            return
        origin_root = Item([f"Origin — how PID {self.pid} came to exist", "", f"{len(origin)} node(s)"])
        for n in origin:
            origin_root.addChild(self._node_item(n))
        blast_root = Item([f"Blast radius — what PID {self.pid} spawned/touched", "",
                           f"{len(blast)} node(s)"])
        for n in blast:
            blast_root.addChild(self._node_item(n))
        self.tree.addTopLevelItem(origin_root)
        self.tree.addTopLevelItem(blast_root)
        origin_root.setExpanded(True)
        blast_root.setExpanded(True)
        clipped = []
        if tree.get("origin_truncated"):
            clipped.append(f"origin limited to {_MAX_VISIBLE_FAMILY_NODES}")
        if tree.get("blast_radius_truncated"):
            clipped.append(f"descendants limited to {_MAX_VISIBLE_FAMILY_NODES}")
        suffix = f" Display bounded: {', '.join(clipped)}." if clipped else ""
        if not origin and not blast:
            self.summary.setText(
                f"No recorded parents, children, files, or connections for PID {self.pid}."
                + suffix
            )
        else:
            self.summary.setText(
                f"{len(origin)} ancestor node(s) upstream, "
                f"{len(blast)} node(s) in the downstream blast radius." + suffix
            )


# ── Shark-vs-Shield collision view ───────────────────────────────────────────
# Map the module that caught a footprint to its hardening ring.
_RING_OF_MODULE = {
    "file integrity monitor": "Ring 1 · Driver/File Shield",
    "process monitor": "Ring 1 · Driver/File Shield",
    "upstream threat intel sync": "Ring 1 · Driver-Intel",
    "api patch / anti-blinding detector": "Ring 2 · In-Memory Integrity",
    "indirect syscall bridge": "Ring 2 · In-Memory Integrity",
    "telemetry canary drill": "Ring 3 · Runtime Vitality",
    "etw core listener": "Ring 3 · Runtime Vitality",
    "anti-suspension heartbeat": "Ring 3 · Runtime Vitality",
    "posture hardening": "Ring 4 · Posture Evolution",
    "active response soar": "Ring 4 · Posture Evolution",
    "soar automation": "Ring 4 · Posture Evolution",
    "yara scanner": "Ring 1 · Driver/File Shield",
}


def _ring_for(module_name: str) -> str:
    return _RING_OF_MODULE.get(str(module_name or "").lower().strip(), "—")


class CollisionView(QDialog):
    """Shark-vs-Shield collision view: reads the latest red-team After-Action
    Report and shows, per simulated technique, whether a defensive ring caught
    it and which one — the 'which ring of the circle caught the footprint' view."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Shark vs Shield — collision view")
        self.setMinimumSize(880, 560)
        if parent:
            self.setStyleSheet(parent.styleSheet())
        root = QVBoxLayout(self)
        head = QLabel("Shark vs Shield — collision view")
        head.setObjectName("PageTitle")
        root.addWidget(head)
        self.summary = QLabel("")
        self.summary.setStyleSheet("color:#9aa4b2;")
        self.summary.setWordWrap(True)
        root.addWidget(self.summary)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(
            ["Technique / stage", "Caught?", "Ring", "Detected by", "Latency"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.cellDoubleClicked.connect(self._on_verdict)   # row → detail + actions
        self._row_verdicts: dict = {}
        root.addWidget(self.table)
        _hint = QLabel("Double-click a technique for full detail + a MITRE ATT&CK link.")
        _hint.setStyleSheet("color:#64748b; font-size:11px;")
        root.addWidget(_hint)

        row = QHBoxLayout()
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self._refresh)
        close = QPushButton("Close")
        close.clicked.connect(self.close)
        row.addStretch(1)
        row.addWidget(refresh)
        row.addWidget(close)
        root.addLayout(row)
        self._refresh()

    @staticmethod
    def _aar_paths() -> list:
        try:
            from angerona.core.data_paths import data_dir
            repo = data_dir()
        except Exception:
            repo = Path(".")
        # Current reports live at the canonical runtime root. Retain the old
        # diagnostics locations as read-only fallbacks for pre-migration runs.
        return [repo / "redteam_aar.json",
                repo / "shark_aar.json",
                repo / "diagnostics" / "redteam_aar.json",
                repo / "diagnostics" / "shark_aar.json"]

    def _load_verdicts(self) -> tuple:
        for p in self._aar_paths():
            try:
                if p.exists():
                    data = json.loads(p.read_text(encoding="utf-8"))
                    return data.get("verdicts", []), str(p)
            except Exception:
                continue
        return [], ""

    def _refresh(self) -> None:
        verdicts, src = self._load_verdicts()
        self.table.setRowCount(0)
        self._row_verdicts = {}
        caught = 0
        for v in verdicts:
            r = self.table.rowCount()
            self.table.insertRow(r)
            self._row_verdicts[r] = v
            is_caught = bool(v.get("caught"))
            caught += is_caught
            by = v.get("detected_by") or ""
            lat = v.get("detect_latency_s")
            tech = f"{v.get('stage', '')} — {v.get('technique', '')}".strip(" —")
            self.table.setItem(r, 0, QTableWidgetItem(tech))
            c_item = QTableWidgetItem("BLOCKED" if is_caught else "MISSED")
            c_item.setForeground(QColor("#22c55e" if is_caught else "#ef4444"))
            self.table.setItem(r, 1, c_item)
            self.table.setItem(r, 2, QTableWidgetItem(_ring_for(by) if is_caught else "—"))
            self.table.setItem(r, 3, QTableWidgetItem(by))
            self.table.setItem(r, 4, QTableWidgetItem(
                f"{lat:.1f}s" if isinstance(lat, (int, float)) else "—"))
        n = len(verdicts)
        if not n:
            self.summary.setText("No red-team After-Action Report found yet. Run a Shark "
                                 "drill, then reopen this view to see the ring-by-ring collision.")
        else:
            self.summary.setText(f"{caught}/{n} simulated technique(s) intercepted by the shield. "
                                 f"Source: {src}")

    def _on_verdict(self, row: int, _col: int) -> None:
        v = getattr(self, "_row_verdicts", {}).get(row)
        if v:
            self._verdict_detail(v)

    def _verdict_detail(self, v: dict) -> None:
        import re
        import webbrowser
        import json as _json
        from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel,
                                       QTextEdit, QPushButton, QApplication)
        tech = f"{v.get('stage', '')} — {v.get('technique', '')}".strip(" —")
        caught = bool(v.get("caught"))
        m = re.search(r"\bT\d{4}(?:\.\d{3})?\b", _json.dumps(v))
        tid = m.group(0) if m else ""

        dlg = QDialog(self); dlg.setWindowTitle(f"Collision detail — {tech or 'technique'}")
        dlg.resize(640, 480)
        try:
            dlg.setStyleSheet(self.styleSheet())
        except Exception:
            pass
        lay = QVBoxLayout(dlg)
        colour = "#22c55e" if caught else "#ef4444"
        status = "BLOCKED by the shield" if caught else "MISSED — not intercepted"
        lay.addWidget(QLabel(f"<b>{tech or 'Technique'}</b><br>Result: "
                             f"<b style='color:{colour}'>{status}</b>"))
        det = QTextEdit(); det.setReadOnly(True)
        det.setPlainText("\n".join(f"{k}: {val}" for k, val in v.items()))
        lay.addWidget(det)

        rowb = QHBoxLayout()
        if tid:
            base = tid.split(".")[0]
            url = (f"https://attack.mitre.org/techniques/{base}/{tid.split('.')[1]}/"
                   if "." in tid else f"https://attack.mitre.org/techniques/{tid}/")
            b_mitre = QPushButton(f"MITRE ATT&CK ({tid})")
            b_mitre.clicked.connect(lambda: webbrowser.open(url))
            rowb.addWidget(b_mitre)
        b_copy = QPushButton("Copy details")
        b_copy.clicked.connect(lambda: QApplication.clipboard().setText(det.toPlainText()))
        rowb.addWidget(b_copy)
        b_close = QPushButton("Close"); b_close.clicked.connect(dlg.close)
        rowb.addWidget(b_close)
        lay.addLayout(rowb)
        dlg.exec()


# ── Red Team Simulation config (unified Shark + APT, difficulty/target/custom) ─
class CustomTechniqueStore:
    """Tiny JSON-backed library of user-defined benign techniques (name + payload).
    Persisted so saved techniques survive restarts and can be re-used, edited, or
    deleted. Payload is only ever written as an inert marker at run time."""

    def __init__(self, path) -> None:
        self.path = Path(path)
        self._items = self._load()

    def _load(self) -> list:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return [d for d in data if isinstance(d, dict) and d.get("name")]
        except Exception:
            return []

    def save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self._items, indent=2), encoding="utf-8")
        except Exception:
            pass

    def names(self) -> list:
        return [i["name"] for i in self._items]

    def get(self, name: str):
        return next((i for i in self._items if i["name"] == name), None)

    def upsert(self, name: str, payload: str) -> None:
        it = self.get(name)
        if it:
            it["payload"] = payload
        else:
            self._items.append({"name": name, "payload": payload})
        self.save()

    def delete(self, name: str) -> None:
        self._items = [i for i in self._items if i["name"] != name]
        self.save()


class RedTeamSimulationDialog(QDialog):
    """Configure one Red Team Simulation: which scenarios (Shark / APT Red-Team),
    difficulty (recursion depth), target directory, and an OPTIONAL custom benign
    technique. The custom text is written verbatim to an INERT marker file — it is
    never executed, interpreted, or run. This is detection testing, not a payload
    runner."""

    _COMPLEXITY = {"Low (1 phase)": 1, "Medium (2 phases)": 2, "High (3 phases)": 3}

    def __init__(self, parent=None, default_target: str = "", store_path=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Run Red Team Simulation")
        self.setMinimumSize(680, 760)
        if parent:
            self.setStyleSheet(parent.styleSheet())
        self._cfg = None
        if store_path is None:
            from angerona.core.data_paths import data_dir
            store_path = data_dir() / "custom_techniques.json"
        self.store = CustomTechniqueStore(store_path)
        root = QVBoxLayout(self)
        head = QLabel("Run Red Team Simulation")
        head.setObjectName("PageTitle")
        root.addWidget(head)
        intro = QLabel("Unannounced, non-destructive adversary simulation against THIS instance. "
                       "Every technique is a benign, reversible marker — no real exploit, secret, "
                       "driver, or persistence is ever executed or touched.")
        intro.setWordWrap(True)
        intro.setStyleSheet("color:#9aa4b2;")
        root.addWidget(intro)

        root.addWidget(_section("Scenarios"))
        self.cb_shark = QCheckBox("Shark — lure drops, discovery, BYOVD driver-drop, exfil markers")
        self.cb_shark.setChecked(True)
        self.cb_apt = QCheckBox("APT Red-Team — credential-access, WMI persistence, defense-evasion markers")
        self.cb_apt.setChecked(True)
        root.addWidget(self.cb_shark)
        root.addWidget(self.cb_apt)

        root.addWidget(_section("Difficulty / depth"))
        drow = QHBoxLayout()
        drow.addWidget(QLabel("Complexity:"))
        self.complexity = QComboBox()
        self.complexity.addItems(list(self._COMPLEXITY.keys()))
        self.complexity.setCurrentText("Medium (2 phases)")
        drow.addWidget(self.complexity)
        drow.addStretch(1)
        root.addLayout(drow)
        hint = QLabel("Higher complexity runs more recursive phases (recon → escalate → persist), "
                      "each pass chaining deeper — a longer test that makes richer defense logs.")
        hint.setWordWrap(True)
        hint.setStyleSheet("color:#6b7280; font-size:11px;")
        root.addWidget(hint)

        root.addWidget(_section("Target"))
        trow = QHBoxLayout()
        trow.addWidget(QLabel("Marker directory:"))
        self.target = QLineEdit(default_target)
        trow.addWidget(self.target)
        root.addLayout(trow)
        thint = QLabel("Where benign marker files are written. A File-Integrity-Monitor-watched "
                       "path makes the test most visible; leave as-is for the default.")
        thint.setWordWrap(True)
        thint.setStyleSheet("color:#6b7280; font-size:11px;")
        root.addWidget(thint)

        root.addWidget(_section("Custom techniques — your saved library (scroll · click to edit)"))
        from PySide6.QtWidgets import QListWidget
        clib = QHBoxLayout()
        self.custom_list = QListWidget()
        self.custom_list.setMaximumHeight(120)
        self.custom_list.itemClicked.connect(self._on_custom_select)
        clib.addWidget(self.custom_list, 1)
        libbtns = QVBoxLayout()
        b_new = QPushButton("New")
        b_new.clicked.connect(self._new_custom)
        b_save = QPushButton("Save / Update")
        b_save.clicked.connect(self._save_custom)
        b_del = QPushButton("Delete")
        b_del.clicked.connect(self._delete_custom)
        for b in (b_new, b_save, b_del):
            libbtns.addWidget(b)
        libbtns.addStretch(1)
        clib.addLayout(libbtns)
        root.addLayout(clib)

        self.custom_name = QLineEdit()
        self.custom_name.setPlaceholderText("Technique name, e.g. 'my-detection-test'")
        root.addWidget(self.custom_name)
        self.custom_payload = QPlainTextEdit()
        self.custom_payload.setPlaceholderText(
            "Paste the content / pattern / snippet you want the defense tested against. "
            "It is written verbatim to an INERT marker file and NEVER executed.")
        self.custom_payload.setMaximumHeight(110)
        root.addWidget(self.custom_payload)
        cwarn = QLabel("⚠ Safety: your text is only written to a file as detection bait — Angerona "
                       "never executes, interprets, or runs it. This tests detection; it is not a "
                       "payload runner. 'Save / Update' keeps it in your library above.")
        cwarn.setWordWrap(True)
        cwarn.setStyleSheet("color:#f59e0b; font-size:11px;")
        root.addWidget(cwarn)
        self._refresh_custom_list()

        brow = QHBoxLayout()
        brow.addStretch(1)
        cancel = QPushButton("Cancel")
        cancel.clicked.connect(self.reject)
        run = QPushButton("▶  Run simulation")
        run.clicked.connect(self._on_run)
        brow.addWidget(cancel)
        brow.addWidget(run)
        root.addLayout(brow)

    # ── custom-technique library CRUD ────────────────────────────────────────
    def _refresh_custom_list(self) -> None:
        self.custom_list.clear()
        for nm in self.store.names():
            self.custom_list.addItem(nm)

    def _on_custom_select(self, item) -> None:
        rec = self.store.get(item.text())
        if rec:
            self.custom_name.setText(rec.get("name", ""))
            self.custom_payload.setPlainText(rec.get("payload", ""))

    def _new_custom(self) -> None:
        self.custom_list.clearSelection()
        self.custom_name.clear()
        self.custom_payload.clear()
        self.custom_name.setFocus()

    def _save_custom(self) -> None:
        name = self.custom_name.text().strip()
        payload = self.custom_payload.toPlainText().strip()
        if not (name and payload):
            return
        self.store.upsert(name, payload)
        self._refresh_custom_list()

    def _delete_custom(self) -> None:
        items = self.custom_list.selectedItems()
        name = items[0].text() if items else self.custom_name.text().strip()
        if name:
            self.store.delete(name)
            self._new_custom()
            self._refresh_custom_list()

    def _on_run(self) -> None:
        name = self.custom_name.text().strip()
        payload = self.custom_payload.toPlainText().strip()
        custom = {"name": name, "payload": payload} if (name and payload) else None
        self._cfg = {
            "complexity": self._COMPLEXITY.get(self.complexity.currentText(), 2),
            "run_shark": self.cb_shark.isChecked(),
            "run_redteam": self.cb_apt.isChecked(),
            "target_dir": self.target.text().strip() or None,
            "custom": custom,
        }
        self.accept()

    def result_config(self) -> dict:
        return self._cfg or {"complexity": 1, "run_shark": False, "run_redteam": False,
                             "target_dir": None, "custom": None}


# ── Modules panel ────────────────────────────────────────────────────────────
class ModulesPanel(QFrame):
    def __init__(self, manager, bus) -> None:
        super().__init__()
        self.setObjectName("Panel")
        self.manager = manager
        self.bus = bus
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 12, 14, 14)
        self._title = _ClickableSection(
            "Modules",
            "Open the expanded live status matrix for every defensive module.",
        )
        self._title.clicked.connect(self._open_overview)
        lay.addWidget(self._title)
        hint = QLabel("Click a row to inspect its v12 contract. Toggle to enable/disable.")
        hint.setStyleSheet("color:#6b7280; font-size:11px;")
        lay.addWidget(hint)

        sort_row = QHBoxLayout()
        sort_row.addWidget(QLabel("Sort by:"))
        self._sort_combo = QComboBox()
        self._sort_combo.addItems(["Name", "On/Off", "Status", "Assurance", "Category"])
        self._sort_combo.currentIndexChanged.connect(lambda *_: self._build())
        sort_row.addWidget(self._sort_combo)
        self._module_search = QLineEdit()
        self._module_search.setPlaceholderText("Search capabilities…")
        self._module_search.setClearButtonEnabled(True)
        self._module_search.textChanged.connect(lambda *_: self._build())
        sort_row.addWidget(self._module_search, 1)
        self._mode_combo = QComboBox()
        self._mode_combo.addItems(
            ["All modes", "unknown", "observe", "detect", "protect", "respond"]
        )
        self._mode_combo.currentIndexChanged.connect(lambda *_: self._build())
        sort_row.addWidget(self._mode_combo)
        sort_row.addStretch(1)
        lay.addLayout(sort_row)

        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(
            ["On", "Module", "Status", "Assurance", "Category", "Mode", "Impl."]
        )
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSortingEnabled(True)
        self.table.cellClicked.connect(self._on_click)
        lay.addWidget(self.table)
        self._built_count = -1
        self._build()

    def _sorted_items(self):
        items = list(self.manager.modules.items())
        query = self._module_search.text().strip().casefold() if hasattr(self, "_module_search") else ""
        mode_filter = self._mode_combo.currentText() if hasattr(self, "_mode_combo") else "All modes"
        if query:
            items = [
                item for item in items
                if query in " ".join(
                    (
                        item[0],
                        str(getattr(item[1], "category", "")),
                        str(_capability_summary(item[1]).get("capability_id", "")),
                    )
                ).casefold()
            ]
        if mode_filter != "All modes":
            items = [
                item for item in items
                if _capability_summary(item[1]).get("mode") == mode_filter
            ]
        mode = self._sort_combo.currentText() if hasattr(self, "_sort_combo") else "Name"
        if mode == "On/Off":
            # enabled first, then by name
            return sorted(items, key=lambda kv: (not self.manager.is_enabled(kv[0]), kv[0].lower()))
        if mode == "Status":
            return sorted(items, key=lambda kv: (getattr(kv[1], "status", ""), kv[0].lower()))
        if mode == "Assurance":
            def assurance_key(item):
                health_summary = item[1].health_summary()
                score = _module_assurance(
                    self.manager,
                    item[1],
                    _fast_assurance_operational(item[1], health_summary),
                ).score
                return (score, item[0].lower())

            return sorted(items, key=assurance_key)
        if mode == "Category":
            return sorted(items, key=lambda kv: (getattr(kv[1], "category", ""), kv[0].lower()))
        return sorted(items, key=lambda kv: kv[0].lower())

    def _build(self) -> None:
        header = self.table.horizontalHeader()
        sort_column = header.sortIndicatorSection()
        sort_order = header.sortIndicatorOrder()
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        for name, mod in self._sorted_items():
            r = self.table.rowCount()
            self.table.insertRow(r)
            chk = QCheckBox()
            chk.setChecked(self.manager.is_enabled(name))
            chk.stateChanged.connect(lambda st, n=name: self.manager.set_enabled(n, bool(st)))
            wrap = QWidget(); wlay = QHBoxLayout(wrap)
            wlay.setAlignment(Qt.AlignCenter); wlay.setContentsMargins(0, 0, 0, 0)
            wlay.addWidget(chk)
            on_item = QTableWidgetItem("On" if chk.isChecked() else "Off")
            on_item.setData(Qt.UserRole, name)
            self.table.setItem(r, 0, on_item)
            self.table.setCellWidget(r, 0, wrap)
            name_item = QTableWidgetItem(f"{_avatar(mod.category)}  {mod.name}")
            name_item.setData(Qt.UserRole, mod.name)
            self.table.setItem(r, 1, name_item)
            health_summary = mod.health_summary()
            status, health, health_state = health_summary
            status_text = f"{status} {health}%" if status == "running" else status
            status_item = QTableWidgetItem(status_text)
            status_item.setForeground(QColor(HEALTH_COLOR.get(health_state, "#e5e7eb")))
            self.table.setItem(r, 2, status_item)
            assurance = _module_assurance(
                self.manager, mod, _fast_assurance_operational(mod, health_summary)
            )
            assurance_item = _PercentTableItem(assurance.score)
            assurance_item.setForeground(QColor(_assurance_color(assurance.score)))
            assurance_item.setToolTip(_assurance_tooltip(assurance))
            self.table.setItem(r, 3, assurance_item)
            self.table.setItem(r, 4, QTableWidgetItem(mod.category))
            contract = _capability_summary(mod)
            self.table.setItem(r, 5, QTableWidgetItem(str(contract.get("mode", "legacy"))))
            self.table.setItem(
                r, 6, QTableWidgetItem(str(contract.get("implementation_version", mod.version)))
            )
        self.table.setColumnWidth(0, 36)
        self.table.setSortingEnabled(True)
        self.table.sortItems(sort_column, sort_order)
        self._built_count = len(self.manager.modules)

    def refresh(self) -> None:
        # Rebuild once discovery has populated modules (fixes the empty table).
        if self._built_count != len(self.manager.modules):
            self._build()
            return
        header = self.table.horizontalHeader()
        sort_column = header.sortIndicatorSection()
        sort_order = header.sortIndicatorOrder()
        self.table.setSortingEnabled(False)
        self.table.setUpdatesEnabled(False)
        for r in range(self.table.rowCount()):
            name_item = self.table.item(r, 1)
            if not name_item:
                continue
            mod = self.manager.modules.get(name_item.data(Qt.UserRole))
            if not mod:
                continue
            health_summary = mod.health_summary()
            status, health, health_state = health_summary
            txt = f"{status} {health}%" if status == "running" else status
            existing = self.table.item(r, 2)
            if not existing or existing.text() != txt:
                item = QTableWidgetItem(txt)
                item.setForeground(QColor(HEALTH_COLOR.get(health_state, "#e5e7eb")))
                self.table.setItem(r, 2, item)
            assurance = _module_assurance(
                self.manager, mod, _fast_assurance_operational(mod, health_summary)
            )
            current_assurance = self.table.item(r, 3)
            rendered = f"{assurance.score}%"
            if not current_assurance or current_assurance.text() != rendered:
                assurance_item = _PercentTableItem(assurance.score)
                assurance_item.setForeground(QColor(_assurance_color(assurance.score)))
                assurance_item.setToolTip(_assurance_tooltip(assurance))
                self.table.setItem(r, 3, assurance_item)
                current_assurance = assurance_item
            tooltip = _assurance_tooltip(assurance)
            if current_assurance.toolTip() != tooltip:
                current_assurance.setToolTip(tooltip)
        self.table.setUpdatesEnabled(True)
        self.table.setSortingEnabled(True)
        self.table.sortItems(sort_column, sort_order)

    def _on_click(self, row: int, col: int) -> None:
        if col == 0:                         # checkbox column — don't open inspector
            return
        name_item = self.table.item(row, 1)
        if not name_item:
            return
        mod = self.manager.modules.get(name_item.data(Qt.UserRole))
        if mod:
            if col == 3:
                try:
                    operational = mod.operational_snapshot()
                except Exception:
                    operational = {"status": "snapshot-error", "health": 0}
                assurance = _module_assurance(self.manager, mod, operational)
                _show_nonmodal_from(
                    self.table,
                    lambda: ModuleAssuranceDialog(
                        mod.name, assurance, self.window()
                    ),
                    _assurance_color(assurance.score),
                )
                return
            _show_nonmodal_from(
                self.table,
                lambda: ModuleInspector(
                    self.manager, self.bus, mod, self.window()
                ),
                "#22c55e",
            )

    def _open_overview(self) -> None:
        _show_nonmodal_from(
            self._title,
            lambda: ModulesStatusWindow(
                self.manager, self.bus, self.window()
            ),
            "#22c55e",
        )


# ── Module inspector ─────────────────────────────────────────────────────────
class ModuleHealthEvidenceDialog(QDialog):
    """Read-only explanation and exact source context for degraded health."""

    def __init__(
        self,
        module_name: str,
        evidence: object,
        parent=None,
        *,
        evidence_label: str = "Health",
    ) -> None:
        super().__init__(parent)
        label = str(evidence_label or "Evidence")[:80]
        self.setWindowTitle(f"{str(module_name)[:160]} — {label} evidence")
        self.setMinimumSize(760, 540)
        if parent:
            self.setStyleSheet(parent.styleSheet())
        layout = QVBoxLayout(self)

        record = dict(evidence) if isinstance(evidence, dict) else {}
        reason = str(record.get("reason") or "Degraded health reason is unavailable")[:1000]
        reason_label = QLabel(reason)
        reason_label.setObjectName("moduleHealthEvidenceReason")
        reason_label.setTextFormat(Qt.PlainText)
        reason_label.setWordWrap(True)
        reason_label.setStyleSheet(
            "color:#fecaca; background:#3f1016; border:1px solid #ef4444; "
            "border-radius:6px; padding:10px;"
        )
        layout.addWidget(reason_label)

        state = str(record.get("source_state") or "unavailable")[:80]
        provenance = str(record.get("source_provenance") or "unverified-callsite")[:80]
        relative = record.get("source_path")
        line = record.get("source_line")
        source_sha256 = record.get("source_sha256")
        trusted = _trusted_repository_source(relative)
        trusted_provenance = provenance in {
            "verified-loaded-implementation",
            "verified-loaded-declaration",
        }
        if (
            state == "available"
            and trusted_provenance
            and trusted is not None
        ):
            relative_text = str(relative)
            try:
                line_number = max(1, int(line))
            except (TypeError, ValueError):
                line_number = 1
            location = QLabel(
                f"Verified implementation source: {relative_text}:{line_number}"
            )
            location.setObjectName("moduleHealthEvidenceLocation")
            location.setTextFormat(Qt.PlainText)
            location.setWordWrap(True)
            location.setStyleSheet("color:#93c5fd; font-family:Consolas;")
            layout.addWidget(location)

            source_url = (
                f"{_ANGERONA_REPOSITORY_URL}/blob/main/"
                f"{quote(relative_text, safe='/')}#L{line_number}"
            )
            link = QLabel(
                f'<a href="{source_url}">Open this exact file and line on GitHub</a>'
            )
            link.setObjectName("moduleHealthEvidenceRepositoryLink")
            link.setOpenExternalLinks(True)
            link.setTextInteractionFlags(Qt.TextBrowserInteraction)
            layout.addWidget(link)
        elif state == "untrusted-external":
            unavailable = QLabel(
                "Source path withheld: this in-process callsite was not proven "
                "to be a declared function of the loaded Angerona module."
            )
            unavailable.setObjectName("moduleHealthEvidenceUnavailable")
            unavailable.setWordWrap(True)
            unavailable.setStyleSheet("color:#f59e0b;")
            layout.addWidget(unavailable)
        else:
            unavailable = QLabel(
                "Source unavailable in this packaged or source-less runtime. "
                "No local path has been invented."
            )
            unavailable.setObjectName("moduleHealthEvidenceUnavailable")
            unavailable.setWordWrap(True)
            unavailable.setStyleSheet("color:#f59e0b;")
            layout.addWidget(unavailable)

        self.source_view = QPlainTextEdit()
        self.source_view.setObjectName("moduleHealthEvidenceSource")
        self.source_view.setReadOnly(True)
        self.source_view.setFont(QFont("Consolas", 9))
        self.highlighted_source_line: int | None = None
        self.highlighted_block_index: int | None = None
        if state == "available" and trusted_provenance:
            context, block_index, error = _health_source_context(
                relative, line, source_sha256
            )
        elif state == "untrusted-external":
            context, block_index, error = (
                None,
                None,
                "Source context withheld because this callsite was not proven as "
                "loaded Angerona implementation code.",
            )
        else:
            context, block_index, error = (
                None,
                None,
                "Source context is unavailable in this packaged or source-less runtime.",
            )
        if (
            state == "available"
            and trusted_provenance
            and context is not None
            and block_index is not None
        ):
            self.source_view.setPlainText(context)
            block = self.source_view.document().findBlockByNumber(block_index)
            cursor = QTextCursor(block)
            selection = QTextEdit.ExtraSelection()
            selection.cursor = cursor
            selection.format.setBackground(QColor("#991b1b"))
            selection.format.setForeground(QColor("#fff7ed"))
            selection.format.setProperty(QTextFormat.FullWidthSelection, True)
            self.source_view.setExtraSelections([selection])
            self.source_view.setTextCursor(cursor)
            self.source_view.centerCursor()
            self.highlighted_source_line = int(line)
            self.highlighted_block_index = block_index
        else:
            self.source_view.setPlainText(error or "Source context is unavailable.")
        layout.addWidget(self.source_view, 1)

        close = QPushButton("Close")
        close.clicked.connect(self.close)
        layout.addWidget(close)


class ModuleAssuranceDialog(QDialog):
    """Explain a capability's weakest-dimension assurance and every deduction."""

    def __init__(self, module_name: str, assurance: object, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"{str(module_name)[:160]} — Capability assurance")
        self.setMinimumSize(940, 650)
        if parent:
            self.setStyleSheet(parent.styleSheet())
        layout = QVBoxLayout(self)
        if hasattr(assurance, "as_dict"):
            record = assurance.as_dict()
        elif isinstance(assurance, dict):
            record = dict(assurance)
        else:
            record = {}
        score = max(0, min(100, int(record.get("score", 0) or 0)))
        self.assurance_record = record
        self.reasons = [
            dict(item) for item in record.get("reasons", ()) if isinstance(item, dict)
        ]

        summary = QLabel(
            f"Assurance: {score}% · {record.get('interpretation', '')}"
        )
        summary.setObjectName("moduleAssuranceSummary")
        summary.setTextFormat(Qt.PlainText)
        summary.setWordWrap(True)
        summary.setStyleSheet(
            f"color:{_assurance_color(score)}; background:#111827; "
            "border:1px solid #334155; border-radius:6px; padding:10px;"
        )
        layout.addWidget(summary)

        explanation = QLabel(
            "The overall value is the lowest dimension, never an average. A high value "
            "does not prove exploit immunity; it means the listed implementation, host, "
            "runtime, continuity, and verification evidence currently has no shown deduction."
        )
        explanation.setWordWrap(True)
        explanation.setStyleSheet("color:#cbd5e1;")
        layout.addWidget(explanation)

        layout.addWidget(_section("Scored dimensions — click any row for its meaning"))
        self.dimension_table = QTableWidget(0, 4)
        self.dimension_table.setHorizontalHeaderLabels(
            ["Dimension", "Score", "State", "What was measured"]
        )
        self.dimension_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.dimension_table.verticalHeader().setVisible(False)
        self.dimension_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.dimension_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.dimension_table.setSortingEnabled(True)
        for dimension in record.get("dimensions", ()):
            if not isinstance(dimension, dict):
                continue
            row = self.dimension_table.rowCount()
            self.dimension_table.insertRow(row)
            label = QTableWidgetItem(str(dimension.get("label", "Unknown")))
            label.setData(Qt.UserRole, dict(dimension))
            self.dimension_table.setItem(row, 0, label)
            dim_score = max(0, min(100, int(dimension.get("score", 0) or 0)))
            score_item = _PercentTableItem(dim_score)
            score_item.setForeground(QColor(_assurance_color(dim_score)))
            self.dimension_table.setItem(row, 1, score_item)
            self.dimension_table.setItem(
                row, 2, QTableWidgetItem(str(dimension.get("state", "unknown")))
            )
            self.dimension_table.setItem(
                row, 3, QTableWidgetItem(str(dimension.get("explanation", "")))
            )
        self.dimension_table.cellClicked.connect(self._show_dimension)
        self.dimension_table.setFixedHeight(190)
        layout.addWidget(self.dimension_table)

        self.dimension_detail = QLabel(
            "Select a dimension to display its exact definition and current state."
        )
        self.dimension_detail.setObjectName("moduleAssuranceDimensionDetail")
        self.dimension_detail.setTextFormat(Qt.PlainText)
        self.dimension_detail.setWordWrap(True)
        self.dimension_detail.setStyleSheet(
            "color:#bfdbfe; background:#0f172a; border:1px solid #1e3a8a; padding:8px;"
        )
        layout.addWidget(self.dimension_detail)

        layout.addWidget(
            _section("Every deduction — click a row for exact path, line, and red source context")
        )
        self.reason_table = QTableWidget(0, 4)
        self.reason_table.setHorizontalHeaderLabels(
            ["Dimension", "Score", "Why less than 100%", "Source"]
        )
        self.reason_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.reason_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.reason_table.verticalHeader().setVisible(False)
        self.reason_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.reason_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.reason_table.setSortingEnabled(True)
        for reason in self.reasons:
            row = self.reason_table.rowCount()
            self.reason_table.insertRow(row)
            dimension_item = QTableWidgetItem(str(reason.get("dimension", "unknown")))
            dimension_item.setData(Qt.UserRole, reason)
            self.reason_table.setItem(row, 0, dimension_item)
            reason_score = max(
                0, min(100, int(reason.get("dimension_score", score) or 0))
            )
            score_item = _PercentTableItem(reason_score)
            score_item.setForeground(QColor(_assurance_color(reason_score)))
            self.reason_table.setItem(row, 1, score_item)
            why = QTableWidgetItem(str(reason.get("reason", "Reason unavailable")))
            why.setToolTip(str(reason.get("remediation", "")))
            self.reason_table.setItem(row, 2, why)
            path = reason.get("source_path")
            line = reason.get("source_line")
            source = f"{path}:{line}" if path and line else "source unavailable"
            self.reason_table.setItem(row, 3, QTableWidgetItem(source))
        if not self.reasons:
            self.reason_table.insertRow(0)
            none = QTableWidgetItem("No deductions")
            none.setData(Qt.UserRole, None)
            self.reason_table.setItem(0, 0, none)
            self.reason_table.setItem(0, 2, QTableWidgetItem(
                "All five presently observed assurance dimensions score 100%."
            ))
        self.reason_table.cellClicked.connect(self._open_reason)
        layout.addWidget(self.reason_table, 1)

        close = QPushButton("Close")
        close.clicked.connect(self.close)
        layout.addWidget(close)

    def _show_dimension(self, row: int, _column: int) -> None:
        item = self.dimension_table.item(row, 0)
        dimension = item.data(Qt.UserRole) if item is not None else None
        if not isinstance(dimension, dict):
            return
        self.dimension_detail.setText(
            f"{dimension.get('label', 'Dimension')} · "
            f"{dimension.get('score', 0)}% · {dimension.get('state', 'unknown')}\n"
            f"{dimension.get('explanation', '')}"
        )

    def _open_reason(self, row: int, _column: int) -> None:
        item = self.reason_table.item(row, 0)
        reason = item.data(Qt.UserRole) if item is not None else None
        if not isinstance(reason, dict):
            self.dimension_detail.setText(
                "No assurance deduction exists to open for this capability."
            )
            return
        _show_nonmodal_from(
            self.reason_table,
            lambda: ModuleHealthEvidenceDialog(
                self.windowTitle().split(" — ", 1)[0],
                reason,
                self.window(),
                evidence_label="Assurance",
            ),
            "#ef4444",
        )


class ModuleInspector(QDialog):
    _test_done = Signal(str)

    def __init__(self, manager, bus, module, parent=None) -> None:
        super().__init__(parent)
        self.manager, self.bus, self.module = manager, bus, module
        self._accept_async_results = True
        self._test_worker: threading.Thread | None = None
        self._cached_bus_revision: int | None = None
        self._cached_bus_events: list = []
        self._feed_fingerprint: tuple | None = None
        self._history_fingerprint: tuple | None = None
        self._health_evidence_fingerprint: tuple | None = None
        self._assurance_fingerprint: tuple | None = None
        self._current_assurance = None
        self.setWindowTitle(f"Module — {module.name}")
        self.setMinimumSize(660, 560)
        if parent:
            self.setStyleSheet(parent.styleSheet())
        root = QVBoxLayout(self)

        root.addWidget(FuturisticHeader(
            f"{module.name} · Module Inspector",
            f"{module.category} · v{module.version} · live controls, events, health, and dependencies",
            HEALTH_COLOR.get(module.health_state, "#38bdf8"),
            self,
        ))

        tabs = QTabWidget()
        tabs.addTab(self._overview_tab(),  "Overview")
        tabs.addTab(self._assurance_tab(), "Assurance")
        tabs.addTab(self._contract_tab(),  "Contract v12")
        tabs.addTab(self._perf_tab(),      "⚡ Performance")
        tabs.addTab(self._history_tab(),   "📋 History")
        tabs.addTab(self._deps_tab(),      "🔗 Dependencies")
        if self._is_ai():
            tabs.addTab(self._api_keys_tab(), "API Keys")
            tabs.addTab(self._help_tab(), "Help")
        from angerona.gui.context_info import (
            attach_context_info,
            module_info_topic,
        )
        self._context_info = attach_context_info(
            tabs,
            "module",
            resolver=lambda label: module_info_topic(self.module, label),
        )
        root.addWidget(tabs)
        self._test_done.connect(self._apply_test_result)

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh)
        self._timer.start(2000)   # 2 s is sufficient; 1 s was unnecessary CPU churn
        self._refresh()

    def _is_ai(self) -> bool:
        m = self.module
        return m.category == "AI" or "AI" in m.name or "Cloud" in m.name

    # ── Tabs ─────────────────────────────────────────────────────────────────
    def _overview_tab(self) -> QWidget:
        w = QWidget(); lay = QVBoxLayout(w)
        desc = QLabel(str(self.module.description)[:4096]); desc.setWordWrap(True)
        desc.setTextFormat(Qt.PlainText)
        desc.setStyleSheet("color:#cbd5e1;"); lay.addWidget(desc)
        self.status_lbl = QLabel(""); self.status_lbl.setTextFormat(Qt.PlainText)
        lay.addWidget(self.status_lbl)
        self.health_evidence_btn = QPushButton("")
        self.health_evidence_btn.setObjectName("ModuleHealthEvidenceButton")
        self.health_evidence_btn.setToolTip(
            "Open the exact reason, trusted local source path, and highlighted callsite."
        )
        self.health_evidence_btn.clicked.connect(self._open_health_evidence)
        self.health_evidence_btn.hide()
        lay.addWidget(self.health_evidence_btn)
        self.assurance_btn = QPushButton("Inspect capability assurance…")
        self.assurance_btn.setObjectName("ModuleAssuranceButton")
        self.assurance_btn.setToolTip(
            "Explain every scored dimension and open exact red-highlighted source evidence."
        )
        self.assurance_btn.clicked.connect(self._open_assurance)
        lay.addWidget(self.assurance_btn)
        self.error_lbl = QLabel(""); self.error_lbl.setWordWrap(True)
        self.error_lbl.setTextFormat(Qt.PlainText)
        self.error_lbl.setStyleSheet("color:#ef4444;"); lay.addWidget(self.error_lbl)
        controls = QHBoxLayout()
        self.toggle_btn = QPushButton(); self.toggle_btn.clicked.connect(self._toggle)
        restart = QPushButton("Restart module"); restart.clicked.connect(self._restart)
        self.selftest_btn = QPushButton("Run self-test")
        self.selftest_btn.clicked.connect(self._selftest)
        controls.addWidget(self.toggle_btn); controls.addWidget(restart)
        controls.addWidget(self.selftest_btn)
        if _source_editing_allowed():
            edit_btn = QPushButton("Open source sandbox")
            edit_btn.setToolTip("Development mode only: stage and test source changes in isolation.")
            edit_btn.clicked.connect(self._open_in_sandbox)
            controls.addWidget(edit_btn)
        controls.addStretch(1)
        lay.addLayout(controls)
        if not _source_editing_allowed():
            protected = QLabel(
                "Protected runtime: live source editing is disabled. Install only reviewed, "
                "signed, staged capability packages."
            )
            protected.setWordWrap(True)
            protected.setStyleSheet("color:#f59e0b; font-size:11px;")
            lay.addWidget(protected)
        self.test_lbl = QLabel(""); self.test_lbl.setWordWrap(True)
        self.test_lbl.setTextFormat(Qt.PlainText); lay.addWidget(self.test_lbl)
        lay.addWidget(_section("This module's recent events  —  click a row for full detail + actions"))
        self.feed = QTableWidget(0, 3)
        self.feed.setHorizontalHeaderLabels(["Time", "Severity", "Message"])
        self.feed.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.feed.verticalHeader().setVisible(False)
        self.feed.setEditTriggers(QTableWidget.NoEditTriggers)
        self.feed.setSelectionBehavior(QTableWidget.SelectRows)
        self.feed.setSortingEnabled(True)
        self.feed.cellClicked.connect(self._on_feed_click)
        lay.addWidget(self.feed)
        return w

    def _assurance_tab(self) -> QWidget:
        """Weakest-dimension score with every line item drillable."""
        w = QWidget(); lay = QVBoxLayout(w)
        lay.addWidget(_section("Capability Assurance Ledger v1"))
        self._assurance_summary = QLabel("")
        self._assurance_summary.setTextFormat(Qt.PlainText)
        self._assurance_summary.setWordWrap(True)
        lay.addWidget(self._assurance_summary)
        caveat = QLabel(
            "This is implementation/runtime assurance, not attack coverage or a guarantee. "
            "The lowest dimension is the score so strong metadata cannot hide a stopped "
            "sensor, evidence loss, or shallow verification."
        )
        caveat.setWordWrap(True)
        caveat.setStyleSheet("color:#94a3b8;")
        lay.addWidget(caveat)
        self._assurance_dimensions = QTableWidget(0, 4)
        self._assurance_dimensions.setHorizontalHeaderLabels(
            ["Dimension", "Score", "State", "Explanation"]
        )
        self._assurance_dimensions.horizontalHeader().setSectionResizeMode(
            3, QHeaderView.Stretch
        )
        self._assurance_dimensions.verticalHeader().setVisible(False)
        self._assurance_dimensions.setEditTriggers(QTableWidget.NoEditTriggers)
        self._assurance_dimensions.setSelectionBehavior(QTableWidget.SelectRows)
        self._assurance_dimensions.setSortingEnabled(True)
        self._assurance_dimensions.cellClicked.connect(
            lambda _row, _column: self._open_assurance()
        )
        lay.addWidget(self._assurance_dimensions, 1)
        self._assurance_open_btn = QPushButton(
            "Open every deduction, file path, GitHub line, and red source highlight"
        )
        self._assurance_open_btn.clicked.connect(self._open_assurance)
        lay.addWidget(self._assurance_open_btn)
        return w

    def _contract_tab(self) -> QWidget:
        """Machine-readable declaration plus live loss/freshness state."""
        w = QWidget(); lay = QVBoxLayout(w)
        lay.addWidget(_section("Capability Contract v12"))
        self._contract_summary = QLabel("")
        self._contract_summary.setWordWrap(True)
        self._contract_summary.setTextFormat(Qt.PlainText)
        lay.addWidget(self._contract_summary)
        self._contract_body = QPlainTextEdit()
        self._contract_body.setReadOnly(True)
        self._contract_body.setFont(QFont("Consolas", 9))
        contract = _capability_contract(self.module)
        self._contract_body.setPlainText(json.dumps(contract, indent=2, sort_keys=True))
        lay.addWidget(self._contract_body, 1)
        copy_btn = QPushButton("Copy contract JSON")
        copy_btn.clicked.connect(
            lambda: QGuiApplication.clipboard().setText(self._contract_body.toPlainText())
        )
        lay.addWidget(copy_btn)
        return w

    # ── Extra tabs ────────────────────────────────────────────────────────────

    def _perf_tab(self) -> QWidget:
        """Real-time performance metrics: throttle, event rates, health trend."""
        w = QWidget(); lay = QVBoxLayout(w)
        lay.addWidget(_section("Module performance (auto-refreshes every 2 s)"))

        grid = QGridLayout(); grid.setColumnStretch(1, 1)
        self._p_throttle = QLabel("—")
        self._p_rate5    = QLabel("—")
        self._p_rate60   = QLabel("—")
        self._p_health   = QLabel("—")
        self._p_thread   = QLabel("—")
        for i, (lbl, val) in enumerate([
            ("Throttle multiplier:", self._p_throttle),
            ("Events (last 5 min):", self._p_rate5),
            ("Events (last 60 min):", self._p_rate60),
            ("Health %:", self._p_health),
            ("Thread status:", self._p_thread),
        ]):
            grid.addWidget(QLabel(lbl), i, 0)
            grid.addWidget(val, i, 1)
        lay.addLayout(grid)

        lay.addWidget(_section("Health trend (last 20 readings)"))
        self._p_trend = QPlainTextEdit()
        self._p_trend.setReadOnly(True)
        self._p_trend.setFixedHeight(80)
        self._p_trend.setFont(QFont("Consolas", 9))
        lay.addWidget(self._p_trend)
        self._health_trend: list[int] = []

        lay.addStretch()
        return w

    def _history_tab(self) -> QWidget:
        """Full scrollable event log for this module (all severities)."""
        w = QWidget(); lay = QVBoxLayout(w)
        lay.addWidget(_section("All events from this module (most recent first)"))

        filt_row = QHBoxLayout()
        filt_row.addWidget(QLabel("Filter:"))
        self._hist_filter = QLineEdit()
        self._hist_filter.setPlaceholderText("keyword (Enter to apply)")
        self._hist_filter.returnPressed.connect(self._refresh_history)
        filt_row.addWidget(self._hist_filter, 1)
        lay.addLayout(filt_row)

        self._hist_table = QTableWidget(0, 3)
        self._hist_table.setHorizontalHeaderLabels(["Time", "Severity", "Message"])
        self._hist_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self._hist_table.verticalHeader().setVisible(False)
        self._hist_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._hist_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._hist_table.setSortingEnabled(True)
        self._hist_table.cellClicked.connect(
            lambda r, _: _show_nonmodal_from(
                self._hist_table,
                lambda: AlertDetailDialog(
                    self._hist_table.item(r, 0).data(Qt.UserRole), self.window()
                ),
                "#38bdf8",
            )
            if self._hist_table.item(r, 0)
            and self._hist_table.item(r, 0).data(Qt.UserRole)
            else None
        )
        lay.addWidget(self._hist_table)
        return w

    def _refresh_history(self, snapshot: list | None = None) -> None:
        kw = self._hist_filter.text().lower()
        source = self.bus.recent(1000) if snapshot is None else snapshot
        events = [e for e in source if e.module == self.module.name]
        if kw:
            events = [e for e in events if kw in e.message.lower()]
        fingerprint = (kw,) + tuple(
            (
                id(event),
                float(getattr(event, "ts", 0.0)),
                int(getattr(event, "severity", Severity.INFO)),
                str(getattr(event, "message", "")),
            )
            for event in events
        )
        if fingerprint == self._history_fingerprint:
            return
        self._history_fingerprint = fingerprint
        header = self._hist_table.horizontalHeader()
        sort_column = header.sortIndicatorSection()
        sort_order = header.sortIndicatorOrder()
        self._hist_table.setSortingEnabled(False)
        self._hist_table.setRowCount(0)
        for e in events:
            r = self._hist_table.rowCount(); self._hist_table.insertRow(r)
            ts_item = QTableWidgetItem(e.time_str)
            ts_item.setData(Qt.UserRole, e)
            self._hist_table.setItem(r, 0, ts_item)
            self._hist_table.setItem(r, 1, _sev_item(e.severity))
            self._hist_table.setItem(r, 2, QTableWidgetItem(e.message))
        self._hist_table.setSortingEnabled(True)
        self._hist_table.sortItems(sort_column, sort_order)

    def _deps_tab(self) -> QWidget:
        """Source file path, Python imports, and config fields used."""
        w = QWidget(); lay = QVBoxLayout(w)
        lay.addWidget(_section("Module source"))

        src_path = self._find_module_src()
        source_label = _repository_relative_source(src_path)
        path_lbl = QLabel(source_label or "(trusted source file not found)")
        path_lbl.setStyleSheet("color:#93c5fd; font-family:Consolas;")
        path_lbl.setWordWrap(True)
        lay.addWidget(path_lbl)

        if src_path and _source_editing_allowed():
            open_btn = QPushButton("Open source sandbox")
            open_btn.clicked.connect(self._open_in_sandbox)
            lay.addWidget(open_btn)

        lay.addWidget(_section("Imports & dependencies"))
        deps_box = QPlainTextEdit()
        deps_box.setReadOnly(True)
        deps_box.setFont(QFont("Consolas", 9))
        deps_box.setPlainText(self._parse_imports(src_path))
        lay.addWidget(deps_box, 1)

        lay.addWidget(_section("Module metadata"))
        meta_box = QPlainTextEdit()
        meta_box.setReadOnly(True)
        meta_box.setFont(QFont("Consolas", 9))
        m = self.module
        meta_lines = [
            f"name          = {m.name}",
            f"category      = {m.category}",
            f"version       = {m.version}",
            f"enabled_by_default = {getattr(m, 'enabled_by_default', '?')}",
            f"MITRE_tags    = {getattr(m, 'mitre_tags', '(none)')}",
            f"description   = {m.description}",
        ]
        meta_box.setPlainText("\n".join(meta_lines))
        meta_box.setFixedHeight(110)
        lay.addWidget(meta_box)
        return w

    def _find_module_src(self) -> str:
        """Locate only a trusted, bounded-checkout source for this module."""
        try:
            import inspect
            candidate = inspect.getfile(type(self.module))
            relative = _repository_relative_source(candidate)
            trusted = _trusted_repository_source(relative)
            return str(trusted) if trusted is not None else ""
        except Exception:
            return ""

    def _parse_imports(self, src_path: str) -> str:
        if not src_path:
            return "(source unavailable)"
        try:
            import ast as _ast
            relative = _repository_relative_source(src_path)
            src, error = _read_trusted_source(relative)
            if src is None:
                return f"(source unavailable: {error})"
            tree = _ast.parse(src)
            lines = []
            for node in _ast.walk(tree):
                if isinstance(node, _ast.Import):
                    for alias in node.names:
                        lines.append(f"import {alias.name}")
                elif isinstance(node, _ast.ImportFrom):
                    names = ", ".join(a.name for a in node.names)
                    lines.append(f"from {node.module or ''} import {names}")
            # De-dup, sort, highlight angerona-internal deps
            seen, out = set(), []
            for ln in sorted(set(lines)):
                if ln not in seen:
                    seen.add(ln)
                    prefix = "  [internal] " if "angerona" in ln else "  "
                    out.append(prefix + ln)
            return "\n".join(out) or "(no imports found)"
        except Exception as exc:
            return f"(parse error: {exc})"

    def _on_feed_click(self, row: int, _col: int) -> None:
        item = self.feed.item(row, 0)
        if item is None:
            return
        event = item.data(Qt.UserRole)
        if event is not None:
            # Module alerts now open the SAME detail window (with Allow/Block/
            # Analyze/Research) as the main Live Alerts feed.
            _show_nonmodal_from(
                self.feed,
                lambda: AlertDetailDialog(event, self.window()),
                _sev_color(event.severity),
            )

    def _api_keys_tab(self) -> QWidget:
        w = QWidget(); lay = QVBoxLayout(w)
        info = QLabel(
            "Provider credentials are managed only in Settings ▸ API Keys. "
            "This read-only view never reveals or duplicates a secret."
        )
        info.setWordWrap(True); lay.addWidget(info)
        from angerona.core.provider_credentials import (
            PROVIDER_CREDENTIALS,
            credential_values,
        )

        for provider in PROVIDER_CREDENTIALS:
            configured = bool(credential_values(provider.provider_id))
            status = QLabel(
                f"{'✓' if configured else '○'}  {provider.label}: "
                f"{'configured' if configured else 'not configured'}"
            )
            status.setStyleSheet(
                "color:#22c55e;" if configured else "color:#94a3b8;"
            )
            lay.addWidget(status)
        open_settings = QPushButton("Open Settings ▸ API Keys")
        open_settings.setObjectName("Primary")
        open_settings.clicked.connect(self._open_api_key_settings)
        lay.addWidget(open_settings)
        lay.addStretch(1)
        return w

    def _open_api_key_settings(self) -> None:
        owner = self.parentWidget()
        while owner is not None:
            show_settings = getattr(owner, "_show_settings", None)
            if callable(show_settings):
                self.close()
                show_settings("API Keys")
                return
            owner = owner.parentWidget()
        QMessageBox.information(
            self,
            "Open API Keys",
            "Open the main Angerona window, then choose Settings ▸ API Keys.",
        )

    def _help_tab(self) -> QWidget:
        w = QWidget(); lay = QVBoxLayout(w)
        intro = QLabel(HELP_TEXT_SHORT); intro.setWordWrap(True)
        intro.setStyleSheet("color:#cbd5e1;"); lay.addWidget(intro)
        btn = QPushButton("Open full instructions"); btn.setObjectName("Primary")
        btn.clicked.connect(self._open_help); lay.addWidget(btn)
        lay.addStretch(1)
        return w

    def _open_help(self) -> None:
        dlg = QDialog(self); dlg.setWindowTitle("Angerona — API Key Setup Help")
        dlg.setMinimumSize(580, 540); dlg.setStyleSheet(self.styleSheet())
        l = QVBoxLayout(dlg)
        body = QPlainTextEdit(); body.setReadOnly(True); body.setPlainText(HELP_TEXT_FULL)
        body.setFont(QFont("Consolas", 10)); l.addWidget(body)
        close = QPushButton("Close"); close.setObjectName("Primary")
        close.clicked.connect(dlg.close); l.addWidget(close)
        dlg.exec()

    def _enabled(self) -> bool:
        return self.manager.is_enabled(self.module.name)

    def _toggle(self) -> None:
        self.manager.set_enabled(self.module.name, not self._enabled())
        self._refresh()

    def _restart(self) -> None:
        self.module.stop()
        self.module.start()
        self._refresh()

    def _open_in_sandbox(self) -> None:
        if not _source_editing_allowed():
            QMessageBox.warning(
                self,
                "Protected runtime",
                "Source editing is available only in explicit unprivileged development mode.",
            )
            return
        try:
            from angerona.gui.sandbox_editor import launch_sandbox_editor
            # Auto-open THIS module's .py so the operator lands straight on its code.
            self._sandbox = launch_sandbox_editor(
                self.manager, self.bus, parent=self.window(),
                preselect=getattr(self.module, "name", None))
        except Exception as exc:
            QMessageBox.warning(self, "Sandbox", f"Could not open the sandbox: {exc}")

    def _current_health_evidence(
        self, operational: dict[str, object] | None = None,
    ) -> dict[str, object] | None:
        """Return evidence derived only from one operational snapshot."""
        if operational is None:
            try:
                operational = self.module.operational_snapshot()
            except Exception:
                operational = {
                    "health": 0,
                    "health_note": "Module operational snapshot is unavailable.",
                    "health_evidence": None,
                }
        try:
            health = max(0, min(100, int(operational.get("health", 0))))
        except (TypeError, ValueError):
            health = 0
        if health >= 100:
            return None
        evidence = operational.get("health_evidence")
        if isinstance(evidence, dict):
            return dict(evidence)
        reason = str(operational.get("health_note") or "").strip()[:1000]
        if not reason:
            reason = f"Module reported {health}% health without a diagnostic reason."
        return {
            "reason": reason,
            "source_state": "unavailable",
            "source_path": None,
            "source_line": None,
            "source_sha256": None,
            "source_provenance": "unavailable",
        }

    def _open_health_evidence(self) -> None:
        evidence = self._current_health_evidence()
        if evidence is None:
            return
        _show_nonmodal_from(
            self.health_evidence_btn,
            lambda: ModuleHealthEvidenceDialog(
                self.module.name, evidence, self.window()
            ),
            "#ef4444",
        )

    def _open_assurance(self) -> None:
        assurance = self._current_assurance
        if assurance is None:
            try:
                operational = self.module.operational_snapshot()
            except Exception:
                operational = {
                    "status": "snapshot-error",
                    "health": 0,
                    "health_note": "Module operational snapshot is unavailable.",
                }
            assurance = _module_assurance(self.manager, self.module, operational)
        _show_nonmodal_from(
            self.assurance_btn,
            lambda: ModuleAssuranceDialog(
                self.module.name, assurance, self.window()
            ),
            _assurance_color(assurance.score),
        )

    def _refresh_assurance(self, operational: dict[str, object]) -> None:
        assurance = _module_assurance(self.manager, self.module, operational)
        fingerprint = (
            assurance.score,
            tuple(
                (item.dimension, item.score, item.state, item.explanation)
                for item in assurance.dimensions
            ),
            tuple(
                (
                    item.code,
                    item.dimension_score,
                    item.reason,
                    item.source_path,
                    item.source_line,
                    item.source_sha256,
                )
                for item in assurance.reasons
            ),
        )
        self._current_assurance = assurance
        if fingerprint == self._assurance_fingerprint:
            return
        self._assurance_fingerprint = fingerprint
        color = _assurance_color(assurance.score)
        reason_count = len(assurance.reasons)
        self.assurance_btn.setText(
            f"Assurance {assurance.score}% — inspect {reason_count} "
            f"deduction{'s' if reason_count != 1 else ''}, paths, and lines"
        )
        self.assurance_btn.setStyleSheet(f"color:{color};")
        self.assurance_btn.setToolTip(_assurance_tooltip(assurance))
        self._assurance_summary.setText(
            f"{assurance.score}% · {reason_count} current deduction"
            f"{'s' if reason_count != 1 else ''}\n{assurance.interpretation}"
        )
        self._assurance_summary.setStyleSheet(f"color:{color};")
        header = self._assurance_dimensions.horizontalHeader()
        sort_column = header.sortIndicatorSection()
        sort_order = header.sortIndicatorOrder()
        self._assurance_dimensions.setSortingEnabled(False)
        self._assurance_dimensions.setRowCount(0)
        for dimension in assurance.dimensions:
            row = self._assurance_dimensions.rowCount()
            self._assurance_dimensions.insertRow(row)
            label = QTableWidgetItem(dimension.label)
            label.setToolTip("Click to open all evidence for this assurance score.")
            self._assurance_dimensions.setItem(row, 0, label)
            score_item = _PercentTableItem(dimension.score)
            score_item.setForeground(QColor(_assurance_color(dimension.score)))
            self._assurance_dimensions.setItem(row, 1, score_item)
            self._assurance_dimensions.setItem(
                row, 2, QTableWidgetItem(dimension.state)
            )
            explanation = QTableWidgetItem(dimension.explanation)
            explanation.setToolTip(dimension.explanation)
            self._assurance_dimensions.setItem(row, 3, explanation)
        self._assurance_dimensions.setSortingEnabled(True)
        self._assurance_dimensions.sortItems(sort_column, sort_order)

    def _selftest(self) -> None:
        if self._test_worker is not None and self._test_worker.is_alive():
            self.test_lbl.setText("A self-test is already running for this capability.")
            return
        lock = getattr(self.module, "_angerona_selftest_lock", None)
        if lock is None:
            lock = threading.Lock()
            setattr(self.module, "_angerona_selftest_lock", lock)
        if not lock.acquire(blocking=False):
            self.test_lbl.setText("A self-test is already running for this capability.")
            return
        self._active_test_lock = lock
        self.test_lbl.setText("Testing…")
        self.selftest_btn.setEnabled(False)
        self._test_worker = threading.Thread(
            target=self._run_test,
            name=f"ModuleSelfTest-{self.module.name}",
            daemon=True,
        )
        self._test_worker.start()

    def _run_test(self) -> None:
        try:
            ok, detail = self.module.self_test()
            _emit_if_accepting(
                self,
                "_test_done",
                f"{'PASS' if ok else 'FAIL'} — {str(detail)[:4000]}",
            )
        except Exception as exc:
            _emit_if_accepting(
                self,
                "_test_done",
                f"FAIL — {str(exc)[:4000]}",
            )
        finally:
            lock = getattr(self, "_active_test_lock", None)
            if lock is not None:
                try:
                    lock.release()
                except RuntimeError:
                    pass
                self._active_test_lock = None

    def _apply_test_result(self, message: str) -> None:
        if self._accept_async_results:
            self.test_lbl.setText(message)
            self.selftest_btn.setEnabled(True)

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt signature
        self._accept_async_results = False
        self._timer.stop()
        super().closeEvent(event)

    def _refresh(self) -> None:
        try:
            operational = self.module.operational_snapshot()
        except Exception:
            operational = {
                "status": "snapshot-error",
                "health": 0,
                "health_state": "failed",
                "health_note": "Module operational snapshot is unavailable.",
                "health_evidence": None,
            }
        health_state = str(operational.get("health_state", "failed"))
        try:
            health_value = max(0, min(100, int(operational.get("health", 0))))
        except (TypeError, ValueError):
            health_value = 0
        health_note = str(operational.get("health_note") or "")[:1000]
        status = str(operational.get("status", "snapshot-error"))[:80]
        color = HEALTH_COLOR.get(health_state, "#e5e7eb")
        note = f" · {health_note}" if health_note else ""
        self.status_lbl.setText(
            f"Status: {status} · "
            f"health {health_value}% · "
            f"{'enabled' if self._enabled() else 'disabled'}" + note)
        self.status_lbl.setStyleSheet(f"color:{color};")
        evidence = self._current_health_evidence(operational)
        evidence_fingerprint = (
            health_value,
            str(evidence.get("reason") or "") if evidence is not None else "",
            evidence.get("source_state") if evidence is not None else None,
            evidence.get("source_path") if evidence is not None else None,
            evidence.get("source_line") if evidence is not None else None,
            evidence.get("source_sha256") if evidence is not None else None,
            evidence.get("source_provenance") if evidence is not None else None,
        ) if evidence is not None else None
        if evidence_fingerprint != self._health_evidence_fingerprint:
            self._health_evidence_fingerprint = evidence_fingerprint
            if evidence is None:
                self.health_evidence_btn.hide()
            else:
                reason = str(evidence.get("reason") or "Degraded health")[:240]
                source_path = evidence.get("source_path")
                source_line = evidence.get("source_line")
                location = (
                    f" · {source_path}:{source_line}"
                    if source_path and source_line
                    else " · source unavailable"
                )
                self.health_evidence_btn.setText(
                    f"Why health is {health_value}%: {reason}{location}"
                )
                self.health_evidence_btn.show()
        self._refresh_assurance(operational)
        self.error_lbl.setText(
            f"Last error: {str(self.module.last_error)[:2000]}"
            if self.module.last_error else ""
        )
        self.toggle_btn.setText("Disable" if self._enabled() else "Enable")
        try:
            contract = _capability_summary(self.module)
            gaps = contract.get("metadata_gaps", [])
            cycle_age = operational.get("last_cycle_age_seconds")
            cycle_text = "not yet sampled" if cycle_age is None else f"{float(cycle_age):.1f}s"
            self._contract_summary.setText(
                f"{contract.get('capability_id', self.module.name)} · "
                f"{contract.get('mode', '?')} · {contract.get('maturity', '?')} · "
                f"authority {contract.get('response_authority', 'none')} · "
                f"loss count {operational.get('event_overflow_count', 0)} · "
                f"cycle age {cycle_text}\n"
                f"Metadata: {contract.get('metadata_level', 'unavailable')}"
                + (f" · migration gaps: {', '.join(gaps)}" if gaps else " · complete")
            )
        except Exception:
            pass

        # One coherent ring snapshot serves both the event feed and performance
        # counters. The revision is sampled before copying: a concurrent event
        # can cause one harmless extra refresh, but cannot be cached under a
        # newer revision and then missed indefinitely.
        revision_reader = getattr(self.bus, "revision", None)
        try:
            observed_revision = (
                int(revision_reader()) if callable(revision_reader) else None
            )
        except Exception:
            observed_revision = None
        if (
            observed_revision is None
            or observed_revision != self._cached_bus_revision
        ):
            all_ev = self.bus.recent(1000)
            self._cached_bus_events = list(all_ev)
            self._cached_bus_revision = observed_revision
        else:
            all_ev = self._cached_bus_events

        events = [
            event
            for event in all_ev[:300]
            if getattr(event, "module", "") == self.module.name
        ][:80]
        feed_fingerprint = tuple(
            (
                id(event),
                float(getattr(event, "ts", 0.0)),
                int(getattr(event, "severity", Severity.INFO)),
                str(getattr(event, "message", "")),
            )
            for event in events
        )
        if feed_fingerprint != self._feed_fingerprint:
            self._feed_fingerprint = feed_fingerprint
            header = self.feed.horizontalHeader()
            sort_column = header.sortIndicatorSection()
            sort_order = header.sortIndicatorOrder()
            self.feed.setUpdatesEnabled(False)
            self.feed.setSortingEnabled(False)
            self.feed.setRowCount(0)
            for event in events:
                row = self.feed.rowCount()
                self.feed.insertRow(row)
                ts_item = QTableWidgetItem(event.time_str)
                ts_item.setData(Qt.UserRole, event)  # click opens exact event detail
                self.feed.setItem(row, 0, ts_item)
                self.feed.setItem(row, 1, _sev_item(event.severity))
                self.feed.setItem(row, 2, QTableWidgetItem(event.message))
            self.feed.setSortingEnabled(True)
            self.feed.sortItems(sort_column, sort_order)
            self.feed.setUpdatesEnabled(True)

        # ── Performance tab refresh ──────────────────────────────────────
        try:
            now = time.time()
            mod_ev = [e for e in all_ev if e.module == self.module.name]
            rate5  = sum(1 for e in mod_ev if now - e.ts < 300)
            rate60 = sum(1 for e in mod_ev if now - e.ts < 3600)
            throttle = getattr(self.module, "_throttle", 1.0)
            health   = self.module.health
            is_live  = getattr(self.module, "_thread", None)
            thread_s = "alive" if (is_live and is_live.is_alive()) else "stopped"
            self._p_throttle.setText(f"{throttle:.1f}×"
                                     f"{'  (eco-throttled)' if throttle > 1 else ''}")
            self._p_rate5.setText(str(rate5))
            self._p_rate60.setText(str(rate60))
            hcolor = "#22c55e" if health >= 70 else "#f59e0b" if health >= 40 else "#ef4444"
            self._p_health.setStyleSheet(f"color:{hcolor};")
            self._p_health.setText(f"{health}%")
            self._p_thread.setText(thread_s)
            self._health_trend.append(health)
            if len(self._health_trend) > 20:
                self._health_trend = self._health_trend[-20:]
            bar = "".join(
                "█" if h >= 80 else "▇" if h >= 60 else "▄" if h >= 40 else "▂"
                for h in self._health_trend
            )
            self._p_trend.setPlainText(
                f"[{bar}]\n"
                f"min={min(self._health_trend)}%  max={max(self._health_trend)}%  "
                f"avg={sum(self._health_trend)//len(self._health_trend)}%"
            )
        except Exception:
            pass

        # ── History tab refresh (light — only if tab visible) ────────────
        try:
            self._refresh_history(all_ev)
        except Exception:
            pass


# ── Alerts panel ─────────────────────────────────────────────────────────────

class _TimestampItem(QTableWidgetItem):
    """Sorts by raw float timestamp so midnight-spanning rows stay correct."""
    def __init__(self, ts: float) -> None:
        super().__init__(time.strftime("%H:%M:%S", time.localtime(ts)))
        self._ts = ts

    def __lt__(self, other: "QTableWidgetItem") -> bool:
        if isinstance(other, _TimestampItem):
            return self._ts < other._ts
        return super().__lt__(other)


class _SeverityItem(QTableWidgetItem):
    """Sorts by Severity int order (INFO < LOW < MEDIUM < HIGH < CRITICAL)."""
    def __init__(self, sev: Severity) -> None:
        super().__init__(sev.label)
        self.setForeground(QColor(SEVERITY_COLOR.get(sev, "#e5e7eb")))
        self._order = int(sev)

    def __lt__(self, other: "QTableWidgetItem") -> bool:
        if isinstance(other, _SeverityItem):
            return self._order < other._order
        return super().__lt__(other)


def _restore_alert_scroll(table: QTableWidget, sort_col: int, sort_ord,
                          previous_value: int, has_new_events: bool) -> None:
    """Keep the live feed's viewport deterministic after row insertion/sort.

    QTableWidget adjusts its scrollbar while rows are prepended and can leave the
    viewport at the oldest row after sorting is re-enabled.  In the default
    newest-first view, a new event must remain visible at row zero.  For an
    operator-selected custom sort, retain their prior scroll position instead.
    """
    bar = table.verticalScrollBar()
    if has_new_events and sort_col == 0 and sort_ord == Qt.DescendingOrder:
        bar.setValue(bar.minimum())
        return
    bar.setValue(max(bar.minimum(), min(previous_value, bar.maximum())))


def _event_evidence_context(event) -> dict[str, str]:
    """Return operator-readable evidence while preserving the signed raw record."""
    details = event.details if isinstance(getattr(event, "details", None), dict) else {}

    event_type = str(details.get("type") or details.get("event_type") or "alert")
    event_label = event_type.replace("_", " ").strip().title() or "Alert"
    name = str(details.get("name") or details.get("process_name") or "").strip()
    pid = details.get("pid")
    if name and isinstance(pid, int):
        subject = f"{name} (PID {pid})"
    elif name:
        subject = name
    else:
        subject = str(getattr(event, "message", "") or "No subject supplied")

    paths = _event_artifact_paths(event)
    location = "  ·  ".join(paths)
    location_status = str(details.get("location_status") or "unavailable")
    if not location:
        location = f"Unavailable ({location_status.replace('_', ' ')})"

    parent_name = str(details.get("parent_name") or "").strip()
    parent_pid = details.get("ppid")
    if parent_name and isinstance(parent_pid, int):
        parent = f"{parent_name} (PID {parent_pid})"
    elif isinstance(parent_pid, int):
        parent = f"PID {parent_pid} (name unavailable)"
    else:
        parent = "Not supplied by this sensor"

    command_line = str(details.get("cmdline") or "").strip()
    if not command_line:
        command_status = str(
            details.get("command_line_status") or "unavailable"
        ).replace("_", " ")
        command_line = f"Unavailable ({command_status})"

    source = str(details.get("source") or "event bus").strip()
    sensor = str(details.get("sensor") or "").strip()
    if sensor and sensor.lower() not in source.lower():
        source = f"{source} · {sensor}"
    return {
        "event": event_label,
        "subject": subject,
        "location": location,
        "parent": parent,
        "command_line": command_line,
        "source": source,
    }


class AlertDetailDialog(QDialog):
    """Full granular detail for one alert, incl. a SHA-256 fingerprint.

    `panel` (optional): the AlertsPanel this alert came from. When provided, the
    Allow / Block / Analyze buttons reuse the panel's handlers so behaviour is
    identical to the inline row buttons. Research always works (AI consult)."""
    def __init__(self, event, parent=None, panel=None) -> None:
        super().__init__(parent)
        self._event = event
        self._panel = panel
        self.setWindowTitle("Alert detail")
        self.setMinimumSize(580, 480)
        if parent:
            self.setStyleSheet(parent.styleSheet())
        lay = QVBoxLayout(self)

        identity = _event_record_identity(
            event, getattr(panel, "bus", None) if panel is not None else None
        )
        authenticity_verified = identity.startswith("verified:")
        evidence_subtitle = (
            "Verified EventBus HMAC authenticity, record fingerprint, and "
            "explicit operator actions"
            if authenticity_verified
            else "Deterministic record fingerprint (authenticity not verified) "
            "and explicit operator actions"
        )
        lay.addWidget(FuturisticHeader(
            f"{event.severity.label} · {event.module}",
            evidence_subtitle,
            _sev_color(event.severity),
            self,
        ))
        authenticity = QLabel(
            "Authenticity: verified by the live EventBus HMAC authority"
            if authenticity_verified
            else "Authenticity: not verified; SHA-256 below identifies this record only"
        )
        authenticity.setObjectName("alertEvidenceAuthenticity")
        authenticity.setStyleSheet(
            "color:#22c55e; font-weight:700;"
            if authenticity_verified else "color:#f59e0b; font-weight:700;"
        )
        lay.addWidget(authenticity)
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(event.ts))
        lay.addWidget(QLabel(f"Time: {ts}"))
        # Long alert text slowly scrolls inside a fixed-height box so the whole
        # message stays readable without stretching the dialog (doc request:
        # "any long string of text in a box, have it slowly rotate down").
        try:
            from angerona.core.analysis_worker import MarqueeLabel
            msg = MarqueeLabel("")
            msg.setText(event.message)   # triggers the overflow/scroll check
        except Exception:
            msg = QLabel(event.message); msg.setWordWrap(True)
        msg.setStyleSheet("color:#cbd5e1;"); lay.addWidget(msg)

        # Keep the full event record visible, while surfacing the
        # affected artifact and process lineage as first-class operator evidence.
        evidence = _event_evidence_context(event)
        evidence_panel = QFrame()
        evidence_panel.setObjectName("Panel")
        evidence_grid = QGridLayout(evidence_panel)
        evidence_grid.setContentsMargins(10, 8, 10, 8)
        evidence_grid.setHorizontalSpacing(10)
        evidence_grid.setVerticalSpacing(5)
        evidence_fields = (
            ("Event", "event", "alertEvidenceEvent"),
            ("Subject", "subject", "alertEvidenceSubject"),
            ("File path(s)", "location", "alertEvidenceLocation"),
            ("Parent", "parent", "alertEvidenceParent"),
            ("Command line", "command_line", "alertEvidenceCommandLine"),
            ("Source", "source", "alertEvidenceSource"),
        )
        for row, (label, key, object_name) in enumerate(evidence_fields):
            caption = QLabel(label)
            caption.setStyleSheet("color:#7dd3fc; font-weight:700;")
            value = QLineEdit(evidence[key])
            value.setObjectName(object_name)
            value.setReadOnly(True)
            value.setCursorPosition(0)
            value.setToolTip(evidence[key])
            evidence_grid.addWidget(caption, row, 0)
            evidence_grid.addWidget(value, row, 1)
        evidence_grid.setColumnStretch(1, 1)

        try:
            details_json = json.dumps(event.details, sort_keys=True, default=str)
        except (TypeError, ValueError):
            details_json = json.dumps(event.details, default=str)
        canon = (f"{event.ts}|{event.module}|{int(event.severity)}|{event.message}|"
                 f"{details_json}")
        digest = hashlib.sha256(canon.encode("utf-8")).hexdigest()
        lay.addWidget(_section("Deterministic record fingerprint (SHA-256)"))
        hbox = QLineEdit(digest)
        hbox.setObjectName("alertRecordFingerprint")
        hbox.setReadOnly(True)
        lay.addWidget(hbox)

        # Evidence and the full record share all remaining height through a
        # draggable splitter. The evidence side scrolls at small window sizes,
        # preventing the lower record box from being squeezed to a sliver.
        details_splitter = QSplitter(Qt.Vertical)
        details_splitter.setObjectName("alertDetailSplitter")
        details_splitter.setChildrenCollapsible(False)
        details_splitter.setOpaqueResize(False)
        details_splitter.setHandleWidth(7)

        evidence_box = QWidget()
        evidence_layout = QVBoxLayout(evidence_box)
        evidence_layout.setContentsMargins(0, 0, 0, 0)
        evidence_layout.addWidget(_section("Observed evidence"))
        evidence_scroll = QScrollArea()
        evidence_scroll.setWidgetResizable(True)
        evidence_scroll.setMinimumHeight(96)
        evidence_scroll.setWidget(evidence_panel)
        evidence_layout.addWidget(evidence_scroll, 1)
        details_splitter.addWidget(evidence_box)

        record_box = QWidget()
        record_layout = QVBoxLayout(record_box)
        record_layout.setContentsMargins(0, 0, 0, 0)
        record_layout.addWidget(_section("Full event record"))
        body = QPlainTextEdit(); body.setReadOnly(True)
        body.setMinimumHeight(96)
        record = {
            "time": ts,
            "module": event.module,
            "severity": event.severity.label,
            "message": event.message,
            "details": event.details,
            "authenticity": (
                "verified_eventbus_hmac"
                if authenticity_verified else "not_verified"
            ),
            "record_sha256": digest,
        }
        body.setPlainText(json.dumps(record, indent=2, default=str))
        record_layout.addWidget(body, 1)
        details_splitter.addWidget(record_box)
        details_splitter.setStretchFactor(0, 1)
        details_splitter.setStretchFactor(1, 1)
        details_splitter.setSizes([240, 260])
        lay.addWidget(details_splitter, 1)
        self._details_splitter = details_splitter
        self._evidence_scroll = evidence_scroll
        self._record_body = body

        # ── Action bar: Allow · Block · Analyze · Research ────────────────────
        lay.addWidget(_section("Actions"))
        self._action_status = QLabel("")
        self._action_status.setWordWrap(True)
        self._action_status.setStyleSheet("color:#94a3b8; font-size:12px;")
        acts = QHBoxLayout()
        b_allow = QPushButton("Allow");   b_allow.clicked.connect(self._act_allow)
        b_block = QPushButton("Block");   b_block.clicked.connect(self._act_block)
        b_analyze = QPushButton("Analyze"); b_analyze.clicked.connect(self._act_analyze)
        b_research = QPushButton("🔎 Research"); b_research.clicked.connect(self._act_research)
        b_copy = QPushButton("📋 Copy"); b_copy.clicked.connect(self._act_copy)
        b_copy.setStyleSheet("background:#334155;color:#e2e8f0;")
        b_allow.setStyleSheet("background:#14532d;color:#86efac;")
        b_block.setStyleSheet("background:#7f1d1d;color:#fca5a5;")
        b_analyze.setStyleSheet("background:#1e3a5f;color:#7dd3fc;")
        b_research.setStyleSheet("background:#4c1d95;color:#e9d5ff;")
        self._b_analyze = b_analyze
        for b in (b_allow, b_block, b_analyze, b_research, b_copy):
            acts.addWidget(b)
        acts.addStretch()
        close = QPushButton("Close"); close.setObjectName("Primary")
        close.clicked.connect(self.close)
        acts.addWidget(close)
        lay.addLayout(acts)
        lay.addWidget(self._action_status)

    # ── Action handlers (reuse the AlertsPanel logic when available) ──────────
    def _act_allow(self) -> None:
        if self._panel is not None:
            changed = self._panel._allow_event(self._event)
            self._action_status.setText(
                "A confirmed 15-minute exact-rule suppression is active; "
                "use Undo Allow in Live Alerts to revoke it."
                if changed else "No alert suppression was created."
            )
        else:
            self._action_status.setText("Allow needs the live Alerts panel.")

    def _act_block(self) -> None:
        if self._panel is not None:
            # Report the panel's ACTUAL result — it shows its own confirm dialog
            # and may cancel or fail; claiming "queued" unconditionally is what
            # made blocks look successful while nothing reached the SOAR tab.
            ok = self._panel._block_event(self._event)
            self._action_status.setText(
                "Direct containment completed; the exact process was suspended "
                "and recorded in SOAR history." if ok
                else "No containment action completed (cancelled or safely refused).")
            return
        # Standalone (opened from a module view): persist the review-gated request
        # first (the SOAR tab reads the file), then best-effort bus notify.
        e = self._event
        persisted = _persist_soar_queue(e)
        try:
            from angerona.core.eventbus import Event as BusEvent, Severity as BusSev
            bus = getattr(self, "bus", None) or getattr(getattr(self, "_panel", None), "bus", None)
            if bus is not None:
                bus.publish(BusEvent(module="OPERATOR", severity=BusSev.INFO,
                            ts=time.time(),
                            message=(f"[SOAR-QUEUE] Operator requested containment of source "
                                     f"'{e.module}' — alert: {e.message[:120]}"),
                            details={"origin_module": e.module, "origin_ts": e.ts,
                                     "soar_action": "containment_review",
                                     "disposition": "response_audit"}))
        except Exception:
            pass
        self._action_status.setText(
            f"✓ Containment staged for '{e.module}'; approval is still required."
            if persisted
            else "⚠ Could not write to the SOAR queue — check disk/permissions.")

    def _act_analyze(self) -> None:
        if self._panel is not None:
            self._panel._analyze_event(self._event, self._b_analyze)
            self._action_status.setText("Running deep AI triage… (see Alerts panel status)")
            return
        # Standalone deep triage (module view): run the worker here.
        try:
            from angerona.core.analysis_worker import AnalysisWorker
        except Exception as exc:
            self._action_status.setText(f"Analyze unavailable: {exc}")
            return
        e = self._event
        d = e.details or {}
        alert = {"pid": d.get("pid"), "process_name": d.get("name") or e.module,
                 "ancestry": d.get("ancestry") or [], "connections": d.get("connections") or [],
                 "memory_strings": d.get("memory_strings") or [], "details": e.message,
                 "type": e.module}
        self._b_analyze.setEnabled(False); self._b_analyze.setText("Analyzing…")
        loading_token = begin_loading("Retrieving alert analysis…")
        self._analyze_worker = AnalysisWorker(alert, parent=self)
        self._analyze_worker.progress.connect(self._action_status.setText)
        self._analyze_worker.result_ready.connect(self._on_standalone_analyze)
        self._analyze_worker.error.connect(
            lambda m: (self._action_status.setText(f"⚠ {m}"),
                       self._b_analyze.setEnabled(True), self._b_analyze.setText("Analyze")))
        self._analyze_worker.finished.connect(
            lambda token=loading_token: finish_loading(token)
        )
        self._analyze_worker.start()

    def _on_standalone_analyze(self, res: dict) -> None:
        self._b_analyze.setEnabled(True); self._b_analyze.setText("Analyze")
        verdict = res.get("final_verdict", "UNKNOWN")
        conf = res.get("final_confidence", 0)
        detail = (res.get("cloud") or res.get("local") or {})
        reason = detail.get("reasoning") or detail.get("justification") or ""
        self._action_status.setText(f"🔍 [{verdict} · {conf}%] {reason}")

    def closeEvent(self, event) -> None:  # noqa: N802
        """Keep a standalone triage worker alive until its blocking call returns."""
        from angerona.gui.thread_lifecycle import defer_close_until_threads

        worker = getattr(self, "_analyze_worker", None)
        if defer_close_until_threads(self, event, (worker,)):
            return
        super().closeEvent(event)

    def _act_copy(self) -> None:
        _copy_event_to_clipboard(self._event)
        self._action_status.setText("📋 Alert copied to clipboard.")

    def _act_research(self) -> None:
        """Consult an online AI (Claude first) for context + remediation on this alert."""
        try:
            from angerona.gui.ai_consult_dialog import AIConsultDialog
        except Exception as exc:
            self._action_status.setText(f"Research unavailable: {exc}")
            return
        e = self._event
        prompt = (
            "Research this endpoint security alert and give the operator: (1) what it "
            "most likely means, (2) how to confirm whether it is malicious, (3) concrete "
            "remediation/containment steps for Windows.\n\n"
            f"Module: {e.module}\nSeverity: {e.severity.label}\nMessage: {e.message}\n"
            f"Details: {json.dumps(e.details, default=str)[:1500]}")
        AIConsultDialog("Research — " + e.module, prompt,
                        default_filename="alert_research.md", parent=self.window()).show()


class AlertsPanel(QFrame):
    events_loaded = Signal(object, object)
    scan_requested = Signal()

    def __init__(self, storage, allow_cloud=False, bus=None) -> None:
        super().__init__()
        self.setObjectName("Panel")
        self.storage = storage
        self.bus = bus
        self._accept_async_results = True
        self._events_worker: threading.Thread | None = None
        self._allow_cloud = allow_cloud is True
        self._events: list = []
        self._rendered_event_ids: tuple[str, ...] = ()
        self._newest_ts: float = 0.0
        self._last_storage_revision: int = -1
        self._last_gap_rebuild: float = 0.0
        self._events_load_busy = False
        self.events_loaded.connect(self._apply_loaded_events)
        # Explicit, short-lived detector-pattern suppressions.  Module-wide and
        # integrity-alert suppression are deliberately unsupported.
        self._suppressions: dict[tuple[str, str], float] = {}
        self._last_suppression: tuple[str, str] | None = None
        # Live "Analyze" deep-triage workers, kept alive across row rebuilds.
        self._analyze_workers: list = []
        self._analyze_inflight: set[str] = set()
        self._analyze_queue: list[tuple[object, object, str]] = []
        self._max_analyze_workers = 2
        self._max_analyze_queue = 6
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 12, 14, 14)
        self._title = _ClickableSection(
            "Live Alerts  —  click a header to sort · click a row for detail  "
            "· Allow = confirm a 15-minute exact-rule suppression  "
            "· Block = confirm + directly suspend a verified process target  "
            "· Analyze = local AI triage (sanitized cloud fallback only if enabled)",
            "Open a full-size newest-first alert evidence window.",
        )
        self._title.clicked.connect(self._open_overview)
        title_row = QHBoxLayout()
        title_row.addWidget(self._title, 1)
        scan_button = QPushButton("🛡  Scan Center")
        scan_button.setToolTip(
            "Scan this computer with bounded Angerona checks, Microsoft Defender, "
            "and passive listening-port/network posture review."
        )
        scan_button.clicked.connect(
            lambda _checked=False: self.scan_requested.emit()
        )
        title_row.addWidget(scan_button)
        lay.addLayout(title_row)
        self.table = QTableWidget(0, 8)
        self.table.setHorizontalHeaderLabels(
            [
                "Time", "Module", "Severity", "Message", "File / artifact path",
                "Allow", "Block", "Analyze",
            ]
        )
        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(1, QHeaderView.Interactive)
        hdr.setSectionResizeMode(3, QHeaderView.Stretch)
        hdr.setSectionResizeMode(4, QHeaderView.Stretch)
        hdr.setSectionResizeMode(5, QHeaderView.Fixed)
        hdr.setSectionResizeMode(6, QHeaderView.Fixed)
        hdr.setSectionResizeMode(7, QHeaderView.Fixed)
        self.table.setColumnWidth(0, 72)
        self.table.setColumnWidth(1, 140)
        self.table.setColumnWidth(2, 82)
        self.table.setColumnWidth(5, 68)
        self.table.setColumnWidth(6, 68)
        self.table.setColumnWidth(7, 78)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.cellClicked.connect(self._on_click)
        # Ctrl+C copies the selected alert row to the clipboard instantly.
        _sc = QShortcut(QKeySequence.Copy, self.table)
        _sc.activated.connect(self._copy_selected)
        # Enable click-to-sort on all column headers; default = newest first.
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(0, Qt.DescendingOrder)
        lay.addWidget(self.table)
        # Status line for Allow/Block feedback
        self._status = QLabel("")
        self._status.setStyleSheet("color:#94a3b8; font-size:12px; padding:2px 0;")
        status_row = QHBoxLayout()
        status_row.addWidget(self._status, 1)
        self._undo_allow = QPushButton("Undo Allow")
        self._undo_allow.setToolTip(
            "Remove the most recent temporary alert-pattern suppression."
        )
        self._undo_allow.setEnabled(False)
        self._undo_allow.clicked.connect(self._undo_last_suppression)
        status_row.addWidget(self._undo_allow)
        lay.addLayout(status_row)

    def _copy_selected(self) -> None:
        row = self.table.currentRow()
        if row < 0:
            return
        item = self.table.item(row, 0)
        ev = item.data(Qt.UserRole) if item else None
        if ev is not None:
            _copy_event_to_clipboard(ev)
            self._status.setText("📋 Alert copied to clipboard.")

    def _on_click(self, row: int, col: int) -> None:
        item = self.table.item(row, 0)
        if item is None:
            return
        event = item.data(Qt.UserRole)
        if event is None:
            return
        if col == 5:
            self._allow_event(event)
        elif col == 6:
            self._block_event(event)
        elif col == 7:
            self._analyze_event(event, None)
        else:
            _show_nonmodal_from(
                self.table,
                lambda: AlertDetailDialog(
                    event, self.window(), panel=self
                ),
                _sev_color(getattr(event, "severity", Severity.INFO)),
            )

    def _open_overview(self) -> None:
        if self.bus is None:
            self._status.setText("Live alert overview is still initializing.")
            return
        _show_nonmodal_from(
            self._title,
            lambda: EventsWindow(
                "Live Alerts · Expanded Evidence",
                self.bus,
                self.storage,
                min_sev=Severity.LOW,
                parent=self.window(),
            ),
            "#38bdf8",
        )

    def _make_allow_btn(self, event) -> QPushButton:
        btn = QPushButton("Allow")
        btn.setFixedHeight(22)
        btn.setStyleSheet(
            "QPushButton{background:#14532d;color:#86efac;border:none;border-radius:3px;"
            "font-size:11px;padding:0 4px;}"
            "QPushButton:hover{background:#166534;}"
        )
        btn.clicked.connect(lambda: self._allow_event(event))
        return btn

    def _make_block_btn(self, event) -> QPushButton:
        btn = QPushButton("Block")
        btn.setFixedHeight(22)
        btn.setStyleSheet(
            "QPushButton{background:#7f1d1d;color:#fca5a5;border:none;border-radius:3px;"
            "font-size:11px;padding:0 4px;}"
            "QPushButton:hover{background:#991b1b;}"
        )
        btn.clicked.connect(lambda: self._block_event(event))
        return btn

    def _make_analyze_btn(self, event) -> QPushButton:
        btn = QPushButton("Analyze")
        btn.setFixedHeight(22)
        btn.setStyleSheet(
            "QPushButton{background:#1e3a5f;color:#7dd3fc;border:none;border-radius:3px;"
            "font-size:11px;padding:0 4px;}"
            "QPushButton:hover{background:#1d4ed8;}"
            "QPushButton:disabled{background:#334155;color:#94a3b8;}"
        )
        btn.clicked.connect(lambda: self._analyze_event(event, btn))
        return btn

    def _analyze_event(self, event, btn) -> None:
        """Run operator-triggered deep triage off the GUI thread.

        Local Ollama is always tried first. Sanitized cloud fallback is used only
        when the operator explicitly enabled it in Settings.
        """
        try:
            from angerona.core.analysis_worker import AnalysisWorker
        except Exception as exc:
            self._status.setText(f"Analyze unavailable: {exc}")
            return
        identity = _event_record_identity(event, self.bus)
        if identity in self._analyze_inflight:
            self._status.setText(
                "Analyze is already running or queued for this exact event."
            )
            return
        if len(self._analyze_workers) >= self._max_analyze_workers:
            if len(self._analyze_queue) >= self._max_analyze_queue:
                self._status.setText(
                    "Analyze queue is full (2 active · 6 queued); try again shortly."
                )
                return
            self._analyze_inflight.add(identity)
            self._analyze_queue.append((event, btn, identity))
            if btn is not None:
                try:
                    btn.setEnabled(False)
                    btn.setText("Queued…")
                except RuntimeError:
                    pass
            self._status.setText(
                f"Analyze queued ({len(self._analyze_queue)}/{self._max_analyze_queue})."
            )
            return
        self._analyze_inflight.add(identity)
        self._start_analysis(event, btn, identity, AnalysisWorker)

    def _start_analysis(self, event, btn, identity: str, worker_type=None) -> None:
        """Start one bounded analysis worker; callers own in-flight identity."""
        if worker_type is None:
            try:
                from angerona.core.analysis_worker import AnalysisWorker as worker_type
            except Exception as exc:
                self._analyze_inflight.discard(identity)
                self._reset_analyze_btn(btn)
                self._status.setText(f"Analyze unavailable: {exc}")
                return
        if btn is not None:
            try:
                btn.setEnabled(False)
                btn.setText("Analyzing…")
            except RuntimeError:
                pass   # button may have been rebuilt by a refresh — harmless
        d = event.details or {}
        alert = {
            "pid":            d.get("pid"),
            "process_name":   d.get("name") or d.get("image") or event.module,
            "ancestry":       d.get("ancestry") or d.get("lineage") or [],
            "connections":    d.get("connections") or [],
            "memory_strings": d.get("memory_strings") or [],
            "details":        event.message,
            "type":           event.module,
        }
        worker = worker_type(
            alert,
            allow_cloud=self._allow_cloud,
            parent=self,
        )
        loading_token = begin_loading("Retrieving alert analysis…")
        self._analyze_workers.append(worker)
        worker.progress.connect(self._status.setText)
        worker.result_ready.connect(
            lambda res, b=btn: self._on_analyze_done(res, b)
        )
        worker.error.connect(lambda msg, b=btn: self._on_analyze_err(msg, b))
        # Retain the worker until Qt confirms run() has returned. Reaping from
        # result_ready/error could delete a native QThread that is still
        # unwinding, which aborts the process on Windows.
        worker.finished.connect(
            lambda w=worker, event_id=identity: self._analysis_finished(w, event_id)
        )
        worker.finished.connect(
            lambda token=loading_token: finish_loading(token)
        )
        worker.start()

    @staticmethod
    def _reset_analyze_btn(btn) -> None:
        if btn is None:
            return
        try:
            btn.setEnabled(True)
            btn.setText("Analyze")
        except RuntimeError:
            pass   # row was rebuilt mid-analysis — the new button is already fresh

    def _analysis_finished(self, worker, identity: str) -> None:
        try:
            self._analyze_workers.remove(worker)
        except ValueError:
            pass
        self._analyze_inflight.discard(identity)
        worker.deleteLater()
        if not self._accept_async_results or not self._analyze_queue:
            return
        event, btn, queued_identity = self._analyze_queue.pop(0)
        self._start_analysis(event, btn, queued_identity)

    def _on_analyze_done(self, result: dict, btn) -> None:
        self._reset_analyze_btn(btn)
        verdict = result.get("final_verdict", "UNKNOWN")
        conf = result.get("final_confidence", 0)
        src = "cloud" if result.get("cloud") else "local"
        detail = (result.get("cloud") or result.get("local") or {})
        reason = detail.get("reasoning") or detail.get("justification") or ""
        self._status.setText(f"🔍 [{verdict} · {conf}% · {src}] {reason}")

    def _on_analyze_err(self, msg: str, btn) -> None:
        self._reset_analyze_btn(btn)
        self._status.setText(f"⚠ Analyze failed: {msg}")

    def _allow_event(self, event) -> bool:
        """Confirm a reversible, expiring exact-rule/pattern suppression."""
        if _is_integrity_alert(event):
            self._status.setText(
                "Integrity alerts cannot be suppressed; investigate the trust failure."
            )
            QMessageBox.warning(
                self.window(),
                "Integrity alert cannot be allowed",
                "Angerona never suppresses integrity, signature, HMAC, ledger, or "
                "tamper failures. Review the evidence and resolve its cause.",
            )
            return False
        module, selector, description = _alert_suppression_scope(event)
        answer = QMessageBox.question(
            self.window(),
            "Temporarily suppress matching alerts",
            f"Suppress {description} for 15 minutes?\n\n"
            "This does not trust a process, change detector settings, or suppress "
            "other alerts from the module. The action is visible here and can be "
            "undone immediately.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if answer != QMessageBox.Yes:
            return False
        scope = (module, selector)
        expires = time.time() + 15 * 60
        self._suppressions[scope] = expires
        self._last_suppression = scope
        self._undo_allow.setEnabled(True)
        self._publish_suppression_audit("created", scope, expires)
        self._status.setText(
            f"Temporary suppression active until "
            f"{time.strftime('%H:%M:%S', time.localtime(expires))}: {description}. "
            "Use Undo Allow to restore it now."
        )
        self._rebuild_event_rows(self._events, force=True)
        return True

    def _publish_suppression_audit(
        self, action: str, scope: tuple[str, str], expires: float
    ) -> None:
        if self.bus is None or not hasattr(self.bus, "publish"):
            return
        try:
            from angerona.core.eventbus import Event

            self.bus.publish(Event(
                "Operator Alert Suppression",
                f"Temporary alert-pattern suppression {action}",
                Severity.INFO,
                details={
                    "action": action,
                    "expires_at": expires,
                    "module": scope[0],
                    "scope": scope[1],
                    "reversible": True,
                },
            ))
        except Exception:
            pass

    def _undo_last_suppression(self) -> None:
        scope = self._last_suppression
        if scope is None or scope not in self._suppressions:
            self._undo_allow.setEnabled(False)
            self._status.setText("No active temporary suppression to undo.")
            return
        expires = self._suppressions.pop(scope)
        self._publish_suppression_audit("revoked", scope, expires)
        self._last_suppression = None
        self._undo_allow.setEnabled(False)
        self._status.setText(
            f"Temporary suppression revoked for {scope[0]}; matching alerts are visible."
        )
        self._rebuild_event_rows(self._events, force=True)

    def _is_suppressed(self, event, *, now: float | None = None) -> bool:
        if _is_integrity_alert(event):
            return False
        current = time.time() if now is None else float(now)
        expired = [
            scope for scope, expiry in self._suppressions.items()
            if expiry <= current
        ]
        for scope in expired:
            self._suppressions.pop(scope, None)
            if scope == self._last_suppression:
                self._last_suppression = None
                self._undo_allow.setEnabled(False)
        module, selector, _description = _alert_suppression_scope(event)
        return self._suppressions.get((module, selector), 0.0) > current

    def _block_event(self, event) -> bool:
        """Directly contain a safely-bound process after one confirmation.

        The action is deliberately reversible suspension, never an implicit
        kill or file deletion. It is also persisted in SOAR history, but this
        path neither navigates to SOAR nor asks for a second approval there.
        """
        try:
            record = _new_soar_queue_record(event)
            process, _origin = _soar_process_preflight(
                record, self.bus, getattr(self.window(), "manager", None)
            )
            pid = int(process.pid)
            process_name = str(process.name() or "process")
        except Exception as exc:
            reason = str(exc)
            self._status.setText(f"⚠ Direct containment refused: {reason}")
            QMessageBox.warning(
                self.window(),
                "Direct Containment Refused",
                "Angerona did not change the host.\n\n"
                f"Reason: {reason}\n\n"
                "Only a live, signed, non-trusted process instance can be "
                "contained from this button.",
            )
            return False

        ts_str = time.strftime("%H:%M:%S", time.localtime(event.ts))
        details = (f"Module: {event.module}\n"
                   f"Severity: {event.severity.label}\n"
                   f"Time: {ts_str}\n\n"
                   f"Message: {event.message}\n\n"
                   f"Target: {process_name} (pid {pid})\n\n"
                   f"Confirming submits this exact process instance to Combat now.\n"
                   "A durable intent is written before suspension and the action is "
                   "reversible from Settings → Adversary Combat → Action history.\n"
                   f"No process is killed and no file is deleted.")
        dlg = QMessageBox(self.window())
        dlg.setWindowTitle("Confirm Direct Containment")
        dlg.setText(f"Suspend {process_name} (pid {pid})?")
        dlg.setInformativeText(details)
        dlg.setStandardButtons(QMessageBox.Ok | QMessageBox.Cancel)
        dlg.setDefaultButton(QMessageBox.Cancel)
        dlg.setIcon(QMessageBox.Warning)
        if dlg.exec() != QMessageBox.Ok:
            return False

        # Refuse an unaudited host mutation: history must be durable before the
        # process action. Execution then performs its own second identity/HMAC
        # check to close the confirmation-time race.
        if not _append_soar_queue_record(record):
            self._status.setText(
                "⚠ Containment refused because the SOAR audit record could not be written."
            )
            return False
        try:
            result = _execute_approved_soar_record(
                record, self.bus, getattr(self.window(), "manager", None)
            )
        except Exception as exc:
            reason = str(exc)
            _update_soar_queue_record(
                _soar_record_id(record),
                status="FAILED — no host action taken",
                execution_error=reason[:1000],
            )
            self._status.setText(f"⚠ Containment failed safely: {reason}")
            return False
        updated = _update_soar_queue_record(
            _soar_record_id(record),
            status=_SOAR_SUBMITTED,
            submitted_at=time.time(),
            execution_result=result,
        )
        suffix = "" if updated else " (SOAR history status update failed)"
        self._status.setText(f"✓ {result}{suffix}")
        return True

    def _insert_row(self, pos: int, e, row_identity: str | None = None) -> None:
        if self._is_suppressed(e):
            return
        self.table.insertRow(pos)
        ts_item = _TimestampItem(e.ts)
        ts_item.setData(Qt.UserRole, e)      # store event for click lookup
        ts_item.setData(
            Qt.UserRole + 1,
            row_identity or _event_record_identity(e, self.bus) + ":0",
        )
        self.table.setItem(pos, 0, ts_item)
        # node_origin: alerts forwarded by a remote sensor node (Remote Bridge)
        # are tagged so the operator can tell them apart from local telemetry.
        details = e.details if isinstance(getattr(e, "details", None), dict) else {}
        origin = details.get("node_origin")
        mod_item = QTableWidgetItem(f"{e.module}  ⇠{origin}" if origin else e.module)
        if origin:
            mod_item.setToolTip(f"Forwarded from remote node: {origin}")
        self.table.setItem(pos, 1, mod_item)
        self.table.setItem(pos, 2, _SeverityItem(e.severity))
        self.table.setItem(pos, 3, QTableWidgetItem(e.message))
        path_text, path_tooltip = _event_path_display(e)
        path_item = QTableWidgetItem(path_text)
        path_item.setToolTip(path_tooltip)
        self.table.setItem(pos, 4, path_item)
        # Action buttons — must use setCellWidget, not setItem
        # Lightweight clickable items replace three QWidget buttons per row.
        # At 120 rows this avoids creating/reparenting 360 controls during an
        # alert burst, the exact GUI-thread stall recorded in diagnostics.
        for col, text, bg, fg in (
                (5, "Allow", "#14532d", "#86efac"),
                (6, "Block", "#7f1d1d", "#fca5a5"),
                (7, "Analyze", "#1e3a5f", "#7dd3fc")):
            action = QTableWidgetItem(text)
            action.setTextAlignment(Qt.AlignCenter)
            action.setBackground(QColor(bg))
            action.setForeground(QColor(fg))
            action.setToolTip(f"{text} this alert")
            self.table.setItem(pos, col, action)

    _MAX_ROWS = 120   # feed cap keeps table-item refresh work bounded

    def _free_row_widgets(self, r: int) -> None:
        """Explicitly delete a row's Allow/Block/Analyze cell widgets.

        CRITICAL for long-run performance: QTableWidget.setRowCount(0)/removeRow
        does NOT delete widgets installed via setCellWidget — they orphan and leak.
        In a busy EDR the feed refreshes every couple of seconds, so without this
        the suite accumulates hundreds of thousands of dead QPushButtons over a
        session (the "slower the longer it runs" symptom). Free them here."""
        for c in (5, 6, 7):
            w = self.table.cellWidget(r, c)
            if w is not None:
                self.table.removeCellWidget(r, c)
                w.deleteLater()

    def _trim_to_cap(self) -> None:
        while self.table.rowCount() > self._MAX_ROWS:
            r = self.table.rowCount() - 1
            self._free_row_widgets(r)
            self.table.removeRow(r)

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt signature
        self._accept_async_results = False
        super().closeEvent(event)

    def refresh(self) -> None:
        # Expiry is wall-clock state, independent of ledger revision. Re-render
        # when a temporary suppression lapses even if no new event arrived.
        if any(expiry <= time.time() for expiry in self._suppressions.values()):
            self._rebuild_event_rows(self._events, force=True)
        # The pre-check is an in-memory committed revision. If a writer is busy,
        # keep the current table and retry on the next two-second refresh.
        revision = self.storage.revision()
        if revision == self._last_storage_revision or self._events_load_busy:
            return
        self._events_load_busy = True

        def _load_events(_revision=revision) -> None:
            try:
                events = self.storage.try_recent(120)
                _emit_if_accepting(self, "events_loaded", _revision, events)
            except Exception:
                _emit_if_accepting(self, "events_loaded", _revision, None)

        self._events_worker = threading.Thread(
            target=_load_events, name="DashboardAlertReader", daemon=True
        )
        self._events_worker.start()

    def _apply_loaded_events(self, revision, events) -> None:
        if not self._accept_async_results:
            return
        self._events_load_busy = False
        if events is None:
            return
        self._rebuild_event_rows(events)
        self._events = list(events)
        self._newest_ts = float(events[0].ts) if events else 0.0
        self._last_storage_revision = revision

    def _rebuild_event_rows(self, events, *, force: bool = False) -> None:
        """Reconcile by full event identity so equal timestamps cannot drop rows."""
        visible = [event for event in events if not self._is_suppressed(event)][:self._MAX_ROWS]
        identities = tuple(_event_row_identities(visible, self.bus))
        if identities == self._rendered_event_ids and not force:
            return
        previous_ids = set(self._rendered_event_ids)
        has_new_identity = any(identity not in previous_ids for identity in identities)
        hdr = self.table.horizontalHeader()
        sort_col = hdr.sortIndicatorSection()
        sort_ord = hdr.sortIndicatorOrder()
        previous_scroll = self.table.verticalScrollBar().value()
        self.table.setSortingEnabled(False)
        self.table.setUpdatesEnabled(False)
        try:
            wanted = set(identities)
            # Keep unchanged items (and their selection) during an alert burst.
            # A single incoming alert must not recreate 960 table items.
            for row in range(self.table.rowCount() - 1, -1, -1):
                item = self.table.item(row, 0)
                if item is None or item.data(Qt.UserRole + 1) not in wanted:
                    self._free_row_widgets(row)
                    self.table.removeRow(row)
            retained = {
                self.table.item(row, 0).data(Qt.UserRole + 1): self.table.item(row, 0)
                for row in range(self.table.rowCount())
            }
            for event, identity in zip(visible, identities):
                if identity in retained:
                    retained[identity].setData(Qt.UserRole, event)
                else:
                    self._insert_row(self.table.rowCount(), event, identity)
        finally:
            self.table.setSortingEnabled(True)
            self.table.sortByColumn(sort_col, sort_ord)
            _restore_alert_scroll(
                self.table, sort_col, sort_ord, previous_scroll, has_new_identity
            )
            self.table.setUpdatesEnabled(True)
        self._rendered_event_ids = identities


# ── Bottom status strip ───────────────────────────────────────────────────────
# Each chip shows: CODE (acronym, 2-5 chars) on line 1, health-% on line 2.
# Chips share equal stretch so they fill the bar width automatically.
# Change-detection (_prev_states) skips stylesheet regeneration for chips that
# haven't changed, keeping repaint cost O(new_events) not O(all_modules).

_CHIP_FONT: QFont | None = None  # built lazily to avoid pre-QApplication issues


def _chip_font() -> QFont:
    global _CHIP_FONT
    if _CHIP_FONT is None:
        _CHIP_FONT = QFont("Consolas", 8)
        _CHIP_FONT.setBold(True)
    return _CHIP_FONT


class SoarPanel(QFrame):
    """SOAR queue: every 'Block → SOAR' request lands here (persisted, scrollable).

    Includes a smart 'Consult AI' button that sends the whole queue — enriched
    with per-item file info + VPN/interface status — to online AIs for an opinion.
    """
    def __init__(self, bus, manager=None) -> None:
        super().__init__()
        self.setObjectName("Panel")
        self.bus = bus
        self.manager = manager
        self._queue_fingerprint: tuple | None = None
        self._last_clear_archive: Path | None = None
        # Approval must be acquired in this live UI session. Persisted JSONL is
        # history, not an authorization boundary, so editing it cannot enable
        # Execute after a restart.
        self._approved_requests: dict[str, str] = {}
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 12, 14, 14)
        self._title = _ClickableSection(
            "SOAR Queue  —  Review → Approve → Execute, or Dismiss",
            "Open the expanded containment-review queue and evidence summary.",
        )
        self._title.clicked.connect(self._open_overview)
        lay.addWidget(self._title)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Time", "Source module", "Severity", "Message", "Status"])
        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(3, QHeaderView.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.cellDoubleClicked.connect(self._open_record)
        self.table.itemSelectionChanged.connect(self._sync_action_buttons)
        # Right-click → per-alert AI analysis
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._row_context_menu)
        lay.addWidget(self.table)

        actions = QHBoxLayout()
        self._btn_review = QPushButton("Review details")
        self._btn_review.setObjectName("soarReviewButton")
        self._btn_review.setToolTip(
            "Inspect persisted evidence and the exact proposed target. No host action."
        )
        self._btn_review.clicked.connect(self._review_selected)
        actions.addWidget(self._btn_review)
        self._btn_approve = QPushButton("Approve")
        self._btn_approve.setObjectName("soarApproveButton")
        self._btn_approve.setToolTip(
            "Approve this request for this UI session. Approval alone changes no host state."
        )
        self._btn_approve.setStyleSheet(
            "background:#14532d;color:#bbf7d0;font-weight:700;"
        )
        self._btn_approve.clicked.connect(self._approve_selected)
        actions.addWidget(self._btn_approve)
        self._btn_dismiss = QPushButton("Reject / Dismiss")
        self._btn_dismiss.setObjectName("soarDismissButton")
        self._btn_dismiss.setToolTip(
            "Close this request without changing the host. The history record remains."
        )
        self._btn_dismiss.clicked.connect(self._dismiss_selected)
        actions.addWidget(self._btn_dismiss)
        actions.addStretch(1)
        self._btn_execute = QPushButton("Execute approved containment")
        self._btn_execute.setObjectName("soarExecuteButton")
        self._btn_execute.setToolTip(
            "After approval, revalidate the signed event and exact process identity, "
            "then suspend it. A final confirmation is always required."
        )
        self._btn_execute.setStyleSheet(
            "background:#7f1d1d;color:#fecaca;font-weight:800;"
        )
        self._btn_execute.clicked.connect(self._execute_selected)
        actions.addWidget(self._btn_execute)
        lay.addLayout(actions)

        row = QHBoxLayout()
        self._status = QLabel("")
        self._status.setStyleSheet("color:#94a3b8; font-size:12px;")
        row.addWidget(self._status, 1)
        self._btn_ai_sel = QPushButton("🤖 Ask AI (selected)")
        self._btn_ai_sel.setToolTip(
            "Deep-dive AI analysis of the selected alert — includes file hash, "
            "parent process, open connections, VPN status, and system health snapshot.")
        self._btn_ai_sel.setStyleSheet("background:#1e3a5f;color:#bfdbfe;font-weight:700;")
        self._btn_ai_sel.clicked.connect(self._consult_ai_selected)
        row.addWidget(self._btn_ai_sel)
        self._btn_ai = QPushButton("🤖 Consult AI on queue")
        self._btn_ai.setToolTip("Send every queued item — with file info + VPN/interface "
                                "status — to online AIs (Claude first) for triage.")
        self._btn_ai.setStyleSheet("background:#4c1d95;color:#e9d5ff;font-weight:700;")
        self._btn_ai.clicked.connect(self._consult_ai)
        row.addWidget(self._btn_ai)
        self._btn_clear = QPushButton("Archive & clear history")
        self._btn_clear.setToolTip(
            "After confirmation, move queue evidence into a recoverable archive."
        )
        self._btn_clear.clicked.connect(self._clear)
        row.addWidget(self._btn_clear)
        self._btn_restore_clear = QPushButton("Restore last clear")
        self._btn_restore_clear.setEnabled(False)
        self._btn_restore_clear.clicked.connect(self._restore_last_clear)
        row.addWidget(self._btn_restore_clear)
        lay.addLayout(row)
        self._sync_action_buttons()

    def refresh(self) -> None:
        items = _read_soar_queue()
        if _reconcile_soar_submission_receipts(items, self.bus):
            items = _read_soar_queue()
        fingerprint = tuple(
            (
                _soar_record_id(record),
                str(record.get("status", "")),
                record.get("reviewed_at"),
                record.get("approved_at"),
                record.get("dismissed_at"),
                record.get("submitted_at"),
                record.get("executed_at"),
                record.get("receipt_hmac"),
            )
            for record in items
        )
        if fingerprint == self._queue_fingerprint:
            self._sync_action_buttons()
            return
        selected = self._selected_request_id()
        self._queue_fingerprint = fingerprint
        self.table.setRowCount(0)
        for rec in reversed(items):     # newest first
            r = self.table.rowCount()
            self.table.insertRow(r)
            ts = time.strftime("%m-%d %H:%M:%S", time.localtime(rec.get("ts", 0)))
            ts_item = QTableWidgetItem(ts)
            request_id = _soar_record_id(rec)
            ts_item.setData(Qt.UserRole, request_id)
            self.table.setItem(r, 0, ts_item)
            self.table.setItem(r, 1, QTableWidgetItem(str(rec.get("origin_module", ""))))
            self.table.setItem(r, 2, QTableWidgetItem(str(rec.get("severity", ""))))
            self.table.setItem(r, 3, QTableWidgetItem(str(rec.get("message", ""))))
            st = QTableWidgetItem(str(rec.get("status", "")))
            status = str(rec.get("status", "")).upper()
            color = (
                "#22c55e" if status.startswith("EXECUTED")
                else "#ef4444" if status.startswith(("FAILED", "DISMISSED"))
                else "#38bdf8" if status.startswith("APPROVED")
                else "#f59e0b"
            )
            st.setForeground(QColor(color))
            self.table.setItem(r, 4, st)
            if selected == request_id:
                self.table.selectRow(r)
        pending = sum(
            1 for record in items
            if str(record.get("status", "")).upper().startswith("PENDING")
        )
        approved = sum(
            1 for record in items
            if str(record.get("status", "")).upper().startswith("APPROVED")
        )
        self._status.setText(
            f"{len(items)} history item(s) · {pending} pending · {approved} approved. "
            "Approval does not execute; Execute always confirms and revalidates."
        )
        self._sync_action_buttons()

    def _selected_request_id(self) -> str:
        row = self.table.currentRow()
        item = self.table.item(row, 0) if row >= 0 else None
        return str(item.data(Qt.UserRole) or "") if item is not None else ""

    def _record_for_row(self, row: int) -> dict | None:
        item = self.table.item(int(row), 0)
        request_id = str(item.data(Qt.UserRole) or "") if item is not None else ""
        items = _read_soar_queue()
        return next(
            (record for record in items if _soar_record_id(record) == request_id),
            None,
        )

    def _selected_record(self) -> dict | None:
        row = self.table.currentRow()
        return self._record_for_row(row) if row >= 0 else None

    @staticmethod
    def _terminal_record(record: dict) -> bool:
        status = str(record.get("status", "")).upper()
        return status.startswith(("SUBMITTED", "EXECUTED", "DISMISSED", "FAILED"))

    def _sync_action_buttons(self) -> None:
        record = self._selected_record()
        selected = record is not None
        terminal = self._terminal_record(record) if record is not None else True
        request_id = _soar_record_id(record) if record is not None else ""
        approved = bool(
            request_id in self._approved_requests
            and self._approved_requests[request_id]
            == _soar_authorization_digest(record)
            and not terminal
        )
        executable = bool(
            approved
            and isinstance(record.get("action"), dict)
            and record["action"].get("kind") == "suspend_process"
        ) if record is not None else False
        self._btn_review.setEnabled(selected)
        self._btn_approve.setEnabled(selected and not terminal and not approved)
        self._btn_dismiss.setEnabled(selected and not terminal)
        self._btn_execute.setEnabled(executable)
        if approved and not executable:
            self._btn_execute.setToolTip(
                "This item is review-only and has no safely-bound process target."
            )
        else:
            self._btn_execute.setToolTip(
                "After approval, revalidate the signed event and exact process "
                "identity, then suspend it. A final confirmation is always required."
            )

    def _force_queue_refresh(self) -> None:
        self._queue_fingerprint = None
        self.refresh()

    def _review_selected(self) -> None:
        row = self.table.currentRow()
        record = self._record_for_row(row) if row >= 0 else None
        if record is None:
            self._status.setText("Select a SOAR item to review.")
            return
        _update_soar_queue_record(
            _soar_record_id(record), reviewed_at=time.time()
        )
        self._open_record(row, 0)

    def _approve_selected(self) -> None:
        record = self._selected_record()
        if record is None:
            self._status.setText("Select a SOAR item to approve.")
            return
        if self._terminal_record(record):
            self._status.setText("That request is already closed and cannot be approved.")
            return
        try:
            _soar_origin_event(record, self.bus)
        except Exception as exc:
            self._status.setText(
                f"Approval refused: authoritative origin evidence is unavailable ({exc})."
            )
            return
        action = record.get("action", {})
        action_text = (
            f"Suspend pid {action.get('pid')} (reversible)"
            if isinstance(action, dict) and action.get("kind") == "suspend_process"
            else "Review-only item; no executable target is available"
        )
        answer = QMessageBox.question(
            self.window(),
            "Approve SOAR Request",
            f"Approve this request for the current Angerona session?\n\n"
            f"Source: {record.get('origin_module', '')}\n"
            f"Proposed action: {action_text}\n\n"
            "Approval alone does not change the host. Execute remains a separate, "
            "confirmed action.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if answer != QMessageBox.Yes:
            return
        request_id = _soar_record_id(record)
        if not _update_soar_queue_record(
            request_id, status=_SOAR_APPROVED, approved_at=time.time()
        ):
            self._status.setText("Approval was not saved; no response was authorized.")
            return
        self._approved_requests[request_id] = _soar_authorization_digest(record)
        self._force_queue_refresh()
        if isinstance(action, dict) and action.get("kind") == "suspend_process":
            self._status.setText(
                "Approved for this session. Select Execute to revalidate and contain."
            )
        else:
            self._status.setText(
                "Reviewed and approved as evidence only; no executable target exists."
            )

    def _dismiss_selected(self) -> None:
        record = self._selected_record()
        if record is None:
            self._status.setText("Select a SOAR item to dismiss.")
            return
        if self._terminal_record(record):
            self._status.setText("That request is already closed.")
            return
        if QMessageBox.question(
            self.window(),
            "Reject / Dismiss SOAR Request",
            "Dismiss this request without changing the host? The audit history "
            "will remain available.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        ) != QMessageBox.Yes:
            return
        request_id = _soar_record_id(record)
        if _update_soar_queue_record(
            request_id, status=_SOAR_DISMISSED, dismissed_at=time.time()
        ):
            self._approved_requests.pop(request_id, None)
            self._force_queue_refresh()
            self._status.setText("Request dismissed; no host action was taken.")
        else:
            self._status.setText("Could not persist the dismissal; request remains open.")

    def _execute_selected(self) -> None:
        record = self._selected_record()
        if record is None:
            self._status.setText("Select an approved SOAR item to execute.")
            return
        request_id = _soar_record_id(record)
        approved_digest = (
            self._approved_requests[request_id]
            if request_id in self._approved_requests
            else None
        )
        if (
            approved_digest is None
            or approved_digest != _soar_authorization_digest(record)
        ):
            self._approved_requests.pop(request_id, None)
            self._status.setText(
                "Execute refused: the request changed or lacks current-session approval; "
                "review and approve it again."
            )
            return
        try:
            process, _origin = _soar_process_preflight(record, self.bus, self.manager)
            pid = int(process.pid)
            name = str(process.name() or "process")
        except Exception as exc:
            reason = str(exc)
            _update_soar_queue_record(
                request_id,
                status="FAILED — no host action taken",
                execution_error=reason[:1000],
            )
            self._approved_requests.pop(request_id, None)
            self._force_queue_refresh()
            self._status.setText(f"Execution refused safely: {reason}")
            return
        if QMessageBox.question(
            self.window(),
            "Execute Approved Containment",
            f"Suspend {name} (pid {pid}) now?\n\n"
            "Angerona will revalidate the signed alert, allowlist, protected-process "
            "rules, PID creation time, name, and executable again, then submit the "
            "exact suspension to Combat's durable intent/commit/undo journal.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        ) != QMessageBox.Yes:
            return
        # The confirmation dialog gives another local process time to replace a
        # mutable queue line. Re-read and compare the exact authorization digest
        # immediately before the response sink.
        fresh = next(
            (
                candidate
                for candidate in _read_soar_queue()
                if _soar_record_id(candidate) == request_id
            ),
            None,
        )
        if (
            fresh is None
            or approved_digest != _soar_authorization_digest(fresh)
        ):
            self._approved_requests.pop(request_id, None)
            self._force_queue_refresh()
            self._status.setText(
                "Execution refused: the approved request changed during confirmation."
            )
            return
        record = fresh
        try:
            result = _execute_approved_soar_record(record, self.bus, self.manager)
        except Exception as exc:
            reason = str(exc)
            _update_soar_queue_record(
                request_id,
                status="FAILED — no host action taken",
                execution_error=reason[:1000],
            )
            self._approved_requests.pop(request_id, None)
            self._force_queue_refresh()
            self._status.setText(f"Execution failed safely: {reason}")
            return
        updated = _update_soar_queue_record(
            request_id,
            status=_SOAR_SUBMITTED,
            submitted_at=time.time(),
            execution_result=result,
        )
        self._approved_requests.pop(request_id, None)
        self._force_queue_refresh()
        self._status.setText(
            result if updated else f"{result} Queue status update failed; bus audit retained."
        )

    def _open_record(self, row: int, _column: int) -> None:
        record = self._record_for_row(row)
        if record is None:
            return

        def _build() -> FuturisticDetailDialog:
            module = str(record.get("origin_module", "Unknown"))
            dialog = FuturisticDetailDialog(
                f"SOAR Evidence · {module}",
                "Operator-requested containment evidence. This view is read-only; "
                "AI consultation and response controls remain explicit actions.",
                "#f59e0b",
                self.window(),
                (820, 560),
            )
            dialog.add_metric("Severity", str(record.get("severity", "")), "#ef4444")
            dialog.add_metric("Status", str(record.get("status", "")), "#f59e0b")
            dialog.add_metric("Source", module, "#38bdf8")
            details = record.get("details", {}) or {}
            dialog.add_metric("PID", str(details.get("pid", "—")), "#c084fc")
            message = QLabel(str(record.get("message", "")))
            message.setWordWrap(True)
            message.setStyleSheet("font-size:14px; font-weight:700;")
            dialog.content.addWidget(message)
            evidence = QPlainTextEdit()
            evidence.setReadOnly(True)
            evidence.setPlainText(json.dumps(record, indent=2, default=str)[:40_000])
            dialog.content.addWidget(evidence, 1)
            dialog.footer_status.setText(
                "Persisted queue record · use Ask AI (selected) for live enrichment"
            )
            return dialog

        _show_nonmodal_from(self.table, _build, "#f59e0b")

    def _open_overview(self) -> None:
        def _build() -> FuturisticDetailDialog:
            items = _read_soar_queue()
            dialog = FuturisticDetailDialog(
                "SOAR Queue · Containment Review",
                "Newest-first operator Block requests. Queue entries are review "
                "artifacts—not proof that a containment action succeeded.",
                "#f59e0b",
                self.window(),
                (920, 620),
            )
            high = sum(
                1
                for record in items
                if str(record.get("severity", "")).upper()
                in {"HIGH", "CRITICAL"}
            )
            sources = {
                str(record.get("origin_module", ""))
                for record in items
                if record.get("origin_module")
            }
            dialog.add_metric("Queued", str(len(items)), "#f59e0b")
            dialog.add_metric("High / critical", str(high), "#ef4444")
            dialog.add_metric("Source modules", str(len(sources)), "#38bdf8")
            table = QTableWidget(0, 5)
            table.setHorizontalHeaderLabels(
                ["Time", "Source", "Severity", "Message", "Status"]
            )
            table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
            table.verticalHeader().setVisible(False)
            table.setEditTriggers(QTableWidget.NoEditTriggers)
            table.setSelectionBehavior(QTableWidget.SelectRows)
            for record in reversed(items[-300:]):
                table.insertRow(table.rowCount())
                current = table.rowCount() - 1
                when = time.strftime(
                    "%m-%d %H:%M:%S",
                    time.localtime(float(record.get("ts", 0.0))),
                )
                values = (
                    when,
                    str(record.get("origin_module", "")),
                    str(record.get("severity", "")),
                    str(record.get("message", "")),
                    str(record.get("status", "")),
                )
                for column, value in enumerate(values):
                    table.setItem(current, column, QTableWidgetItem(value))
            dialog.content.addWidget(table, 1)
            dialog.footer_status.setText(
                "Showing newest 300 persisted review records"
            )
            return dialog

        _show_nonmodal_from(self._title, _build, "#f59e0b")

    def _clear(self) -> bool:
        if not _read_soar_queue() and not _soar_queue_state_path().exists():
            self._status.setText("SOAR history is already empty.")
            return False
        answer = QMessageBox.question(
            self.window(),
            "Archive and clear SOAR history",
            "Move the current SOAR queue and review state into a recoverable "
            "archive, then clear the visible history?\n\nNo evidence is permanently "
            "deleted. Use Restore last clear before new queue items arrive, or "
            "recover the timestamped archive from the data directory.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if answer != QMessageBox.Yes:
            return False
        try:
            with _SOAR_QUEUE_CACHE_LOCK:
                archive = _archive_soar_history()
                _invalidate_soar_queue_cache()
        except Exception as exc:
            self._status.setText(f"SOAR history was not cleared: {exc}")
            QMessageBox.warning(
                self.window(),
                "SOAR archive failed",
                "The queue remains available unless the message below reports a "
                f"rollback failure.\n\n{exc}",
            )
            return False
        if archive is None:
            self._status.setText("SOAR history is already empty.")
            return False
        self._last_clear_archive = archive
        self._btn_restore_clear.setEnabled(True)
        self._approved_requests.clear()
        self._queue_fingerprint = None
        self.refresh()
        self._status.setText(f"SOAR history archived safely at {archive}")
        return True

    def _restore_last_clear(self) -> bool:
        archive = self._last_clear_archive
        if archive is None:
            self._status.setText("No same-session SOAR archive is available to restore.")
            return False
        answer = QMessageBox.question(
            self.window(),
            "Restore archived SOAR history",
            "Restore the most recently archived SOAR queue? This is refused if "
            "new queue history exists, so no newer evidence can be overwritten.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if answer != QMessageBox.Yes:
            return False
        try:
            with _SOAR_QUEUE_CACHE_LOCK:
                _restore_soar_archive(archive)
                _invalidate_soar_queue_cache()
        except Exception as exc:
            self._status.setText(f"SOAR archive was not restored: {exc}")
            QMessageBox.warning(
                self.window(), "SOAR restore failed", str(exc)
            )
            return False
        self._last_clear_archive = None
        self._btn_restore_clear.setEnabled(False)
        self._queue_fingerprint = None
        self.refresh()
        self._status.setText("The most recently archived SOAR history was restored.")
        return True

    # ── System context ────────────────────────────────────────────────────────
    def _gather_system_context(self) -> str:
        """Snapshot of system health at query time — sent to AI with every prompt."""
        lines = []
        try:
            lines.append(f"host={platform.node()} os={platform.version()[:60]}")
        except Exception:
            pass
        try:
            import psutil
            vm = psutil.virtual_memory()
            lines.append(f"ram_used={vm.percent}% cpu={psutil.cpu_percent(interval=0.15):.0f}%")
            lines.append(f"proc_count={len(psutil.pids())} conn_count={len(psutil.net_connections(kind='inet'))}")
            boot = time.time() - psutil.boot_time()
            h, m = divmod(int(boot // 60), 60)
            lines.append(f"uptime={h}h{m}m")
        except Exception:
            pass
        try:
            from angerona.core.net_interfaces import classify_interfaces, VIRTUAL_VPN
            ifaces = classify_interfaces()
            vpn = {n: v for n, v in ifaces.items() if v == VIRTUAL_VPN}
            lines.append(f"vpn_tunnels={'none' if not vpn else ','.join(vpn.keys())}")
        except Exception:
            pass
        # Angerona module health summary
        if self.manager:
            try:
                statuses = []
                for m in self.manager.modules:
                    h = getattr(m, "_health", None)
                    if h and h.get("pct", 100) < 50:
                        statuses.append(f"{m.name}:{h.get('pct')}%")
                if statuses:
                    lines.append(f"unhealthy_modules={';'.join(statuses)}")
            except Exception:
                pass
        # Threat level from bus
        if self.bus:
            try:
                recent = self.bus.recent(5)
                crits = sum(1 for e in recent if e.severity.value >= 4)
                lines.append(f"recent_crits_5min={crits}")
            except Exception:
                pass
        return " | ".join(lines)

    def _enrich(self, rec: dict) -> str:
        """Deep-enrich one queued item: process tree, file hash, connections, VPN."""
        d = rec.get("details", {}) or {}
        bits = []
        pid = d.get("pid")
        path = d.get("path") or d.get("image") or d.get("exe")

        # ── Process info ───────────────────────────────────────────────────
        try:
            import psutil
            if pid:
                p = psutil.Process(int(pid))
                with p.oneshot():
                    path = path or p.exe()
                    bits.append(f"proc={p.name()}(pid={pid})")
                    try:
                        parent = p.parent()
                        bits.append(f"parent={parent.name()}(pid={parent.pid})")
                    except Exception:
                        pass
                    # All TCP connections for this PID
                    try:
                        conns = p.connections(kind="inet")
                        remote_set = {
                            f"{c.raddr.ip}:{c.raddr.port}"
                            for c in conns if c.raddr
                        }
                        if remote_set:
                            bits.append(f"open_connections={','.join(sorted(remote_set)[:6])}")
                    except Exception:
                        pass
        except Exception:
            if pid:
                bits.append(f"pid={pid}")

        # ── File attributes + hash ─────────────────────────────────────────
        if path and os.path.exists(path):
            try:
                stt = os.stat(path)
                bits.append(f"path={path}")
                bits.append(
                    f"size={stt.st_size}B "
                    f"created={time.strftime('%Y-%m-%d', time.localtime(stt.st_ctime))} "
                    f"modified={time.strftime('%Y-%m-%d', time.localtime(stt.st_mtime))}"
                )
                # SHA-256 (skip files > 64 MB to stay fast in GUI thread)
                if stt.st_size < 64 * 1024 * 1024:
                    sha = hashlib.sha256()
                    with open(path, "rb") as fh:
                        for chunk in iter(lambda: fh.read(65536), b""):
                            sha.update(chunk)
                    bits.append(f"sha256={sha.hexdigest()}")
            except Exception:
                bits.append(f"path={path}")
            # Windows Authenticode / digital signature quick check
            if os.name == "nt":
                try:
                    out = _authenticode_status(path)
                    bits.append(f"signature={out}")
                except Exception:
                    pass

        # ── VPN / network ──────────────────────────────────────────────────
        try:
            from angerona.core.net_interfaces import classify_interfaces, VIRTUAL_VPN
            ifaces = classify_interfaces()
            vpn = [n for n, t in ifaces.items() if t == VIRTUAL_VPN]
            bits.append(f"vpn={'yes:' + ','.join(vpn) if vpn else 'no'}")
        except Exception:
            pass

        raddr = d.get("raddr") or d.get("remote_ip")
        if raddr:
            bits.append(f"remote={raddr}:{d.get('rport', '')}")

        return " | ".join(bits) if bits else "(no details)"

    # ── Right-click context menu ───────────────────────────────────────────────
    def _row_context_menu(self, pos) -> None:
        row = self.table.rowAt(pos.y())
        if row < 0:
            return
        self.table.setCurrentCell(row, 0)
        menu = QMenu(self)
        act_review = QAction("Review details", self)
        act_approve = QAction("Approve", self)
        act_execute = QAction("Execute approved containment", self)
        act_dismiss = QAction("Reject / Dismiss", self)
        act_ai   = QAction("🤖 Ask AI about this alert", self)
        act_copy = QAction("📋 Copy message", self)
        record = self._record_for_row(row)
        request_id = _soar_record_id(record) if record is not None else ""
        terminal = self._terminal_record(record) if record is not None else True
        act_approve.setEnabled(record is not None and not terminal)
        act_execute.setEnabled(request_id in self._approved_requests and not terminal)
        act_dismiss.setEnabled(record is not None and not terminal)
        menu.addAction(act_review)
        menu.addAction(act_approve)
        menu.addAction(act_execute)
        menu.addAction(act_dismiss)
        menu.addSeparator()
        menu.addAction(act_ai)
        menu.addAction(act_copy)
        chosen = menu.exec(self.table.viewport().mapToGlobal(pos))
        if chosen == act_review:
            self._review_selected()
        elif chosen == act_approve:
            self._approve_selected()
        elif chosen == act_execute:
            self._execute_selected()
        elif chosen == act_dismiss:
            self._dismiss_selected()
        elif chosen == act_ai:
            self._consult_ai_single(row)
        elif chosen == act_copy:
            item = self.table.item(row, 3)
            if item:
                QGuiApplication.clipboard().setText(item.text())

    def _consult_ai_selected(self) -> None:
        rows = {idx.row() for idx in self.table.selectedIndexes()}
        if not rows:
            self._status.setText("Select a row first, then click Ask AI (selected).")
            return
        self._consult_ai_single(sorted(rows)[0])

    def _consult_ai_single(self, row: int) -> None:
        """Deep-dive AI analysis of one specific SOAR queue item."""
        items = _read_soar_queue()
        # items are displayed newest-first; row 0 = items[-1]
        idx = len(items) - 1 - row
        if idx < 0 or idx >= len(items):
            self._status.setText("Row out of range — refresh and try again.")
            return
        try:
            from angerona.gui.ai_consult_dialog import AIConsultDialog
        except Exception as exc:
            self._status.setText(f"Consult AI unavailable: {exc}")
            return
        rec = items[idx]
        sys_ctx = self._gather_system_context()
        enriched = self._enrich(rec)
        prompt = (
            "You are a Tier-3 SOC analyst reviewing a single operator-flagged SOAR alert.\n"
            "Provide:\n"
            "  1. Likely intent / threat classification\n"
            "  2. Confidence (Low / Medium / High) with reasoning\n"
            "  3. Recommended immediate action (kill / suspend / isolate / allow / investigate)\n"
            "  4. Suggested next forensic steps\n"
            "  5. Any indicators of compromise to hunt for\n\n"
            f"=== Alert ===\n"
            f"Severity : {rec.get('severity','')}\n"
            f"Module   : {rec.get('origin_module','')}\n"
            f"Message  : {rec.get('message','')}\n\n"
            f"=== Enrichment ===\n{enriched}\n\n"
            f"=== System state at query time ===\n{sys_ctx}"
        )
        dlg = AIConsultDialog(
            f"SOAR — AI deep-dive: {rec.get('origin_module','')} alert",
            prompt,
            default_filename="soar_single_alert_ai.md",
            parent=self.window(),
        )
        _show_nonmodal(dlg)

    def _consult_ai(self) -> None:
        items = _read_soar_queue()
        if not items:
            self._status.setText("SOAR queue is empty.")
            return
        try:
            from angerona.gui.ai_consult_dialog import AIConsultDialog
        except Exception as exc:
            self._status.setText(f"Consult AI unavailable: {exc}")
            return
        sys_ctx = self._gather_system_context()
        lines = [
            "You are a Tier-3 SOC analyst reviewing operator-blocked containment items.\n"
            "For EACH item give:\n"
            "  • likely intent & threat classification\n"
            "  • confidence (Low/Medium/High)\n"
            "  • recommended action (kill/suspend/isolate/allow/investigate) + one-line why\n"
            "  • if multiple items share a source IP, PID, or file — call out the pattern.\n\n"
            f"=== System snapshot ===\n{sys_ctx}\n",
        ]
        for i, rec in enumerate(items[-25:], 1):
            lines.append(
                f"[{i}] {rec.get('severity','')} | {rec.get('origin_module','')} | "
                f"{rec.get('message','')}\n     {self._enrich(rec)}"
            )
        prompt = "\n\n".join(lines)
        dlg = AIConsultDialog("SOAR — AI review of the containment queue", prompt,
                              default_filename="soar_ai_review.md", parent=self.window())
        _show_nonmodal(dlg)


class _ClickableChip(QLabel):
    """A status chip that emits its module name when clicked."""
    clicked = Signal(str)

    def __init__(self, name: str) -> None:
        super().__init__()
        self._name = name
        self.setCursor(Qt.PointingHandCursor)

    def mousePressEvent(self, ev) -> None:  # noqa: N802 (Qt signature)
        if ev.button() == Qt.LeftButton:
            self.clicked.emit(self._name)
        super().mousePressEvent(ev)


class StatusStrip(QFrame):
    def __init__(self, manager, on_chip_click=None) -> None:
        super().__init__()
        self.setObjectName("StatusStrip")
        self.manager = manager
        self._on_chip_click = on_chip_click   # callback(name) → open module window
        self.setFixedHeight(52)
        self._lay = QHBoxLayout(self)
        self._lay.setContentsMargins(8, 4, 8, 4)
        self._lay.setSpacing(4)
        self._chips: dict[str, QLabel] = {}
        # Cache last visual state per chip: (health_state, pct_text)
        self._prev: dict[str, tuple[str, str]] = {}
        self._built_count = -1
        self._build()

    def _build(self) -> None:
        while self._lay.count():
            item = self._lay.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self._chips.clear()
        self._prev.clear()
        font = _chip_font()
        for name in sorted(self.manager.modules):
            chip = _ClickableChip(name)
            chip.setAlignment(Qt.AlignCenter)
            chip.setFont(font)
            chip.setMinimumWidth(0)
            if self._on_chip_click is not None:
                chip.clicked.connect(self._on_chip_click)
            self._chips[name] = chip
            self._lay.addWidget(chip, 1)
        self._built_count = len(self.manager.modules)

    def refresh(self) -> None:
        if self._built_count != len(self.manager.modules):
            self._build()
            return
        for name, chip in self._chips.items():
            mod = self.manager.modules.get(name)
            if not mod:
                continue
            state = mod.health_state
            pct_text = (f"{mod.health}%" if mod.status == "running"
                        else mod.status[:3].upper())
            key = (state, pct_text)
            if self._prev.get(name) == key:
                continue                     # nothing changed — skip repaint
            self._prev[name] = key
            color = HEALTH_COLOR.get(state, "#6b7280")
            code  = _short_code(mod)
            chip.setText(f"{code}\n{pct_text}")
            chip.setToolTip(
                f"{mod.name}  {pct_text}"
                + (f"  [{mod.health_note}]" if mod.health_note else "")
            )
            chip.setStyleSheet(
                f"background:{color}1a; color:{color};"
                f"border:1px solid {color}55; border-radius:8px;"
                f"padding:1px 3px; font-weight:700;"
            )


# ── Resource-intensity strip ──────────────────────────────────────────────────
# A second row of chips, aligned under the StatusStrip, showing how resource-hungry
# each module currently is (0–100%). 0 = not running (red); low = green/good; the
# busier a module is, the higher the % and the more amber→red it becomes. Since
# modules are threads inside one process (no per-thread RSS in Python), intensity
# is a heuristic: a static heaviness weight for known heavy scanners + a live bonus
# from how many events the module has emitted recently (real, changing activity).
_HEAVY_MODULES = {
    "Process Monitor", "Network Monitor", "Memory Time-Machine",
    "Memory Injection Scanner", "YARA Scanner", "Packet Sniffer",
    "Ransomware Heuristics", "Sysmon Event Bridge", "ETW Core Listener",
    "Upstream Threat Intel Sync", "API Patch / Anti-Blinding Detector",
    "Persistence Sweep", "Network Protocol Deep Decoder", "WLAN Monitor",
    "ARP Watchdog", "AMSI Bridge", "AV Telemetry Bridge",
    "Data Provenance Graph", "Hardware-Rooted Integrity",
}


def _intensity_color(pct: int, running: bool) -> str:
    if not running or pct <= 0:
        return "#ef4444"          # off → red
    if pct < 34:
        return "#22c55e"          # low → green/good
    if pct < 67:
        return "#f59e0b"          # medium → amber
    return "#f97316"              # heavy → orange-red


class ResourceStrip(QFrame):
    """Per-module resource-intensity chips (0–100%), aligned under the StatusStrip."""

    def __init__(self, manager, bus) -> None:
        super().__init__()
        self.setObjectName("ResourceStrip")
        self.manager = manager
        self.bus = bus
        self.setFixedHeight(46)
        self._lay = QHBoxLayout(self)
        self._lay.setContentsMargins(8, 2, 8, 4)
        self._lay.setSpacing(4)
        self._chips: dict[str, QLabel] = {}
        self._prev: dict[str, tuple[int, bool]] = {}
        self._built_count = -1
        self._build()

    def _build(self) -> None:
        while self._lay.count():
            item = self._lay.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self._chips.clear()
        self._prev.clear()
        font = _chip_font()
        for name in sorted(self.manager.modules):
            chip = _ClickableChip(name)
            chip.setAlignment(Qt.AlignCenter)
            chip.setFont(font)
            chip.clicked.connect(self._open_resource)
            self._chips[name] = chip
            self._lay.addWidget(chip, 1)
        self._built_count = len(self.manager.modules)

    def _intensity(self, name: str, mod, activity: dict) -> int:
        if getattr(mod, "status", "") != "running":
            return 0
        base = 42 if name in _HEAVY_MODULES else 16
        bonus = min(52, activity.get(name, 0) * 8)
        return max(1, min(100, base + bonus))

    def refresh(self) -> None:
        if self._built_count != len(self.manager.modules):
            self._build()
            return
        # Live activity: count recent events per module (cheap, changes over time).
        activity: dict[str, int] = {}
        try:
            for e in self.bus.recent(120):
                activity[e.module] = activity.get(e.module, 0) + 1
        except Exception:
            pass
        for name, chip in self._chips.items():
            mod = self.manager.modules.get(name)
            if not mod:
                continue
            running = getattr(mod, "status", "") == "running"
            pct = self._intensity(name, mod, activity)
            key = (pct, running)
            if self._prev.get(name) == key:
                continue
            self._prev[name] = key
            color = _intensity_color(pct, running)
            chip.setText(f"{_short_code(mod)}\n{pct}%")
            chip.setToolTip(f"{mod.name} — resource intensity {pct}%"
                            + ("" if running else " (stopped)"))
            chip.setStyleSheet(
                f"background:{color}1a; color:{color};"
                f"border:1px solid {color}55; border-radius:8px;"
                f"padding:1px 3px; font-weight:700;")

    def _resource_snapshot(self, name: str) -> dict:
        module = self.manager.modules.get(name)
        if module is None:
            return {}
        recent = []
        activity: dict[str, int] = {}
        try:
            all_recent = self.bus.recent(120)
            for event in all_recent:
                activity[event.module] = activity.get(event.module, 0) + 1
            for event in reversed(all_recent):
                if event.module == name and len(recent) < 25:
                    recent.append(event)
        except Exception:
            pass
        return {
            "intensity": self._intensity(name, module, activity),
            "health": int(getattr(module, "health", 0)),
            "status": str(getattr(module, "status", "unknown")),
            "events": recent,
        }

    def _open_resource(self, name: str) -> None:
        source = self._chips.get(name)
        if source is None:
            return
        _show_nonmodal_from(
            source,
            lambda: ModuleResourceDialog(
                name, self._resource_snapshot, self.window()
            ),
            "#fb923c",
        )


# ── Command console (interactive prompt + AI) ────────────────────────────────
class CommandConsolePanel(QFrame):
    """Embedded console — now ARIA's home. Type an IR command (try 'help') or just
    talk to ARIA in plain language; ARIA's replies stream in live. Everything runs
    on a background thread so AI calls never freeze the UI. This is the single ARIA
    prompt bar: the orb HUD sits beside it and the Live Alerts stay in their own
    panel so you can watch alerts and talk to ARIA at the same time."""
    _result = Signal(str)
    _token = Signal(str)     # one streamed ARIA chunk (live typing effect)

    def __init__(self, backend) -> None:
        super().__init__()
        self.setObjectName("Panel")
        self.backend = backend
        self._stream_ask = None          # optional fn(text, on_token)->str (ARIA)
        aria_enabled = bool(getattr(getattr(backend, "config", None), "aria_enabled", False))
        self._prompt_label = "ARIA#" if aria_enabled else "IR#"
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 12, 14, 12)
        self._title = _ClickableSection(
            ("ARIA Console  —  ask ARIA in plain language, or type 'help' for commands"
             if aria_enabled else
             "Incident Response Console  —  ARIA is optional and currently off"),
            "Open the expanded ARIA and guarded-command operations deck.",
        )
        self._title.clicked.connect(self._open_detail)
        lay.addWidget(self._title)

        self.out = QPlainTextEdit()
        self.out.setReadOnly(True)
        self.out.setMaximumBlockCount(4000)
        self.out.setFont(QFont("Fira Code", 10))
        self.out.setStyleSheet("background:#0b0d12; color:#cbd5e1; border:1px solid #232a36; border-radius:8px;")
        lay.addWidget(self.out)

        row = QHBoxLayout()
        self.spin = QLabel("")
        # No fixed min-width (was 150px) so the prompt bar can shrink; the label
        # sizes to its transient "WORKING…" text only while a command runs.
        self.spin.setStyleSheet("color:#1f9cff; font-weight:800; font-size:14px; "
                                "letter-spacing:1px;")
        row.addWidget(self.spin)
        prompt = QLabel(self._prompt_label)
        prompt.setStyleSheet("color:#22c55e; font-weight:700; font-family:Consolas;")
        row.addWidget(prompt)
        self.inp = QLineEdit()
        self.inp.setPlaceholderText(
            "what's my posture?   ·   ps   ·   kill 1234   ·   trust my running apps"
            if aria_enabled else
            "help   ·   ps   ·   modules   ·   threat   ·   enable ARIA in Settings > ARIA"
        )
        self.inp.setStyleSheet("font-family:Consolas;")
        self.inp.returnPressed.connect(self._submit)
        row.addWidget(self.inp)
        lay.addLayout(row)

        # Spinner (braille dots) shown while a command / self-test runs.
        self._busy = 0
        self._frames = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
        self._frame = 0
        self._spin_timer = QTimer(self)
        self._spin_timer.timeout.connect(self._tick)

        self._result.connect(self._on_result)
        self._token.connect(self._on_token)
        self._append(
            "ARIA console ready — ask me anything, or type 'help' for commands."
            if aria_enabled else
            "Incident-response console ready. ARIA, voice, awareness, and hand controls "
            "are off; enable them explicitly in Settings > ARIA."
        )

    def set_stream_ask(self, fn) -> None:
        """Wire ARIA's streaming brain. fn(text, on_token)->str; free-form input
        (anything that isn't a known command) streams through it token-by-token."""
        self._stream_ask = fn

    def _submit(self) -> None:
        text = self.inp.text().strip()
        self.inp.clear()
        if not text:
            return
        if text.lower() == "clear":
            self.out.clear()
            return
        self._append(f"{self._prompt_label} {text}")
        self._start_busy()
        threading.Thread(target=self._work, args=(text,), daemon=True).start()

    def run_command(self, text: str) -> None:
        """Run a command programmatically (e.g. from a toolbar button)."""
        self._append(f"{self._prompt_label} {text}")
        self._start_busy()
        threading.Thread(target=self._work, args=(text,), daemon=True).start()

    def _work(self, text: str) -> None:
        # Free-form text → stream through ARIA if wired; real commands run normally.
        try:
            if self._stream_ask is not None and not self.backend.is_command(text):
                emitted = {"n": 0}

                def _tok(chunk: str) -> None:
                    if chunk:
                        emitted["n"] += 1
                        self._token.emit(chunk)

                self._token.emit("ARIA: ")
                ans = str(self._stream_ask(text, _tok))
                if emitted["n"] == 0:        # instant / non-streaming answer
                    self._token.emit(ans)
                self._result.emit("")         # finalize turn (newline + end busy)
                return
            result = self.backend.run(text)
        except Exception as exc:
            result = f"error: {exc}"
        self._result.emit(result)

    def _on_token(self, chunk: str) -> None:
        """Append one streamed ARIA chunk inline at the end (GUI thread)."""
        self.out.moveCursor(QTextCursor.End)
        self.out.insertPlainText(chunk)
        self.out.moveCursor(QTextCursor.End)
        self.out.verticalScrollBar().setValue(self.out.verticalScrollBar().maximum())

    def _on_result(self, text: str) -> None:
        self._append(text)
        self._end_busy()

    # ── Spinner ──────────────────────────────────────────────────────────────
    def _start_busy(self) -> None:
        self._busy += 1
        if not self._spin_timer.isActive():
            self._spin_timer.start(90)

    def _end_busy(self) -> None:
        self._busy = max(0, self._busy - 1)
        if self._busy == 0:
            self._spin_timer.stop()
            self.spin.setText("")

    def _tick(self) -> None:
        self._frame = (self._frame + 1) % len(self._frames)
        self.spin.setText(f"{self._frames[self._frame]}  WORKING…")

    def _append(self, text: str) -> None:
        if text:
            self.out.appendPlainText(text)
        self.out.verticalScrollBar().setValue(self.out.verticalScrollBar().maximum())

    def refresh(self) -> None:
        pass  # console is event-driven; nothing to poll

    def _open_detail(self) -> None:
        _show_nonmodal_from(
            self._title,
            lambda: ConsoleDetailDialog(self, self.window()),
            "#2dd4bf",
        )


# ── Shark Attack — live offense monitor (non-modal) ───────────────────────────
class SharkMonitorDialog(QDialog):
    """Live narration window for a running Shark Attack drill — what it's
    doing and where, as it happens. Deliberately non-modal: it's meant to sit
    next to the main dashboard so you can watch the OFFENSE narration here
    and the DEFENSE side (Alerts panel, Modules table, status strip) react
    live in the main window at the same time. Closing this window does not
    stop the drill — it only hides the narration; the AAR review window
    still opens automatically when the run finishes."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Live Offense Monitor")
        self.setMinimumSize(980, 520)
        if parent:
            self.setStyleSheet(parent.styleSheet())
        # Non-modal + not auto-deleted on close, so MainWindow can keep
        # reusing/showing the same instance across multiple drills.
        self.setWindowModality(Qt.NonModal)
        self.setAttribute(Qt.WA_DeleteOnClose, False)
        lay = QVBoxLayout(self)

        from angerona.gui.animations import RunSpinner
        title = QLabel("\U0001F988  Offense — a live view of what the drill is doing")
        title.setObjectName("PageTitle")
        self.run_spinner = RunSpinner()
        trow = QHBoxLayout()
        trow.addWidget(title)
        trow.addStretch(1)
        trow.addWidget(self.run_spinner)
        lay.addLayout(trow)
        hint = QLabel("This window narrates the simulated attack as it unfolds. Keep the "
                     "main dashboard in view — its Alerts panel, Modules table, and status "
                     "strip show the defense reacting in real time.")
        hint.setWordWrap(True)
        hint.setStyleSheet("color:#9aa4b2;")
        lay.addWidget(hint)

        # ── Flight Instructor Mode — Cyber Security Academy's live AI coach ──
        # Purely additive: when off, this dialog behaves exactly as before
        # (raw engine narration only). When on, MainWindow also streams a
        # short AI explanation of each stage into this same log, using the
        # same append() path — so it's one interleaved, timestamped feed.
        fi_row = QHBoxLayout()
        self.fi_check = QCheckBox("\U0001F393 Flight Instructor Mode — AI coaching narration")
        self.fi_style = QComboBox()
        self.fi_style.addItems(["analogy", "technical"])
        self.fi_style.setToolTip("Explanation register: plain-language analogy, or precise technical detail.")
        fi_row.addWidget(self.fi_check)
        fi_row.addWidget(self.fi_style)
        fi_row.addStretch(1)
        lay.addLayout(fi_row)

        panes = QHBoxLayout()
        # Left pane: the OFFENSE — the test running and its results.
        left = QVBoxLayout()
        lh = QLabel("\U0001F5E1️  OFFENSE — test run & results")
        lh.setStyleSheet("color:#f87171; font-weight:700;")
        left.addWidget(lh)
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumBlockCount(4000)
        self.log.setFont(QFont("Fira Code", 10))
        self.log.setStyleSheet(
            "background:#0b0d12; color:#7dd3fc; border:1px solid #232a36; border-radius:8px;")
        left.addWidget(self.log)
        panes.addLayout(left, 1)
        # Right pane: the FLIGHT INSTRUCTOR — analogy/technical coaching per step.
        right = QVBoxLayout()
        rh = QLabel("\U0001F393  FLIGHT INSTRUCTOR — what it's doing & why")
        rh.setStyleSheet("color:#a78bfa; font-weight:700;")
        right.addWidget(rh)
        self.instructor = QPlainTextEdit()
        self.instructor.setReadOnly(True)
        self.instructor.setMaximumBlockCount(4000)
        self.instructor.setFont(QFont("Fira Code", 10))
        self.instructor.setStyleSheet(
            "background:#0b0d12; color:#c4b5fd; border:1px solid #232a36; border-radius:8px;")
        self.instructor.setPlaceholderText(
            "Enable 'Flight Instructor Mode' above to stream a plain-language ANALOGY or a "
            "precise TECHNICAL explanation of each step here (pick the register in the dropdown).")
        right.addWidget(self.instructor)
        panes.addLayout(right, 1)
        lay.addLayout(panes)

        row = QHBoxLayout()
        row.addStretch(1)
        close = QPushButton("Close (drill keeps running)")
        close.clicked.connect(self.hide)
        row.addWidget(close)
        lay.addLayout(row)

    def reset(self) -> None:
        self.log.clear()
        self.instructor.clear()
        self.run_spinner.stop()

    def begin_run(self, estimated_seconds: float) -> None:
        """Start the live progress wheel for a drill of roughly this duration.
        The bar eases toward ~95% over the estimate, then finish_run() completes it."""
        self.run_spinner.begin_estimated(estimated_seconds, "Simulation running")

    def finish_run(self) -> None:
        """Snap the wheel to a green 100% — the drill has finished."""
        self.run_spinner.finish("Simulation complete")

    def append(self, line: str) -> None:
        ts = time.strftime("%H:%M:%S")
        self.log.appendPlainText(f"[{ts}] {line}")
        self.log.verticalScrollBar().setValue(self.log.verticalScrollBar().maximum())

    def append_instructor(self, line: str) -> None:
        ts = time.strftime("%H:%M:%S")
        self.instructor.appendPlainText(f"[{ts}] {line}")
        self.instructor.verticalScrollBar().setValue(self.instructor.verticalScrollBar().maximum())


# ── Shark Attack — After-Action Report (dialog) ───────────────────────────────


def _load_verified_aar_text(
    data_dir: Path,
    *,
    basename: str,
    expected_kind: str,
    expected_run_id: str = "",
    expected_report_sha256: str = "",
    expected_head_sha256: str = "",
    expected_sequence: int = 0,
) -> str:
    """Load one identity-held AAR pair bound to the review window.

    A valid older HMAC is still valid history, not permission to replace the
    newer report already opened by this dialog.  The expected run and JSON-byte
    digest therefore become immutable refresh high-water marks.
    """
    from angerona.core import report_attest

    root = Path(data_dir).resolve(strict=False)
    json_path = root / f"{basename}.json"
    text_path = root / f"{basename}.txt"
    head_path = root / f"{basename}.head.json"

    def read_member(path: Path) -> bytes:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor: int | None = None
        try:
            descriptor = os.open(path, flags)
            before = os.fstat(descriptor)
            path_stat = path.stat(follow_symlinks=False)
            if (
                not stat.S_ISREG(before.st_mode)
                or not stat.S_ISREG(path_stat.st_mode)
                or bool(getattr(before, "st_file_attributes", 0) & 0x400)
                or bool(getattr(path_stat, "st_file_attributes", 0) & 0x400)
                or int(getattr(before, "st_nlink", 1)) != 1
                or int(getattr(path_stat, "st_nlink", 1)) != 1
                or (before.st_dev, before.st_ino)
                != (path_stat.st_dev, path_stat.st_ino)
                or not 0 < before.st_size <= 16 * 1024 * 1024
            ):
                raise ValueError(
                    f"persisted report file has an unsafe identity: {path.name}"
                )
            remaining = int(before.st_size)
            chunks: list[bytes] = []
            while remaining:
                chunk = os.read(descriptor, min(128 * 1024, remaining))
                if not chunk:
                    raise ValueError(
                        f"persisted report file changed during read: {path.name}"
                    )
                chunks.append(chunk)
                remaining -= len(chunk)
            after = os.fstat(descriptor)
            final_path = path.stat(follow_symlinks=False)
            if (
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                or (after.st_dev, after.st_ino)
                != (final_path.st_dev, final_path.st_ino)
                or int(getattr(after, "st_nlink", 1)) != 1
                or int(getattr(final_path, "st_nlink", 1)) != 1
            ):
                raise ValueError(
                    f"persisted report file identity changed during read: {path.name}"
                )
            return b"".join(chunks)
        except OSError as exc:
            raise ValueError(
                f"authenticated persisted report file is unavailable: {path.name}"
            ) from exc
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    try:
        raw_json = read_member(json_path)
        payload = json.loads(raw_json.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("persisted report metadata is unreadable") from exc
    if not isinstance(payload, dict) or report_attest.verify(payload) != "ok":
        raise ValueError("persisted report HMAC is missing or invalid")
    if (
        payload.get("report_basename") != basename
        or payload.get("report_kind") != expected_kind
        or not str(payload.get("run_id") or "").strip()
    ):
        raise ValueError("persisted report identity does not match this review window")
    run_id = str(payload.get("run_id") or "")
    raw_json_digest = hashlib.sha256(raw_json).hexdigest()
    if expected_run_id and not hmac.compare_digest(run_id, str(expected_run_id)):
        raise ValueError("persisted report run is older or different from this review window")
    if expected_report_sha256 and (
        not re.fullmatch(r"[0-9a-f]{64}", str(expected_report_sha256).casefold())
        or not hmac.compare_digest(
            raw_json_digest, str(expected_report_sha256).casefold()
        )
    ):
        raise ValueError("persisted report metadata was replaced after this review opened")
    if head_path.exists() or expected_head_sha256:
        try:
            raw_head = read_member(head_path)
            head = json.loads(raw_head.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("persisted report head is unreadable") from exc
        if not isinstance(head, dict) or report_attest.verify(head) != "ok":
            raise ValueError("persisted report head HMAC is missing or invalid")
        if (
            head.get("schema") not in {
                "angerona.aar-report-head.v1",
                "angerona.aar-report-head.v2",
            }
            or head.get("report_basename") != basename
            or head.get("report_kind") != expected_kind
            or head.get("run_id") != run_id
            or head.get("report_json_sha256") != raw_json_digest
        ):
            raise ValueError("persisted report pair does not match its authenticated head")
        head_digest = hashlib.sha256(raw_head).hexdigest()
        if expected_head_sha256 and not hmac.compare_digest(
            head_digest, str(expected_head_sha256).casefold()
        ):
            raise ValueError("persisted report head was replaced after this review opened")
        if expected_sequence and int(head.get("sequence", 0)) != int(expected_sequence):
            raise ValueError("persisted report head sequence changed after review opened")
    raw_text = read_member(text_path)
    supplied_digest = str(payload.get("report_text_sha256") or "")
    actual_digest = hashlib.sha256(raw_text).hexdigest()
    if not re.fullmatch(r"[0-9a-f]{64}", supplied_digest) or not hmac.compare_digest(
        supplied_digest,
        actual_digest,
    ):
        raise ValueError("persisted report text does not match its authenticated metadata")
    try:
        return raw_text.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("persisted report text is not valid UTF-8") from exc


class AARDialog(QDialog):
    """Read-only review window for a completed Shark Attack drill. Shows the
    same formatted report that's printed to the terminal (see
    angerona.shark.aar_report), with a button to re-run the comparison —
    A refresh re-renders already-recorded evidence; a fresh drill is required
    to test detector coverage after the originating evidence was cleaned."""

    _fix_done = Signal(str)
    _apply_done = Signal(str)
    _fix_progress = Signal(int, str)

    def __init__(self, data_dir, parent=None, on_attempt_fix=None, on_apply=None,
                 on_clean=None, redteam=False, report_binding=None) -> None:
        super().__init__(parent)
        self.data_dir = data_dir
        self._on_attempt_fix = on_attempt_fix
        self._on_apply = on_apply
        self._on_clean = on_clean
        self._redteam = bool(redteam)
        self._report_binding = report_binding
        initial_binding = report_binding if isinstance(report_binding, dict) else {}
        self._expected_report_run_id = str(initial_binding.get("run_id") or "")
        self._expected_report_sha256 = str(initial_binding.get("sha256") or "")
        self._expected_head_sha256 = str(
            initial_binding.get("head_sha256") or ""
        )
        self._expected_report_sequence = int(initial_binding.get("sequence") or 0)
        self._fix_done.connect(self._show_fix_result)
        self._apply_done.connect(lambda t: self.body.appendPlainText("\n" + t))
        self._fix_progress.connect(self._on_fix_progress)
        self.setWindowTitle("Shark Attack — After-Action Report")
        self.setMinimumSize(760, 600)
        if parent:
            self.setStyleSheet(parent.styleSheet())
        lay = QVBoxLayout(self)

        title = QLabel("\U0001F988  Shark Attack — After-Action Report")
        title.setObjectName("PageTitle")
        lay.addWidget(title)

        self.body = QPlainTextEdit()
        self.body.setReadOnly(True)
        self.body.setFont(QFont("Fira Code", 10))
        self.body.setStyleSheet(
            "background:#0b0d12; color:#cbd5e1; border:1px solid #232a36; border-radius:8px;")
        lay.addWidget(self.body)

        row = QHBoxLayout()
        refresh = QPushButton(
            "Reload verified report" if self._redteam else "Re-run report"
        )
        refresh.setObjectName("Primary")
        refresh.clicked.connect(self.refresh)
        row.addWidget(refresh)
        row.addStretch(1)
        self._fix_btn = QPushButton("\U0001F6E0  " +
                                    ("Apply Practice Fix" if self._redteam else "Attempt Fix"))
        self._fix_btn.setObjectName("Primary")
        self._fix_btn.setToolTip(
            "Install reviewed detector candidates and clean inert markers. Findings stay open "
            "until a fresh drill proves the fixes end to end." if self._redteam else
            "Ask the local AI to generate a remediation for each open weakness, then "
            "optionally apply it (with your confirmation).")
        self._fix_btn.clicked.connect(self._attempt_fix)
        row.addWidget(self._fix_btn)
        from angerona.gui.animations import RunSpinner
        self._fix_spinner = RunSpinner()
        row.addWidget(self._fix_spinner)
        self._test_fix_btn = QPushButton("✓  Test Fix Again")
        self._test_fix_btn.setToolTip(
            "Replay the exact inert positive and benign negative controls through the "
            "installed detector, recorder, SOAR response, and cleanup checks."
        )
        self._test_fix_btn.clicked.connect(self._attempt_fix)
        self._test_fix_btn.hide()
        row.addWidget(self._test_fix_btn)
        self._source_btn = QPushButton("</>  Open Fix Source")
        self._source_btn.setToolTip(
            "Open the exact Purple Remediation Guard implementation in Angerona's "
            "syntax-checked Live-Fire Sandbox."
        )
        self._source_btn.clicked.connect(self._open_fix_source)
        self._source_btn.hide()
        row.addWidget(self._source_btn)
        row.addStretch(1)
        close = QPushButton("\U0001F9F9  Clean & Close")
        close.setToolTip("Erase every benign drill marker / persistence-marker file used during "
                         "the simulation, then close this report.")
        close.clicked.connect(self._clean_and_close)
        row.addWidget(close)
        lay.addLayout(row)

    def _clean_and_close(self) -> None:
        """Sweep the drill's marker files, then close the report."""
        if self._on_clean:
            try:
                n = self._on_clean()
                if isinstance(n, int):
                    self.body.appendPlainText(
                        f"\n\U0001F9F9  Cleaned {n} drill marker/file(s). Closing.")
            except Exception:
                pass
        self.accept()

    @staticmethod
    def _safe(fn):
        try:
            return fn()
        except Exception as exc:
            return f"[error] {exc}"

    def _attempt_fix(self) -> None:
        if not self._on_attempt_fix:
            self.body.appendPlainText("\n[Attempt Fix] Posture Hardening module not available.")
            return
        self._fix_btn.setEnabled(False)
        self._test_fix_btn.setEnabled(False)
        if self._redteam:
            # A prior receipt does not authorize controls during a new retest.
            # Hide them until this run produces its own green verification.
            self._test_fix_btn.hide()
            self._source_btn.hide()
            self.body.appendPlainText("\n[Purple remediation] Building reviewed detector "
                                      "candidates, then running positive/negative controls…")
            self._fix_spinner.begin_estimated(8.0, "Practice fix")
        else:
            self.body.appendPlainText("\n[Attempt Fix] Asking the local AI for a remediation "
                                      "(temperature 0) — this may take a few seconds…")
        import threading
        def work():
            if self._redteam:
                result = self._safe(
                    lambda: self._on_attempt_fix(self._fix_progress.emit)
                )
            else:
                result = self._safe(self._on_attempt_fix)
            self._fix_done.emit(result)

        threading.Thread(target=work, daemon=True).start()

    def _on_fix_progress(self, percent: int, text: str) -> None:
        self._fix_spinner.set_text(text)
        self._fix_spinner.set_pct(percent)

    def _show_fix_result(self, text: str) -> None:
        self._fix_btn.setEnabled(True)
        self._test_fix_btn.setEnabled(True)
        verified = "[PRACTICE FIX VERIFIED]" in text
        if self._redteam:
            if verified:
                # The practice receipt updates the lifecycle state, so re-render
                # immediately instead of leaving the operator staring at the
                # pre-fix 0% score.  Append the proof summary after the refreshed
                # report so neither result is lost.
                self.refresh()
                self.body.appendPlainText("\n\n" + text)
                self._fix_spinner.succeed("Practice fix verified")
                # Only reveal retest/source inspection after signed green proof.
                self._test_fix_btn.show()
                self._source_btn.show()
            else:
                self.body.appendPlainText("\n" + text)
                self._fix_spinner.stop()
                self._test_fix_btn.hide()
                self._source_btn.hide()
        else:
            self.body.appendPlainText("\n" + text)
        # Only offer to apply when a remediation was actually generated. If the
        # posture is clean (no open weaknesses), there is nothing to run.
        if not self._on_apply or "[vetted plan ready]" not in text.lower():
            return
        from PySide6.QtWidgets import QMessageBox
        if QMessageBox.question(
                self, "Apply vetted remediation",
                "Apply the reviewed typed remediation plan now? Local-AI advisory text "
                "will remain inert and will not execute.",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No) == QMessageBox.Yes:
            self.body.appendPlainText("\n[Apply] Running remediation…")
            import threading
            threading.Thread(target=lambda: self._apply_done.emit(self._safe(self._on_apply)),
                             daemon=True).start()

    def _open_fix_source(self) -> None:
        """Open the exact detector source, not a copied report or generated script."""
        try:
            parent = self.parent()
            from angerona.gui.sandbox_editor import launch_sandbox_editor

            self._sandbox = launch_sandbox_editor(
                parent.manager,
                parent.bus,
                parent=parent,
                preselect="Purple Remediation Guard",
            )
        except Exception as exc:
            QMessageBox.warning(self, "Sandbox", f"Could not open fix source: {exc}")

    def set_text(self, text: str) -> None:
        self.body.setPlainText(text)

    def refresh(self) -> None:
        self.body.setPlainText(
            "Loading the authenticated persisted report…"
            if self._redteam
            else "Re-evaluating against the flight-recorder ledger…"
        )
        try:
            if self._redteam:
                # The one-use Red Team validation lease is deliberately revoked
                # after the original AAR. Post-lease refresh must never rescore
                # ledger rows without those live authorities; reload the text
                # whose digest is covered by the attested JSON instead.
                binding = (
                    self._report_binding
                    if isinstance(self._report_binding, dict)
                    else {}
                )
                expected_run_id = str(
                    getattr(self, "_expected_report_run_id", "")
                    or binding.get("run_id")
                    or ""
                )
                expected_report_sha256 = str(
                    getattr(self, "_expected_report_sha256", "")
                    or binding.get("sha256")
                    or ""
                )
                expected_head_sha256 = str(
                    getattr(self, "_expected_head_sha256", "")
                    or binding.get("head_sha256")
                    or ""
                )
                expected_sequence = int(
                    getattr(self, "_expected_report_sequence", 0)
                    or binding.get("sequence")
                    or 0
                )
                text = _load_verified_aar_text(
                    self.data_dir,
                    basename="redteam_aar",
                    expected_kind="red_team",
                    expected_run_id=expected_run_id,
                    expected_report_sha256=expected_report_sha256,
                    expected_head_sha256=expected_head_sha256,
                    expected_sequence=expected_sequence,
                )
            else:
                from angerona.shark.aar_report import generate_aar

                text = generate_aar(self.data_dir, settle_seconds=0)
        except Exception as exc:
            text = (
                f"Could not load authenticated report: {exc}"
                if self._redteam
                else f"Could not generate report: {exc}"
            )
        self.body.setPlainText(text)
        if self._report_binding is not None and not text.startswith("Could not"):
            path = Path(self.data_dir) / (
                "redteam_aar.json" if self._redteam else "shark_aar.json"
            )
            try:
                raw = path.read_bytes()
                payload = json.loads(raw.decode("utf-8"))
                current_run_id = str(payload.get("run_id") or "")
                current_sha256 = hashlib.sha256(raw).hexdigest()
                head_path = Path(self.data_dir) / "redteam_aar.head.json"
                current_head_sha256 = ""
                current_sequence = 0
                if head_path.is_file() and not head_path.is_symlink():
                    raw_head = head_path.read_bytes()
                    head_payload = json.loads(raw_head.decode("utf-8"))
                    current_head_sha256 = hashlib.sha256(raw_head).hexdigest()
                    current_sequence = int(head_payload.get("sequence", 0))
                pinned_run_id = str(
                    getattr(self, "_expected_report_run_id", "") or ""
                )
                pinned_sha256 = str(
                    getattr(self, "_expected_report_sha256", "") or ""
                )
                pinned_head_sha256 = str(
                    getattr(self, "_expected_head_sha256", "") or ""
                )
                pinned_sequence = int(
                    getattr(self, "_expected_report_sequence", 0) or 0
                )
                if not pinned_run_id and not pinned_sha256:
                    # A compatibility-created dialog without an opening
                    # binding may establish it exactly once. It is immutable
                    # after this successful authenticated load.
                    self._expected_report_run_id = current_run_id
                    self._expected_report_sha256 = current_sha256
                    self._expected_head_sha256 = current_head_sha256
                    self._expected_report_sequence = current_sequence
                    self._report_binding.update({
                        "run_id": current_run_id,
                        "sha256": current_sha256,
                        "error": "",
                        "head_sha256": current_head_sha256,
                        "sequence": current_sequence,
                    })
                elif (
                    current_run_id != pinned_run_id
                    or not hmac.compare_digest(current_sha256, pinned_sha256)
                    or (
                        pinned_head_sha256
                        and not hmac.compare_digest(
                            current_head_sha256, pinned_head_sha256
                        )
                    )
                    or (pinned_sequence and current_sequence != pinned_sequence)
                ):
                    raise ValueError(
                        "persisted report changed after the review binding was established"
                    )
                else:
                    self._report_binding["error"] = ""
            except (OSError, UnicodeDecodeError, ValueError, TypeError) as exc:
                self._report_binding["error"] = str(exc)



# ── Settings dialog ───────────────────────────────────────────────────────────

class SettingsDialog(QDialog):
    """Settings dialog — opened from the header gear button.

    Tabs
    ----
    General   : Ollama host / model, GitHub repo, theme picker
    System    : Launch on boot (Scheduled Task), MCP server toggle
    ARIA      : HUD, Overdrive, voice, auto-brief, email scanning + live tests
    API Keys  : Optional cloud-escalation keys (Gemini, Groq, OpenAI, etc.)
    """

    # Background ARIA setup tests post their result here (thread-safe → GUI).
    aria_test_result = Signal(str)
    voice_model_result = Signal(str, bool)
    process_baseline_result = Signal(str, bool)

    _SANDBOX_TARGETS = {
        "Overview": ("src/angerona/gui/pages.py", "def _tab_overview"),
        "Information": ("src/angerona/gui/pages.py", "def _tab_information"),
        "General": ("src/angerona/gui/pages.py", "def _tab_general"),
        "System": ("src/angerona/gui/pages.py", "def _tab_system"),
        "Adversary Combat": (
            "src/angerona/gui/pages.py",
            "def _tab_adversary_combat",
        ),
        "Enterprise": ("src/angerona/gui/pages.py", "def _tab_enterprise"),
        "Integrations": ("src/angerona/gui/pages.py", "def _tab_integrations"),
        "ARIA": ("src/angerona/gui/pages.py", "def _tab_aria"),
        "Trusted Processes": (
            "src/angerona/gui/pages.py",
            "def _tab_trusted_processes",
        ),
        "Mobile Integration": ("src/angerona/gui/pages.py", "def _tab_mobile"),
        "API Keys": ("src/angerona/gui/pages.py", "def _tab_apikeys"),
    }

    def __init__(self, config, check_updates_fn, apply_theme_fn, parent=None,
                 initial_tab: str | None = None, process_baseline=None):
        super().__init__(parent)
        self._cfg            = config
        self._check_updates  = check_updates_fn
        self._apply_theme    = apply_theme_fn
        self._process_baseline = process_baseline
        self._voice_model_loading_token: str | None = None
        self._aria_test_loading_tokens: list[str] = []

        self.setWindowTitle("Angerona — Settings")
        self.setMinimumWidth(720)
        self.setModal(True)

        root = QVBoxLayout(self)
        root.setSpacing(10)
        root.setContentsMargins(16, 16, 16, 16)

        search_row = QHBoxLayout()
        self._settings_search = QLineEdit()
        self._settings_search.setClearButtonEnabled(True)
        self._settings_search.setPlaceholderText(
            "Find a setting — try microphone, privacy, cloud, trusted app, performance…")
        search_row.addWidget(QLabel("Find:"))
        search_row.addWidget(self._settings_search, 1)
        root.addLayout(search_row)

        self.tabs = QTabWidget()
        tabs = self.tabs
        root.addWidget(tabs)

        def _scroll(inner: QWidget) -> QScrollArea:
            """Wrap a tab so long panels (ARIA especially) get a scroll bar."""
            sa = QScrollArea()
            sa.setWidgetResizable(True)
            sa.setFrameShape(QScrollArea.NoFrame)
            sa.setWidget(inner)
            return sa

        tabs.addTab(_scroll(self._tab_overview()), "Overview")
        tabs.addTab(_scroll(self._tab_information()), "Information")
        tabs.addTab(_scroll(self._tab_general()), "General")
        tabs.addTab(_scroll(self._tab_system()),  "System")
        tabs.addTab(_scroll(self._tab_adversary_combat()), "Adversary Combat")
        tabs.addTab(_scroll(self._tab_enterprise()), "Enterprise")
        tabs.addTab(_scroll(self._tab_integrations()), "Integrations")
        tabs.addTab(_scroll(self._tab_aria()),    "ARIA")
        tabs.addTab(_scroll(self._tab_trusted_processes()), "Trusted Processes")
        tabs.addTab(_scroll(self._tab_mobile()), "Mobile Integration")
        tabs.addTab(_scroll(self._tab_apikeys()), "API Keys")
        from angerona.gui.context_info import attach_context_info
        self._context_info = attach_context_info(tabs, "settings")
        self._settings_sandbox_dialogs: dict[str, QDialog] = {}
        self._settings_search.textChanged.connect(self._find_setting)

        # ── button row ──
        btn_row = QHBoxLayout()
        self._privacy_btn = QPushButton("Restore privacy defaults")
        self._privacy_btn.setToolTip(
            "Turns off optional cloud, mailbox, channel, Teams, mobile, and research "
            "egress.")
        self._privacy_btn.clicked.connect(self._restore_privacy_defaults)
        btn_row.addWidget(self._privacy_btn)
        self._settings_sandbox_btn = QPushButton("Open Tab Code Sandbox")
        self._settings_sandbox_btn.setObjectName("SettingsTabSandbox")
        self._settings_sandbox_btn.clicked.connect(self._open_current_tab_sandbox)
        btn_row.addWidget(self._settings_sandbox_btn)
        btn_row.addStretch()
        self._btn_save   = QPushButton("Save")
        self._btn_cancel = QPushButton("Cancel")
        self._btn_save.setFixedWidth(90)
        self._btn_cancel.setFixedWidth(90)
        self._btn_save.setDefault(True)
        btn_row.addWidget(self._btn_cancel)
        btn_row.addWidget(self._btn_save)
        root.addLayout(btn_row)

        self._btn_save.clicked.connect(self._save)
        self._btn_cancel.clicked.connect(self.close)
        tabs.currentChanged.connect(self._update_settings_sandbox_button)
        self._update_settings_sandbox_button()
        # Route background ARIA-test results back to the status label on the GUI thread.
        try:
            self.aria_test_result.connect(self._aria_test_finished)
            self.voice_model_result.connect(self._voice_model_finished)
            self.process_baseline_result.connect(
                self._process_baseline_action_finished
            )
        except Exception:
            pass
        if initial_tab:
            wanted = str(initial_tab).casefold()
            exact = next(
                (
                    i for i in range(tabs.count())
                    if wanted == tabs.tabText(i).casefold()
                ),
                None,
            )
            if exact is not None:
                tabs.setCurrentIndex(exact)
            else:
                for i in range(tabs.count()):
                    if wanted in tabs.tabText(i).casefold():
                        tabs.setCurrentIndex(i)
                        break

    def _find_setting(self, query: str) -> None:
        """Jump to the most relevant settings area without hiding any controls."""
        from angerona.core.settings_catalog import resolve_area

        area = resolve_area(query)
        if area is not None:
            self._select_tab(area.title)

    def _select_tab(self, title: str) -> bool:
        for index in range(self.tabs.count()):
            if self.tabs.tabText(index) == title:
                self.tabs.setCurrentIndex(index)
                return True
        return False

    def _current_settings_tab_label(self) -> str:
        """Return the functional tab represented by the current Settings view."""
        index = self.tabs.currentIndex()
        if self.tabs.tabText(index) == "Info":
            index = int(getattr(self._context_info, "last_functional_index", index))
        if 0 <= index < self.tabs.count():
            return self.tabs.tabText(index)
        return ""

    def _settings_sandbox_target(self):
        from angerona.core.menu_info import get_menu_info

        label = self._current_settings_tab_label()
        topic = get_menu_info("settings", label)
        target = self._SANDBOX_TARGETS.get(label)
        if topic is None or target is None:
            return label, None, "", ""
        return label, topic, target[0], target[1]

    def _update_settings_sandbox_button(self, _index: int = -1) -> None:
        label, topic, preselect, _find_text = self._settings_sandbox_target()
        enabled = bool(topic and preselect)
        self._settings_sandbox_btn.setEnabled(enabled)
        self._settings_sandbox_btn.setText(
            f"Open {label} Code Sandbox" if enabled else "Code Sandbox Unavailable"
        )
        if enabled:
            paths = ", ".join(topic.source_paths)
            self._settings_sandbox_btn.setToolTip(
                f"Open isolated editable copies for {label}. Related files: {paths}"
            )
        else:
            self._settings_sandbox_btn.setToolTip(
                "No editable implementation files are registered for this tab."
            )

    def _open_current_tab_sandbox(self) -> None:
        """Open this tab's related source files at its UI implementation."""
        label, topic, preselect, find_text = self._settings_sandbox_target()
        if topic is None:
            QMessageBox.warning(
                self,
                "Code Sandbox",
                f"No sandbox source mapping is registered for {label or 'this tab'}.",
            )
            return
        existing = self._settings_sandbox_dialogs.get(topic.key)
        if existing is not None:
            existing.show()
            existing.raise_()
            existing.activateWindow()
            return
        try:
            from angerona.core.source_sandbox import SourceSandboxWorkspace
            from angerona.gui.context_info import SourceSandboxDialog

            workspace = SourceSandboxWorkspace(topic.key, topic.source_paths)
            if not workspace.available:
                raise ValueError("the registered source files are unavailable")
            dialog = SourceSandboxDialog(
                workspace,
                self,
                preselect=preselect,
                find_text=find_text,
            )
            self._settings_sandbox_dialogs[topic.key] = dialog
            dialog.destroyed.connect(
                lambda *_args, key=topic.key: self._settings_sandbox_dialogs.pop(
                    key, None
                )
            )
            dialog.show()
            dialog.raise_()
            dialog.activateWindow()
        except Exception as exc:
            QMessageBox.warning(
                self,
                "Code Sandbox",
                f"Could not open the {label} sandbox:\n{exc}",
            )

    def _restore_privacy_defaults(self) -> None:
        """Stage safe local-only defaults; Save applies them."""
        for name in ("_aria_voice_cloud_chk", "_aria_cloud_fallback_chk",
                     "_alert_analysis_cloud_chk",
                     "_aria_push_chk", "_aria_inbox_chk", "_aria_egress_chk",
                     "_aria_awareness_chk", "_aria_always_listen_chk",
                     "_aria_hands_chk", "_teams_chk", "_teams_skip_chk", "_mob_chk"):
            widget = getattr(self, name, None)
            if widget is not None:
                widget.setChecked(False)
        for name in ("_siem_raw_chk", "_siem_plaintext_chk", "_bridge_nonloop_chk"):
            widget = getattr(self, name, None)
            if widget is not None:
                widget.setChecked(False)
        if hasattr(self, "_siem_host"):
            self._siem_host.clear()
        if hasattr(self, "_bridge_mode"):
            self._bridge_mode.setCurrentIndex(0)
        if hasattr(self, "_ioc_url"):
            self._ioc_url.clear()
            self._ioc_sha256.clear()
        self._select_tab("ARIA")
        self._aria_test_status.setText(
            "Privacy defaults staged: optional cloud, mobile, and remote egress are "
            "off. Click Save.")

    # ── Tab builders ──────────────────────────────────────────────────────────

    def _tab_overview(self) -> QWidget:
        """One map of every canonical configuration owner."""
        from angerona.core.settings_catalog import AREAS

        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setSpacing(10)
        lay.addWidget(self._section("Configuration map"))
        intro = QLabel(
            "Each capability is configured in exactly one place. Double-click "
            "an area to open it. Operational dashboards remain in the Advanced "
            "Console and do not duplicate saved settings."
        )
        intro.setWordWrap(True)
        intro.setStyleSheet("color:#94a3b8; font-size:11px;")
        lay.addWidget(intro)
        self._settings_map = QTableWidget(len(AREAS), 4)
        self._settings_map.setHorizontalHeaderLabels(
            ["Area", "Purpose", "Privacy", "Apply"]
        )
        self._settings_map.verticalHeader().setVisible(False)
        self._settings_map.setEditTriggers(QTableWidget.NoEditTriggers)
        self._settings_map.setSelectionBehavior(QTableWidget.SelectRows)
        self._settings_map.setAlternatingRowColors(True)
        for row, area in enumerate(AREAS):
            for column, value in enumerate((
                area.title,
                area.purpose,
                area.privacy,
                "Restart" if area.restart else "Live",
            )):
                item = QTableWidgetItem(value)
                item.setData(Qt.UserRole, area.title)
                self._settings_map.setItem(row, column, item)
        self._settings_map.setSortingEnabled(True)
        header = self._settings_map.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self._settings_map.cellDoubleClicked.connect(
            lambda row, _column: self._select_tab(
                self._settings_map.item(row, 0).data(Qt.UserRole)
            )
        )
        lay.addWidget(self._settings_map, 1)
        return w

    def _tab_information(self) -> QWidget:
        """Searchable capability definitions, procedures and direct navigation."""
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setSpacing(10)
        lay.addWidget(self._section("Capability guide"))
        intro = QLabel(
            "Search by task or feature. Every entry explains what it does, how "
            "to configure it, how to verify it, its privacy boundary, and the "
            "single canonical place that owns it."
        )
        intro.setWordWrap(True)
        intro.setStyleSheet("color:#94a3b8; font-size:11px;")
        lay.addWidget(intro)
        self._info_search = QLineEdit()
        self._info_search.setClearButtonEnabled(True)
        self._info_search.setPlaceholderText(
            "Search capabilities - try VPN, custody, microphone, fleet, performance..."
        )
        lay.addWidget(self._info_search)
        body = QHBoxLayout()
        self._info_list = QListWidget()
        self._info_list.setMinimumWidth(220)
        self._info_detail = QPlainTextEdit()
        self._info_detail.setReadOnly(True)
        self._info_detail.setLineWrapMode(QPlainTextEdit.WidgetWidth)
        body.addWidget(self._info_list, 1)
        body.addWidget(self._info_detail, 3)
        lay.addLayout(body, 1)
        nav = QHBoxLayout()
        nav.addStretch()
        self._info_take_me = QPushButton("Take me there")
        self._info_take_me.setObjectName("Primary")
        self._info_take_me.clicked.connect(self._info_navigate)
        nav.addWidget(self._info_take_me)
        lay.addLayout(nav)
        self._info_search.textChanged.connect(self._refresh_information)
        self._info_list.currentRowChanged.connect(self._show_information)
        self._refresh_information("")
        return w

    def _refresh_information(self, query: str) -> None:
        from angerona.core.capability_guide import search_guides

        self._visible_guides = search_guides(query)
        self._info_list.clear()
        for guide in self._visible_guides:
            item = QListWidgetItem(
                f"{guide.name}\n{guide.category} · {guide.maturity_label}"
            )
            item.setData(Qt.UserRole, guide.key)
            item.setToolTip(
                f"{guide.maturity_label} · {guide.destination_label}"
            )
            self._info_list.addItem(item)
        self._info_list.setCurrentRow(0 if self._visible_guides else -1)
        if not self._visible_guides:
            self._info_detail.setPlainText(
                "No capability matched. Try a broader task or feature name."
            )
            self._info_take_me.setEnabled(False)

    def _show_information(self, row: int) -> None:
        if row < 0 or row >= len(getattr(self, "_visible_guides", ())):
            self._info_take_me.setEnabled(False)
            return
        guide = self._visible_guides[row]
        steps = "\n".join(
            f"{index}. {step}" for index, step in enumerate(guide.steps, 1)
        )
        evidence = "\n".join(f"• {item}" for item in guide.evidence)
        limitations = "\n".join(f"• {item}" for item in guide.limitations)
        destination = guide.destination_label
        if not guide.is_actionable:
            destination += " (no operator navigation in this build)"
        self._info_detail.setPlainText(
            f"{guide.name}\n"
            f"{'=' * len(guide.name)}\n\n"
            f"MATURITY\n{guide.maturity_label}\n\n"
            f"WHAT IT DOES\n{guide.definition}\n\n"
            f"HOW TO USE IT\n{steps}\n\n"
            f"VERIFY\n{guide.verify}\n\n"
            f"PRIVACY AND SAFETY\n{guide.privacy}\n\n"
            f"EVIDENCE\n{evidence}\n\n"
            f"KNOWN LIMITATIONS\n{limitations}\n\n"
            f"CANONICAL DESTINATION\n{destination}"
        )
        self._info_take_me.setEnabled(guide.is_actionable)
        self._info_take_me.setText(
            "Take me there" if guide.is_actionable else "Guidance only"
        )

    def _info_navigate(self) -> None:
        row = self._info_list.currentRow()
        if row < 0 or row >= len(getattr(self, "_visible_guides", ())):
            return
        guide = self._visible_guides[row]
        if not guide.is_actionable:
            return
        if guide.destination_kind == "settings":
            if not self._select_tab(guide.destination):
                self._info_take_me.setEnabled(False)
                self._info_take_me.setText("Destination unavailable")
                self._info_detail.appendPlainText(
                    "\n\nNAVIGATION\nThe declared Settings destination is unavailable "
                    "in this build. No action was taken."
                )
            return
        owner = self.parent()
        callback = getattr(owner, guide.destination, None)
        if callable(callback):
            # Let this dialog finish its reverse-close animation before the next
            # real destination performs its own reveal.
            self.close()
            QTimer.singleShot(420, callback)
            return
        self._info_take_me.setEnabled(False)
        self._info_take_me.setText("Destination unavailable")
        self._info_detail.appendPlainText(
            "\n\nNAVIGATION\nThe declared window is unavailable in this build. "
            "No action was taken."
        )

    def _tab_general(self) -> QWidget:
        w   = QWidget()
        lay = QVBoxLayout(w)
        lay.setSpacing(10)

        lay.addWidget(self._section("Ollama (local AI)"))

        grid = QGridLayout()
        grid.setColumnStretch(1, 1)
        grid.addWidget(QLabel("Host:"), 0, 0)
        self._ollama_host = QLineEdit(self._cfg.ollama_host)
        grid.addWidget(self._ollama_host, 0, 1)
        grid.addWidget(QLabel("Model:"), 1, 0)
        self._ollama_model = QLineEdit(self._cfg.ollama_model)
        grid.addWidget(self._ollama_model, 1, 1)
        lay.addLayout(grid)

        lay.addWidget(self._section("Appearance"))
        theme_row = QHBoxLayout()
        theme_row.addWidget(QLabel("Theme:"))
        self._theme_combo = QComboBox()
        # available_themes() returns (key, label) tuples — add the label as the
        # visible text and stash the key as item data. addItem(tuple) is invalid
        # and was throwing during construction, which is why the Settings dialog
        # "did nothing" when the gear button was clicked.
        for t in available_themes():
            if isinstance(t, (tuple, list)):
                key = str(t[0])
                label = str(t[1]) if len(t) > 1 else key
            else:
                key = label = str(t)
            self._theme_combo.addItem(label, key)
        idx = self._theme_combo.findData(self._cfg.theme)
        if idx < 0:
            idx = self._theme_combo.findText(self._cfg.theme)
        if idx >= 0:
            self._theme_combo.setCurrentIndex(idx)
        theme_row.addWidget(self._theme_combo)
        theme_row.addStretch()
        lay.addLayout(theme_row)

        dashboard_row = QHBoxLayout()
        dashboard_row.addWidget(QLabel("Startup dashboard:"))
        self._dashboard_mode_combo = QComboBox()
        self._dashboard_mode_combo.addItem("Classic dashboard", "classic")
        self._dashboard_mode_combo.addItem(
            "Flow Dashboard · Local SOC", "flow")
        self._dashboard_mode_combo.setToolTip(
            "Classic keeps the familiar monitoring screen. Flow opens the "
            "interactive Local SOC workspace for cases, hunts, assets, signed "
            "detections, and tamper-evident audit history. You can switch back "
            "at any time and both modes stay entirely local.")
        _dashboard_index = self._dashboard_mode_combo.findData(
            str(getattr(self._cfg, "dashboard_mode", "classic")).lower())
        self._dashboard_mode_combo.setCurrentIndex(
            _dashboard_index if _dashboard_index >= 0 else 0)
        dashboard_row.addWidget(self._dashboard_mode_combo)
        dashboard_row.addStretch()
        lay.addLayout(dashboard_row)

        # UI scale — Auto grows/shrinks buttons + text with the window; Fixed
        # pins a size (useful on large or high-DPI monitors). Values match the
        # readable clamp band in gui/theme.clamp_scale (75–135%).
        scale_row = QHBoxLayout()
        scale_row.addWidget(QLabel("UI scale:"))
        self._ui_scale_combo = QComboBox()
        self._ui_scale_combo.addItem("Auto (fit to window)", "auto")
        for _pct in (75, 90, 100, 110, 125, 135):
            self._ui_scale_combo.addItem(f"Fixed · {_pct}%", _pct)
        self._ui_scale_combo.setToolTip(
            "Auto scales buttons and text with the window size. Fixed pins the "
            "size regardless of the window — handy on large or high-DPI screens.")
        if str(getattr(self._cfg, "ui_scale_mode", "auto")).lower() == "fixed":
            _want = int(round(float(getattr(self._cfg, "ui_scale_fixed", 1.0)) * 100))
            _sidx = self._ui_scale_combo.findData(_want)
            self._ui_scale_combo.setCurrentIndex(_sidx if _sidx >= 0 else 0)
        else:
            self._ui_scale_combo.setCurrentIndex(0)
        scale_row.addWidget(self._ui_scale_combo)
        scale_row.addStretch()
        lay.addLayout(scale_row)
        self._ui_motion_chk = QCheckBox(
            "Animate top-row buttons into their destination windows")
        self._ui_motion_chk.setToolTip(
            "Plays a short vertical-line-to-panel reveal before a top-row window "
            "opens. Angerona still honors Windows reduced-motion accessibility "
            "settings, and ANGERONA_REDUCE_MOTION=1 always disables it.")
        self._ui_motion_chk.setChecked(
            bool(getattr(self._cfg, "ui_motion_enabled", True)))
        lay.addWidget(self._ui_motion_chk)
        self._holographic_orb_chk = QCheckBox(
            "Show the holographic Angerona Orb when windows minimize")
        self._holographic_orb_chk.setToolTip(
            "Collapses Angerona windows into a lightweight spinning globe. "
            "Click it for radial Core, Watchdog, Scanner, and Black Box controls. "
            "Reduced-motion mode keeps the token but removes spinning and "
            "transition motion.")
        self._holographic_orb_chk.setChecked(
            bool(getattr(self._cfg, "holographic_orb_enabled", True)))
        lay.addWidget(self._holographic_orb_chk)

        # ── Integrity / performance (advanced) ──────────────────────────────
        lay.addWidget(self._section("Integrity & Performance"))
        self._require_signed_aar_chk = QCheckBox(
            "Require signed After-Action Reports (refuse unsigned/forged self-hardening input)")
        self._require_signed_aar_chk.setToolTip(
            "Strict mode: the self-hardening loop refuses to learn from any AAR that "
            "isn't HMAC-authenticated. Tampered reports are always refused regardless; "
            "this also blocks unsigned/legacy reports instead of just warning. "
            "Recommended once you've run at least one drill so signed reports exist.")
        self._require_signed_aar_chk.setChecked(bool(getattr(self._cfg, "require_signed_aar", True)))
        lay.addWidget(self._require_signed_aar_chk)
        self._entropy_pool_chk = QCheckBox(
            "Offload ransomware entropy scanning to worker processes (experimental)")
        self._entropy_pool_chk.setToolTip(
            "Runs the CPU-bound entropy/hash scan in a small pool of worker processes "
            "so it no longer competes for the main interpreter's GIL — keeps the UI and "
            "response path snappier during big scans on multi-core hosts. Experimental; "
            "leave off if you prefer the in-process path.")
        self._entropy_pool_chk.setChecked(bool(getattr(self._cfg, "entropy_pool_enabled", False)))
        lay.addWidget(self._entropy_pool_chk)

        lay.addWidget(self._section("Updates"))
        repo_row = QHBoxLayout()
        repo_row.addWidget(QLabel("GitHub repo:"))
        self._github_repo = QLineEdit(self._cfg.github_repo)
        repo_row.addWidget(self._github_repo)
        self._btn_check = QPushButton("Check now")
        self._btn_check.clicked.connect(self._on_check_updates)
        repo_row.addWidget(self._btn_check)
        lay.addLayout(repo_row)

        lay.addStretch()
        return w

    def _tab_adversary_combat(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setSpacing(10)

        lay.addWidget(self._section("Standing autonomous response authority"))
        warning = QLabel(
            "When armed, Angerona acts on detector evidence immediately without "
            "asking for per-incident permission. Maximum mode accepts outage risk: "
            "it can terminate processes and isolate all remote network traffic."
        )
        warning.setWordWrap(True)
        warning.setStyleSheet(
            "color:#fecaca; background:#450a0a; border:1px solid #991b1b; "
            "border-radius:6px; padding:10px; font-weight:700;"
        )
        lay.addWidget(warning)

        self._combat_enabled_chk = QCheckBox(
            "Arm Adversary Combat and act automatically on my behalf"
        )
        self._combat_enabled_chk.setChecked(bool(getattr(
            self._cfg, "adversary_combat_enabled", True
        )))
        lay.addWidget(self._combat_enabled_chk)

        grid = QGridLayout()
        grid.addWidget(QLabel("Response level:"), 0, 0)
        self._combat_mode_combo = QComboBox()
        self._combat_mode_combo.addItem("Contain · suspend and quarantine", "contain")
        self._combat_mode_combo.addItem("Aggressive · terminate exact targets", "aggressive")
        self._combat_mode_combo.addItem("Maximum · terminate + host isolation", "maximum")
        mode_index = self._combat_mode_combo.findData(str(getattr(
            self._cfg, "adversary_combat_mode", "maximum"
        )).lower())
        self._combat_mode_combo.setCurrentIndex(mode_index if mode_index >= 0 else 2)
        grid.addWidget(self._combat_mode_combo, 0, 1)

        grid.addWidget(QLabel("Minimum detector severity:"), 1, 0)
        self._combat_severity_combo = QComboBox()
        for severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            self._combat_severity_combo.addItem(severity.title(), severity)
        severity_index = self._combat_severity_combo.findData(str(getattr(
            self._cfg, "adversary_combat_min_severity", "LOW"
        )).upper())
        self._combat_severity_combo.setCurrentIndex(
            severity_index if severity_index >= 0 else 0
        )
        grid.addWidget(self._combat_severity_combo, 1, 1)

        grid.addWidget(QLabel("Process response:"), 2, 0)
        self._combat_process_combo = QComboBox()
        self._combat_process_combo.addItem("Suspend (reversible)", "suspend")
        self._combat_process_combo.addItem("Terminate (not reversible)", "terminate")
        process_index = self._combat_process_combo.findData(str(getattr(
            self._cfg, "adversary_combat_process_action", "terminate"
        )).lower())
        self._combat_process_combo.setCurrentIndex(
            process_index if process_index >= 0 else 1
        )
        grid.addWidget(self._combat_process_combo, 2, 1)

        grid.addWidget(QLabel("Host-isolation trigger count (30s):"), 3, 0)
        self._combat_isolation_threshold = QLineEdit(str(getattr(
            self._cfg, "adversary_combat_isolation_threshold", 3
        )))
        self._combat_isolation_threshold.setValidator(
            QRegularExpressionValidator(QRegularExpression(r"[1-9][0-9]?|100"))
        )
        grid.addWidget(self._combat_isolation_threshold, 3, 1)
        lay.addLayout(grid)

        self._combat_block_chk = QCheckBox(
            "Block the named remote IP and offending program at Windows Firewall"
        )
        self._combat_block_chk.setChecked(bool(getattr(
            self._cfg, "adversary_combat_block_network", True
        )))
        self._combat_quarantine_chk = QCheckBox(
            "Quarantine the exact file artifact (reversible)"
        )
        self._combat_quarantine_chk.setChecked(bool(getattr(
            self._cfg, "adversary_combat_quarantine_files", True
        )))
        self._combat_host_isolation_chk = QCheckBox(
            "Automatically isolate the whole host on critical/correlated attack evidence"
        )
        self._combat_host_isolation_chk.setChecked(bool(getattr(
            self._cfg, "adversary_combat_isolate_host", True
        )))
        self._combat_honeypot_chk = QCheckBox(
            "Keep Smart Deception honeypots active automatically"
        )
        self._combat_honeypot_chk.setChecked(bool(getattr(
            self._cfg, "adversary_combat_activate_honeypots", True
        )))
        for widget in (
            self._combat_block_chk,
            self._combat_quarantine_chk,
            self._combat_host_isolation_chk,
            self._combat_honeypot_chk,
        ):
            lay.addWidget(widget)

        lay.addWidget(self._section("Action history and undo"))
        self._combat_history_status = QLabel()
        self._combat_history_status.setWordWrap(True)
        lay.addWidget(self._combat_history_status)
        select_row = QHBoxLayout()
        select_row.addWidget(QLabel("Reversible action:"))
        self._combat_undo_selector = QComboBox()
        self._combat_undo_selector.setMinimumContentsLength(36)
        select_row.addWidget(self._combat_undo_selector, 1)
        lay.addLayout(select_row)
        undo_row = QHBoxLayout()
        self._combat_refresh_btn = QPushButton("Refresh action history")
        self._combat_undo_btn = QPushButton("Undo selected")
        self._combat_undo_all_btn = QPushButton("Undo all reversible")
        self._combat_refresh_btn.clicked.connect(self._refresh_combat_actions)
        self._combat_undo_btn.clicked.connect(self._undo_selected_combat_action)
        self._combat_undo_all_btn.clicked.connect(self._undo_all_combat_actions)
        undo_row.addWidget(self._combat_refresh_btn)
        undo_row.addWidget(self._combat_undo_btn)
        undo_row.addWidget(self._combat_undo_all_btn)
        undo_row.addStretch()
        lay.addLayout(undo_row)
        self._refresh_combat_actions()
        lay.addStretch()
        return w

    def _combat_module(self):
        parent = self.parent()
        manager = getattr(parent, "manager", None)
        return getattr(manager, "modules", {}).get("Adversary Combat") if manager else None

    def _refresh_combat_actions(self) -> None:
        label = getattr(self, "_combat_history_status", None)
        if label is None:
            return
        selector = getattr(self, "_combat_undo_selector", None)
        undo_button = getattr(self, "_combat_undo_btn", None)
        undo_all_button = getattr(self, "_combat_undo_all_btn", None)
        if selector is not None:
            selector.clear()
        module = self._combat_module()
        if module is None:
            label.setText("Adversary Combat is not attached to this Settings window yet.")
            if selector is not None:
                selector.setEnabled(False)
            if undo_button is not None:
                undo_button.setEnabled(False)
            if undo_all_button is not None:
                undo_all_button.setEnabled(False)
            return
        actions = module.list_actions(limit=100)
        if not actions:
            label.setText("No combat actions have been recorded.")
            if selector is not None:
                selector.setEnabled(False)
            if undo_button is not None:
                undo_button.setEnabled(False)
            if undo_all_button is not None:
                undo_all_button.setEnabled(False)
            return
        rows = []
        for action in actions[:5]:
            status = "UNDONE" if action.get("undone") else "APPLIED"
            stamp = time.strftime(
                "%Y-%m-%d %H:%M:%S",
                time.localtime(float(action.get("applied_at") or 0.0)),
            )
            rows.append(
                f"{stamp} · {status} · {action.get('action')} · {action.get('target')}"
            )
        label.setText("\n".join(rows))

        reversible = [
            action for action in actions
            if action.get("reversible") is True
            and not action.get("undone")
            and action.get("integrity_status") == "verified"
            and action.get("status") == "applied"
        ]
        if selector is not None:
            for action in reversible:
                target = str(action.get("target") or "")
                if len(target) > 70:
                    target = "…" + target[-69:]
                selector.addItem(
                    f"{action.get('action')} · {target}",
                    str(action.get("action_id") or ""),
                )
            selector.setEnabled(bool(reversible))
        if undo_button is not None:
            undo_button.setEnabled(bool(reversible))
        if undo_all_button is not None:
            undo_all_button.setEnabled(bool(reversible))

    def _undo_selected_combat_action(self) -> None:
        module = self._combat_module()
        selector = getattr(self, "_combat_undo_selector", None)
        action_id = str(selector.currentData() or "") if selector is not None else ""
        if module is None or not action_id:
            self._combat_history_status.setText(
                "No verified reversible action is selected; no action was changed."
            )
            return
        result = module.undo_action(action_id)
        if result.get("ok"):
            self._combat_history_status.setText(
                f"Undo completed: {result.get('action')} ({result.get('action_id')})."
            )
        else:
            self._combat_history_status.setText(
                f"Undo did not run: {result.get('error', 'unknown error')}"
            )
        QTimer.singleShot(500, self._refresh_combat_actions)

    def _undo_all_combat_actions(self) -> None:
        module = self._combat_module()
        if module is None:
            self._combat_history_status.setText(
                "Adversary Combat is unavailable; no action was changed."
            )
            return
        result = module.undo_all()
        if result.get("ok"):
            self._combat_history_status.setText(
                f"Undo all completed: {result.get('undone', 0)} reversible "
                "action(s) restored."
            )
        else:
            self._combat_history_status.setText(
                f"Undo all completed with {len(result.get('failures', []))} "
                "failure(s); review the verified action journal."
            )
        QTimer.singleShot(500, self._refresh_combat_actions)

    def _undo_last_combat_action(self) -> None:
        """Compatibility hook for older UI callers; newest action is selected."""
        module = self._combat_module()
        if module is None:
            self._combat_history_status.setText(
                "Adversary Combat is unavailable; no action was changed."
            )
            return
        result = module.undo_last()
        if result.get("ok"):
            self._combat_history_status.setText(
                f"Undo completed: {result.get('action')} ({result.get('action_id')})."
            )
        else:
            self._combat_history_status.setText(
                f"Undo did not run: {result.get('error', 'unknown error')}"
            )
        QTimer.singleShot(500, self._refresh_combat_actions)

    def _tab_system(self) -> QWidget:
        w   = QWidget()
        lay = QVBoxLayout(w)
        lay.setSpacing(10)

        # ── Startup on boot ──
        from angerona.core.autostart import ui_copy as _autostart_ui_copy
        startup_section, startup_checkbox, startup_note, _backend = _autostart_ui_copy()
        lay.addWidget(self._section(startup_section))

        boot_box = QGroupBox()
        boot_box.setFlat(True)
        boot_lay = QVBoxLayout(boot_box)
        boot_lay.setContentsMargins(0, 0, 0, 0)

        from angerona.core.autostart import is_enabled as _autostart_is_enabled
        currently_enabled = _autostart_is_enabled()

        self._autostart_chk = QCheckBox(startup_checkbox)
        self._autostart_chk.setChecked(
            currently_enabled if currently_enabled is not None
            else self._cfg.autostart_enabled
        )
        boot_lay.addWidget(self._autostart_chk)

        note = QLabel(startup_note)
        note.setWordWrap(True)
        note.setStyleSheet("color: #94a3b8; font-size: 11px;")
        boot_lay.addWidget(note)

        self._autostart_status = QLabel()
        self._autostart_status.setStyleSheet("font-size: 11px;")
        self._refresh_autostart_status(currently_enabled)
        boot_lay.addWidget(self._autostart_status)

        lay.addWidget(boot_box)

        lay.addWidget(self._section("MCP Server (Claude Desktop integration)"))
        self._mcp_chk = QCheckBox("Enable local MCP server on port")
        self._mcp_chk.setChecked(self._cfg.mcp_enabled)
        self._mcp_port = QLineEdit(str(self._cfg.mcp_port))
        self._mcp_port.setFixedWidth(70)
        self._mcp_port.setEnabled(self._cfg.mcp_enabled)
        self._mcp_chk.toggled.connect(self._mcp_port.setEnabled)
        mcp_row = QHBoxLayout()
        mcp_row.addWidget(self._mcp_chk); mcp_row.addWidget(self._mcp_port); mcp_row.addStretch()
        lay.addLayout(mcp_row)
        mcp_note = QLabel("Loopback only (127.0.0.1). Restart required for changes to take effect.")
        mcp_note.setWordWrap(True); mcp_note.setStyleSheet("color: #94a3b8; font-size: 11px;")
        lay.addWidget(mcp_note)

        lay.addWidget(self._section("Performance"))
        self._eco_chk = QCheckBox(
            "Start in Chill Mode (network-first, low-resource all-day monitoring)"
        )
        self._eco_chk.setChecked(getattr(self._cfg, "eco_mode", True))
        lay.addWidget(self._eco_chk)
        eco_note = QLabel(
            "Recommended. Network, Defender/AMSI, USB, ETW/Sysmon, watchdog and "
            "response stay live. Deep file/memory scanners and background AI sleep; "
            "a genuine active threat wakes verification modules sequentially, then "
            "Angerona returns to Chill after a quiet window."
        )
        eco_note.setWordWrap(True); eco_note.setStyleSheet("color: #94a3b8; font-size: 11px;")
        lay.addWidget(eco_note)

        lay.addWidget(self._section("Removable media (USB)"))
        usb_grid = QGridLayout()
        usb_grid.setColumnStretch(1, 1)
        usb_grid.addWidget(QLabel("New approval PIN (4–12 digits):"), 0, 0)
        self._usb_pin = QLineEdit()
        self._usb_pin.setEchoMode(QLineEdit.Password)
        self._usb_pin.setMaxLength(12)
        self._usb_pin.setPlaceholderText("Create a new protected PIN")
        self._usb_pin.setValidator(
            QRegularExpressionValidator(
                QRegularExpression(r"[0-9]{0,12}"), self._usb_pin
            )
        )
        usb_grid.addWidget(self._usb_pin, 0, 1)
        usb_grid.addWidget(QLabel("Confirm new PIN:"), 1, 0)
        self._usb_pin_confirm = QLineEdit()
        self._usb_pin_confirm.setEchoMode(QLineEdit.Password)
        self._usb_pin_confirm.setMaxLength(12)
        self._usb_pin_confirm.setPlaceholderText("Re-enter the new PIN")
        self._usb_pin_confirm.setValidator(
            QRegularExpressionValidator(
                QRegularExpression(r"[0-9]{0,12}"), self._usb_pin_confirm
            )
        )
        usb_grid.addWidget(self._usb_pin_confirm, 1, 1)
        self._usb_pin_reset = QPushButton("Confirm & reset USB PIN")
        self._usb_pin_reset.setToolTip(
            "Writes a new PIN to protected storage, clears the session lock, and "
            "revokes every current Angerona removable-media approval."
        )
        self._usb_pin_reset.clicked.connect(self._reset_usb_pin)
        usb_grid.addWidget(self._usb_pin_reset, 2, 1)
        lay.addLayout(usb_grid)
        try:
            from angerona.core.usb_policy import usb_pin_configured
            _usb_ready = usb_pin_configured()
        except Exception:
            _usb_ready = False
        self._usb_pin_status = QLabel(
            "Protected PIN configured" if _usb_ready else "No protected PIN configured"
        )
        self._usb_pin_status.setStyleSheet(
            "color: #22c55e; font-size: 11px;"
            if _usb_ready else "color: #f59e0b; font-size: 11px;"
        )
        lay.addWidget(self._usb_pin_status)
        usb_note = QLabel(
            "New removable media stays untrusted until a protected PIN is enrolled "
            "and then entered separately in the approval window. One incorrect PIN "
            "locks USB approval until this confirmed reset workflow creates a new "
            "PIN. Resetting revokes trust and never approves an attached device. "
            "Approval grants only Angerona permission to inspect "
            "that currently inserted media; it does not block or change raw operating-"
            "system access. Windows AutoRun and AutoPlay remain disabled before and "
            "after approval. The PIN is stored only in your "
            "operating-system protected credential store, never in settings.json."
        )
        usb_note.setWordWrap(True)
        usb_note.setStyleSheet("color: #94a3b8; font-size: 11px;")
        lay.addWidget(usb_note)

        lay.addWidget(self._section("Black Box (out-of-band diagnostic recorder)"))
        self._blackbox_chk = QCheckBox("Launch the Black Box recorder automatically with Angerona")
        self._blackbox_chk.setChecked(getattr(self._cfg, "blackbox_enabled", True))
        import sys as _platform_sys
        if not _platform_sys.platform.startswith("win"):
            self._blackbox_chk.setChecked(False)
            self._blackbox_chk.setEnabled(False)
        lay.addWidget(self._blackbox_chk)
        bb_note = QLabel(
            ("A separate, strictly read-only Windows process that tails crash/diagnostic "
             "files and survives a main-suite deadlock."
             if _platform_sys.platform.startswith("win") else
             "The decoupled Black Box currently consumes Windows-only evidence and is "
             "disabled on this platform; portable crash logging remains active.")
        )
        bb_note.setWordWrap(True); bb_note.setStyleSheet("color: #94a3b8; font-size: 11px;")
        lay.addWidget(bb_note)

        lay.addWidget(self._section("Deception data boundary"))
        self._deception_user_folders_chk = QCheckBox(
            "Place hidden honeytokens in my Desktop/Documents/AppData (advanced opt-in)"
        )
        self._deception_user_folders_chk.setChecked(
            bool(getattr(self._cfg, "deception_user_folders", False))
        )
        self._deception_user_folders_chk.setToolTip(
            "Off keeps every Angerona-created decoy under the configured D-drive data root."
        )
        lay.addWidget(self._deception_user_folders_chk)
        deception_note = QLabel(
            "Default: D-drive only. Enabling this deliberately writes and later removes "
            "hidden inert canary files in personal folders for broader ransomware coverage; "
            "existing real files are never overwritten. A restart applies the change."
        )
        deception_note.setWordWrap(True)
        deception_note.setStyleSheet("color: #94a3b8; font-size: 11px;")
        lay.addWidget(deception_note)

        lay.addWidget(self._section("Linux kernel telemetry (optional supplement)"))
        self._ebpf_chk = QCheckBox("Enable native eBPF kernel telemetry (Linux + BCC + root only)")
        self._ebpf_chk.setChecked(getattr(self._cfg, "ebpf_enabled", False))
        lay.addWidget(self._ebpf_chk)
        ebpf_note = QLabel(
            "Off by default. Rootless Linux Observe works without this option. BCC/eBPF "
            "adds privileged execve + tcp_sendmsg kernel visibility on a dedicated sensor "
            "deployment; do not run the desktop GUI as root."
        )
        ebpf_note.setWordWrap(True); ebpf_note.setStyleSheet("color: #94a3b8; font-size: 11px;")
        lay.addWidget(ebpf_note)

        lay.addWidget(self._section("Confidential Compute (Intel SGX / Gramine)"))
        try:
            from angerona.core.sgx_guard import is_confidential_compute_active
            _sgx_on = is_confidential_compute_active()
        except Exception:
            _sgx_on = False
        sgx_lbl = QLabel(("ACTIVE — the flight cache runs inside an SGX enclave."
                          if _sgx_on else
                          "Not active — run under Gramine-SGX to hardware-encrypt the "
                          "in-memory cache (see angerona.manifest.template)."))
        sgx_lbl.setWordWrap(True)
        sgx_lbl.setStyleSheet(f"color: {'#22c55e' if _sgx_on else '#94a3b8'}; font-size: 11px;")
        lay.addWidget(sgx_lbl)

        lay.addStretch()
        return w

    def _tab_enterprise(self) -> QWidget:
        """Evidence-based readiness, extension trust, and proof status."""
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setSpacing(10)

        lay.addWidget(self._section("Local fleet control plane"))
        self._fleet_service_chk = QCheckBox(
            "Enable authenticated local fleet service"
        )
        self._fleet_service_chk.setChecked(
            bool(getattr(self._cfg, "fleet_service_enabled", False))
        )
        lay.addWidget(self._fleet_service_chk)
        fleet_grid = QGridLayout()
        fleet_grid.addWidget(QLabel("Tenant ID:"), 0, 0)
        self._fleet_tenant = QLineEdit(
            str(getattr(self._cfg, "fleet_tenant_id", "local"))
        )
        self._fleet_tenant.setPlaceholderText("local")
        fleet_grid.addWidget(self._fleet_tenant, 0, 1)
        fleet_grid.addWidget(QLabel("Loopback port:"), 1, 0)
        self._fleet_port = QLineEdit(
            str(getattr(self._cfg, "fleet_service_port", 47930))
        )
        self._fleet_port.setFixedWidth(90)
        fleet_grid.addWidget(self._fleet_port, 1, 1)
        fleet_grid.setColumnStretch(2, 1)
        lay.addLayout(fleet_grid)
        fleet_note = QLabel(
            "Binds only to 127.0.0.1 and requires signed, fresh, replay-protected "
            "requests. Enabling it creates a protected random service key. "
            "Remote fleet access remains disabled until mutual TLS is deployed."
        )
        fleet_note.setWordWrap(True)
        fleet_note.setStyleSheet("color:#94a3b8; font-size:11px;")
        lay.addWidget(fleet_note)

        lay.addWidget(self._section("Enterprise readiness"))
        intro = QLabel(
            "This is a live engineering assessment, not a marketing grade. It "
            "shows which local controls are proven and keeps fleet-scale gaps "
            "visible until they are actually implemented."
        )
        intro.setWordWrap(True)
        intro.setStyleSheet("color:#94a3b8; font-size:11px;")
        lay.addWidget(intro)

        self._enterprise_score = QLabel("Assessing...")
        self._enterprise_score.setStyleSheet(
            "font-size:18px; font-weight:700; color:#38bdf8;"
        )
        lay.addWidget(self._enterprise_score)

        self._enterprise_gate_summary = QLabel("")
        self._enterprise_gate_summary.setWordWrap(True)
        self._enterprise_gate_summary.setStyleSheet(
            "color:#f59e0b; font-size:11px;"
        )
        lay.addWidget(self._enterprise_gate_summary)

        self._enterprise_report = QPlainTextEdit()
        self._enterprise_report.setReadOnly(True)
        self._enterprise_report.setMinimumHeight(360)
        self._enterprise_report.setLineWrapMode(QPlainTextEdit.WidgetWidth)
        lay.addWidget(self._enterprise_report, 1)

        buttons = QHBoxLayout()
        refresh = QPushButton("Refresh assessment")
        causal = QPushButton("Build current causal snapshot")
        copy_api = QPushButton("Copy fleet API contract")
        copy_api.setToolTip(
            "Copies the versioned OpenAPI contract for the authenticated, "
            "loopback-only fleet preview. No key or local identifier is included."
        )
        copy_evidence = QPushButton("Copy public-safe evidence")
        copy_evidence.setToolTip(
            "Copies a bounded, content-addressed readiness report without host "
            "names, user names, paths, credentials, or event payloads."
        )
        refresh.clicked.connect(self._refresh_enterprise_assessment)
        causal.clicked.connect(self._refresh_enterprise_causal)
        copy_api.clicked.connect(self._copy_fleet_api_contract)
        copy_evidence.clicked.connect(self._copy_enterprise_evidence)
        buttons.addWidget(refresh)
        buttons.addWidget(causal)
        buttons.addWidget(copy_api)
        buttons.addWidget(copy_evidence)
        buttons.addStretch()
        lay.addLayout(buttons)

        note = QLabel(
            "External Python capabilities are checked before import against a "
            "detached manifest, exact source digest, declared permissions/privacy "
            "budget, and trusted Ed25519 publisher. Remediation closures use "
            "signed, hash-chained proof receipts."
        )
        note.setWordWrap(True)
        note.setStyleSheet("color:#94a3b8; font-size:11px;")
        lay.addWidget(note)
        self._refresh_enterprise_assessment()
        return w

    def _enterprise_context(self):
        window = self.parent()
        return (
            getattr(window, "manager", None),
            getattr(window, "bus", None),
            getattr(window, "enterprise_runtime_provider", None),
        )

    def _refresh_enterprise_assessment(self) -> None:
        manager, bus, runtime_provider = self._enterprise_context()
        if manager is None or bus is None:
            self._enterprise_score.setText("Assessment unavailable")
            self._enterprise_report.setPlainText(
                "The main runtime services are not attached to this Settings window."
            )
            return
        try:
            from angerona.core.enterprise_readiness import assess, render_text
            from angerona.core.remediation_log import get_log

            runtime = (
                runtime_provider() if callable(runtime_provider) else {}
            )
            report = assess(manager, bus, self._cfg, get_log(), runtime)
            self._enterprise_assessment = report
            self._enterprise_score.setText(
                f"{report['percent']}% - {report['band']}"
            )
            gates = int(report.get("summary", {}).get("external_gates", 0))
            self._enterprise_gate_summary.setText(
                f"Deployment class: {report.get('deployment_class', 'local')}  |  "
                f"{gates} production gate(s) require external infrastructure and "
                "are not included in the local engineering score."
            )
            self._enterprise_report.setPlainText(render_text(report))
        except Exception as exc:
            self._enterprise_score.setText("Assessment error")
            self._enterprise_gate_summary.setText("")
            self._enterprise_report.setPlainText(
                f"Assessment unavailable ({type(exc).__name__})."
            )

    def _copy_enterprise_evidence(self) -> None:
        """Copy only the redacted, deterministic enterprise evidence surface."""
        try:
            from angerona.core.enterprise_readiness import evidence_pack

            report = getattr(self, "_enterprise_assessment", None)
            if not isinstance(report, dict):
                self._refresh_enterprise_assessment()
                report = getattr(self, "_enterprise_assessment", None)
            if not isinstance(report, dict):
                raise RuntimeError("readiness evidence is unavailable")
            packed = json.dumps(
                evidence_pack(report), indent=2, sort_keys=True, ensure_ascii=False
            )
            QGuiApplication.clipboard().setText(packed)
            self._enterprise_gate_summary.setText(
                "Public-safe readiness evidence copied to the clipboard."
            )
        except Exception as exc:
            self._enterprise_gate_summary.setText(
                f"Evidence copy unavailable ({type(exc).__name__})."
            )

    def _copy_fleet_api_contract(self) -> None:
        """Copy the deterministic loopback API contract without credentials."""
        try:
            from angerona.core.fleet_service import openapi_contract

            packed = json.dumps(
                openapi_contract(), indent=2, sort_keys=True, ensure_ascii=False
            )
            QGuiApplication.clipboard().setText(packed)
            self._enterprise_gate_summary.setText(
                "Versioned fleet API contract copied; no service key or local "
                "identifier is included."
            )
        except Exception as exc:
            self._enterprise_gate_summary.setText(
                f"Fleet API contract unavailable ({type(exc).__name__})."
            )

    def _refresh_enterprise_causal(self) -> None:
        manager, bus, _runtime_provider = self._enterprise_context()
        if manager is None or bus is None:
            return
        try:
            from angerona.core.causal_incident_graph import build_graph

            graph = build_graph(
                bus.recent(500),
                max_events=500,
                max_nodes=1_250,
                max_edges=2_500,
            )
            stats = graph["stats"]
            self._refresh_enterprise_assessment()
            self._enterprise_report.appendPlainText(
                "\n\nCURRENT CAUSAL SNAPSHOT\n"
                f"  incidents: {stats['incidents']}\n"
                f"  evidence nodes: {stats['nodes']}\n"
                f"  explained edges: {stats['edges']}\n"
                f"  dropped by bounds: "
                f"{stats['dropped_events'] + stats['dropped_nodes'] + stats['dropped_edges']}"
            )
        except Exception as exc:
            self._enterprise_report.appendPlainText(
                f"\n\nCausal snapshot unavailable ({type(exc).__name__})."
            )

    def _tab_integrations(self) -> QWidget:
        """Canonical, schema-validated interoperability configuration."""
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setSpacing(10)

        intro = QLabel(
            "All connectors are off until configured. SIEM delivery uses a "
            "durable retry outbox, Remote Bridge requires a protected 256-bit "
            "key, and unpinned IOC data remains advisory-only. Restart the "
            "affected module after Save."
        )
        intro.setWordWrap(True)
        intro.setStyleSheet("color:#94a3b8; font-size:11px;")
        lay.addWidget(intro)

        lay.addWidget(self._section("SIEM / CEF export"))
        siem = QGridLayout()
        self._siem_host = QLineEdit(str(getattr(self._cfg, "siem_host", "")))
        self._siem_host.setPlaceholderText("collector.example.test (blank = off)")
        self._siem_port = QLineEdit(str(getattr(self._cfg, "siem_port", 6514)))
        self._siem_port.setFixedWidth(90)
        self._siem_proto = QComboBox()
        for label, value in (
            ("TLS", "tls"),
            ("TCP (plaintext)", "tcp"),
            ("UDP (plaintext)", "udp"),
        ):
            self._siem_proto.addItem(label, value)
        index = self._siem_proto.findData(
            str(getattr(self._cfg, "siem_protocol", "tls")).casefold()
        )
        self._siem_proto.setCurrentIndex(max(0, index))
        self._siem_severity = QComboBox()
        self._siem_severity.addItems(
            ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        )
        index = self._siem_severity.findText(
            str(getattr(self._cfg, "siem_min_severity", "MEDIUM")).upper()
        )
        self._siem_severity.setCurrentIndex(max(0, index))
        self._siem_ca = QLineEdit(str(getattr(self._cfg, "siem_ca_file", "")))
        self._siem_ca.setPlaceholderText("Optional absolute CA bundle path")
        choose_ca = QPushButton("Browse…")

        def select_ca_file() -> None:
            selected, _selected_filter = QFileDialog.getOpenFileName(
                self, "Select SIEM CA bundle", self._siem_ca.text().strip()
            )
            if selected:
                self._siem_ca.setText(selected)

        choose_ca.clicked.connect(select_ca_file)
        siem.addWidget(QLabel("Collector host:"), 0, 0)
        siem.addWidget(self._siem_host, 0, 1)
        siem.addWidget(QLabel("Port:"), 0, 2)
        siem.addWidget(self._siem_port, 0, 3)
        siem.addWidget(QLabel("Transport:"), 1, 0)
        siem.addWidget(self._siem_proto, 1, 1)
        siem.addWidget(QLabel("Minimum severity:"), 1, 2)
        siem.addWidget(self._siem_severity, 1, 3)
        siem.addWidget(QLabel("TLS CA bundle:"), 2, 0)
        siem.addWidget(self._siem_ca, 2, 1, 1, 2)
        siem.addWidget(choose_ca, 2, 3)
        siem.setColumnStretch(1, 1)
        lay.addLayout(siem)
        self._siem_plaintext_chk = QCheckBox(
            "I explicitly approve plaintext TCP/UDP export"
        )
        self._siem_plaintext_chk.setChecked(
            bool(getattr(self._cfg, "siem_allow_plaintext", False))
        )
        self._siem_raw_chk = QCheckBox(
            "Include raw event summaries instead of privacy-redacted summaries"
        )
        self._siem_raw_chk.setChecked(
            bool(getattr(self._cfg, "siem_include_raw", False))
        )
        self._siem_raw_chk.setToolTip(
            "May export local identifiers and paths. Event details are still not exported."
        )
        lay.addWidget(self._siem_plaintext_chk)
        lay.addWidget(self._siem_raw_chk)

        lay.addWidget(self._section("Remote Bridge"))
        bridge = QGridLayout()
        self._bridge_mode = QComboBox()
        for label, value in (
            ("Off", ""), ("Sender", "SENDER"), ("Receiver", "RECEIVER")
        ):
            self._bridge_mode.addItem(label, value)
        index = self._bridge_mode.findData(
            str(getattr(self._cfg, "remote_bridge_mode", "")).upper()
        )
        self._bridge_mode.setCurrentIndex(max(0, index))
        self._bridge_peer = QLineEdit(
            str(getattr(self._cfg, "remote_bridge_peer", ""))
        )
        self._bridge_peer.setPlaceholderText("receiver.example.test:47924")
        self._bridge_bind = QLineEdit(
            str(getattr(self._cfg, "remote_bridge_bind", "127.0.0.1"))
        )
        self._bridge_port = QLineEdit(
            str(getattr(self._cfg, "remote_bridge_port", 47924))
        )
        self._bridge_port.setFixedWidth(90)
        self._bridge_node = QLineEdit(
            str(getattr(self._cfg, "remote_bridge_node_id", ""))
        )
        self._bridge_node.setPlaceholderText("Optional privacy-safe label")
        self._bridge_key = QLineEdit()
        self._bridge_key.setEchoMode(QLineEdit.Password)
        self._bridge_key.setPlaceholderText(
            "Leave blank to keep key; paste 64+ hexadecimal characters to replace"
        )
        bridge.addWidget(QLabel("Mode:"), 0, 0)
        bridge.addWidget(self._bridge_mode, 0, 1)
        bridge.addWidget(QLabel("Peer (sender):"), 0, 2)
        bridge.addWidget(self._bridge_peer, 0, 3)
        bridge.addWidget(QLabel("Bind (receiver):"), 1, 0)
        bridge.addWidget(self._bridge_bind, 1, 1)
        bridge.addWidget(QLabel("Port:"), 1, 2)
        bridge.addWidget(self._bridge_port, 1, 3)
        bridge.addWidget(QLabel("Node label:"), 2, 0)
        bridge.addWidget(self._bridge_node, 2, 1, 1, 3)
        bridge.addWidget(QLabel("Shared key:"), 3, 0)
        bridge.addWidget(self._bridge_key, 3, 1, 1, 3)
        bridge.setColumnStretch(1, 1)
        bridge.setColumnStretch(3, 1)
        lay.addLayout(bridge)
        self._bridge_nonloop_chk = QCheckBox(
            "I explicitly approve a non-loopback receiver bind"
        )
        self._bridge_nonloop_chk.setChecked(
            bool(getattr(self._cfg, "remote_bridge_allow_nonloopback", False))
        )
        lay.addWidget(self._bridge_nonloop_chk)

        lay.addWidget(self._section("Inbound IOC intelligence"))
        ioc = QGridLayout()
        self._ioc_url = QLineEdit(str(getattr(self._cfg, "ioc_feed_url", "")))
        self._ioc_url.setPlaceholderText("https://… (blank = off)")
        self._ioc_sha256 = QLineEdit(
            str(getattr(self._cfg, "ioc_feed_sha256", ""))
        )
        self._ioc_sha256.setPlaceholderText(
            "Optional exact 64-character response SHA-256 pin"
        )
        ioc.addWidget(QLabel("Feed URL:"), 0, 0)
        ioc.addWidget(self._ioc_url, 0, 1)
        ioc.addWidget(QLabel("Response pin:"), 1, 0)
        ioc.addWidget(self._ioc_sha256, 1, 1)
        ioc.setColumnStretch(1, 1)
        lay.addLayout(ioc)

        details = QPushButton("Explain trust and delivery details")
        details.clicked.connect(self._show_integration_details)
        lay.addWidget(details)
        storage = QLabel(
            "Durable queues: " + str(self._cfg.data_dir / "outbox")
            + "\nConnector secrets: operating-system protected credential store"
        )
        storage.setTextFormat(Qt.PlainText)
        storage.setTextInteractionFlags(Qt.TextSelectableByMouse)
        storage.setWordWrap(True)
        storage.setStyleSheet(
            "color:#94a3b8; font-family:Consolas; font-size:10px;"
        )
        lay.addWidget(storage)
        lay.addStretch()
        return w

    def _show_integration_details(self) -> None:
        QMessageBox.information(
            self,
            "Integration trust and delivery",
            "SIEM: events are staged in an authenticated, bounded SQLite outbox "
            "before its EventBus cursor advances. Delivery is at least once; "
            "stable IDs make duplicates identifiable.\n\n"
            "Remote Bridge: only HIGH/CRITICAL summaries cross the link. Peers "
            "prove the protected key, frames use AES-GCM, receivers deduplicate "
            "stable IDs, and routable listening requires separate approval.\n\n"
            "IOC feed: the client accepts bounded public HTTPS responses. Without "
            "a valid exact SHA-256 pin, matches are advisory-only and cannot "
            "authorize response. Private model chain-of-thought is never exposed.",
        )

    def _tab_aria(self) -> QWidget:
        """ARIA assistant layer — HUD, Overdrive, voice, auto-brief, inbox, research.
        Everything here is local-first, independently optional, and off by default."""
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setSpacing(10)

        def _note(text: str) -> None:
            n = QLabel(text)
            n.setWordWrap(True)
            n.setStyleSheet("color:#94a3b8; font-size:11px;")
            lay.addWidget(n)

        lay.addWidget(self._section("ARIA assistant"))
        self._aria_chk = QCheckBox("Enable ARIA (HUD + local assistant)")
        self._aria_chk.setChecked(getattr(self._cfg, "aria_enabled", False))
        lay.addWidget(self._aria_chk)
        profile_row = QHBoxLayout()
        profile_row.addWidget(QLabel("Presentation profile:"))
        self._aria_persona_combo = QComboBox()
        self._aria_persona_combo.addItems(["aria", "friday", "ultron"])
        _persona = str(getattr(self._cfg, "aria_persona", "aria") or "aria").lower()
        _pi = self._aria_persona_combo.findText(_persona)
        self._aria_persona_combo.setCurrentIndex(_pi if _pi >= 0 else 0)
        profile_row.addWidget(self._aria_persona_combo)
        profile_row.addStretch()
        lay.addLayout(profile_row)
        _note("Local, defensive-only, and disabled on a fresh install. Friday changes warmth; "
              "Ultron makes incident analysis terse and risk-ranked. Profiles never change "
              "tools, authority, or confirm-then-execute. Restart to apply the ARIA master switch.")

        lay.addWidget(self._section("ARIA Overdrive — adaptive performance governor"))
        self._aria_perf_chk = QCheckBox(
            "Scale cosmetic/UI work to live load (never throttles detection/response)")
        self._aria_perf_chk.setChecked(getattr(self._cfg, "perf_governor_enabled", False))
        lay.addWidget(self._aria_perf_chk)

        lay.addWidget(self._section("Voice (local, opt-in)"))
        self._aria_voice_chk = QCheckBox("Speak threat narration and accept voice commands ('hey aria')")
        self._aria_voice_chk.setChecked(getattr(self._cfg, "aria_voice_enabled", False))
        lay.addWidget(self._aria_voice_chk)
        self._aria_voice_cloud_chk = QCheckBox("Allow ElevenLabs cloud TTS (opt-in egress; else local SAPI/pyttsx3)")
        self._aria_voice_cloud_chk.setChecked(getattr(self._cfg, "aria_voice_cloud_tts", False))
        lay.addWidget(self._aria_voice_cloud_chk)
        self._aria_cloud_fallback_chk = QCheckBox(
            "Allow sanitized cloud-AI fallback when local Ollama is offline")
        self._aria_cloud_fallback_chk.setChecked(
            getattr(self._cfg, "aria_cloud_fallback", False))
        self._aria_cloud_fallback_chk.setToolTip(
            "Default off. Sends only the redacted question and posture band; never live "
            "alerts, runbooks, usernames, local paths, or raw telemetry.")
        lay.addWidget(self._aria_cloud_fallback_chk)
        self._alert_analysis_cloud_chk = QCheckBox(
            "Allow privacy-sanitized live-alert evidence to use cloud AI after local triage")
        self._alert_analysis_cloud_chk.setChecked(
            getattr(self._cfg, "alert_analysis_cloud_fallback", False))
        self._alert_analysis_cloud_chk.setToolTip(
            "Separate, default-off consent. When enabled, Analyze may send a bounded, "
            "recursively redacted alert summary to the configured cloud provider. "
            "Credentials, identities, local paths, URLs, and network addresses are removed.")
        lay.addWidget(self._alert_analysis_cloud_chk)
        # Microphone source: computer mic by default, or an added/external device.
        mrow = QHBoxLayout()
        mrow.addWidget(QLabel("Microphone:"))
        self._aria_mic_combo = QComboBox()
        self._aria_mic_combo.addItem("Computer microphone (default)", "")
        try:
            from angerona.connectors.voice import Voice
            for _idx, _name in Voice.list_input_devices():
                self._aria_mic_combo.addItem(f"Added mic — {_name}", str(_idx))
        except Exception:
            pass
        _saved_mic = str(getattr(self._cfg, "aria_mic_device", "") or "")
        _mi = self._aria_mic_combo.findData(_saved_mic)
        self._aria_mic_combo.setCurrentIndex(_mi if _mi >= 0 else 0)
        mrow.addWidget(self._aria_mic_combo, 1)
        lay.addLayout(mrow)
        model_row = QHBoxLayout()
        self._aria_model_btn = QPushButton("Download verified offline speech model (39 MB)")
        self._aria_model_btn.clicked.connect(self._install_voice_model)
        try:
            from angerona.connectors.voice import offline_model_status
            _model_ready, _model_note = offline_model_status()
        except Exception:
            _model_ready, _model_note = False, "Speech model status unavailable"
        self._aria_model_btn.setEnabled(not _model_ready)
        self._aria_model_status = QLabel(
            ("Ready — " if _model_ready else "Not ready — ") + _model_note)
        self._aria_model_status.setWordWrap(True)
        model_row.addWidget(self._aria_model_btn)
        model_row.addWidget(self._aria_model_status, 1)
        lay.addLayout(model_row)
        _note("Uses your computer's built-in microphone by default; pick an added/external mic "
              "here if you have one. A live level bar next to ARIA shows when it can hear you. "
              "Needs a local TTS/STT backend (pyttsx3/SAPI, vosk/whisper) — install via ARIA "
              "('install voice'). Degrades silently if absent; the mic stays off unless enabled.")

        lay.addWidget(self._section("Conversational awareness (local, transient, opt-in)"))
        self._aria_awareness_chk = QCheckBox(
            "Remember a short room discussion and allow no-wake follow-up questions")
        self._aria_awareness_chk.setChecked(
            getattr(self._cfg, "aria_conversation_awareness", False))
        lay.addWidget(self._aria_awareness_chk)
        self._aria_always_listen_chk = QCheckBox(
            "Always-listen: accept every multi-word utterance without saying ARIA")
        self._aria_always_listen_chk.setChecked(
            getattr(self._cfg, "aria_always_listen", False))
        lay.addWidget(self._aria_always_listen_chk)
        follow_row = QHBoxLayout()
        follow_row.addWidget(QLabel("No-wake follow-up window (seconds):"))
        self._aria_follow_up = QLineEdit(str(
            getattr(self._cfg, "aria_follow_up_seconds", 12)))
        self._aria_follow_up.setFixedWidth(60)
        follow_row.addWidget(self._aria_follow_up)
        follow_row.addStretch()
        lay.addLayout(follow_row)
        _note("Awareness keeps only a bounded, redacted in-memory window and discards it when "
              "ARIA stops. It suppresses likely speaker echo and accepts 'stop', 'wait', or "
              "'quiet' while ARIA is speaking. Always-listen requires voice + awareness and "
              "has a larger privacy footprint; wake-word mode is the safer choice.")

        lay.addWidget(self._section("Hand controls (local camera, opt-in)"))
        self._aria_hands_chk = QCheckBox("Enable camera hand-gesture navigation")
        self._aria_hands_chk.setChecked(getattr(self._cfg, "aria_hand_controls", False))
        lay.addWidget(self._aria_hands_chk)
        camera_row = QHBoxLayout()
        camera_row.addWidget(QLabel("Camera index:"))
        self._aria_camera_index = QLineEdit(str(
            getattr(self._cfg, "aria_camera_index", 0)))
        self._aria_camera_index.setFixedWidth(60)
        camera_row.addWidget(self._aria_camera_index)
        try:
            from angerona.connectors.hand_controls import HandControls
            _hand_status = HandControls(enabled=True).status()
        except Exception:
            _hand_status = "hand controls unavailable"
        self._aria_hand_status = QLabel(_hand_status)
        self._aria_hand_status.setWordWrap(True)
        camera_row.addWidget(self._aria_hand_status, 1)
        lay.addLayout(camera_row)
        _note("Open palm focuses the ARIA prompt; swipe left/right changes evidence tabs; "
              "victory opens Help; fist interrupts speech and cancels a pending ARIA action. "
              "Pinch/point/thumbs-up only focus or acknowledge navigation. Gestures never "
              "confirm a write. Frames are processed locally and are never saved or uploaded. "
              "Install the optional 'hand-controls' capability if OpenCV/MediaPipe are missing.")

        lay.addWidget(self._section("Auto-brief a channel (outbound, opt-in)"))
        self._aria_push_chk = QCheckBox("Push CRITICAL posture to a channel")
        self._aria_push_chk.setChecked(getattr(self._cfg, "aria_push_enabled", False))
        lay.addWidget(self._aria_push_chk)
        prow = QHBoxLayout()
        prow.addWidget(QLabel("Kind:"))
        self._aria_push_kind = QComboBox()
        self._aria_push_kind.addItems(["slack", "teams", "ntfy", "webhook"])
        _ci = self._aria_push_kind.findText(getattr(self._cfg, "aria_push_kind", "slack"))
        if _ci >= 0:
            self._aria_push_kind.setCurrentIndex(_ci)
        prow.addWidget(self._aria_push_kind)
        prow.addWidget(QLabel("Webhook URL:"))
        self._aria_push_url = QLineEdit(getattr(self._cfg, "aria_push_url", ""))
        self._aria_push_url.setPlaceholderText("https://hooks.slack.com/services/…")
        prow.addWidget(self._aria_push_url, 1)
        lay.addLayout(prow)
        _note("Off by default. Only sends text you'd already see (secret-redacted) — never raw "
              "telemetry, files, or credentials.")

        lay.addWidget(self._section("Email scanning (inbox phishing triage)"))
        self._aria_inbox_chk = QCheckBox("Scan a mailbox for phishing (read-only IMAP, local scoring)")
        self._aria_inbox_chk.setChecked(getattr(self._cfg, "aria_inbox_enabled", False))
        lay.addWidget(self._aria_inbox_chk)
        igrid = QGridLayout()
        igrid.setColumnStretch(1, 1)
        igrid.addWidget(QLabel("IMAP host:"), 0, 0)
        self._aria_imap_host = QLineEdit(getattr(self._cfg, "aria_imap_host", ""))
        self._aria_imap_host.setPlaceholderText("imap.gmail.com")
        igrid.addWidget(self._aria_imap_host, 0, 1)
        igrid.addWidget(QLabel("Mailbox:"), 1, 0)
        self._aria_imap_user = QLineEdit(getattr(self._cfg, "aria_imap_user", ""))
        self._aria_imap_user.setPlaceholderText("you@example.com")
        igrid.addWidget(self._aria_imap_user, 1, 1)
        igrid.addWidget(QLabel("Password / app-password:"), 2, 0)
        from angerona.core.secure_store import read_secret_values

        protected_secrets = read_secret_values(
            ("ARIA_IMAP_PASS", "ANGERONA_TEAMS_APP_PASSWORD"),
            self._cfg.data_dir,
        )
        self._initial_connector_secret_values = dict(protected_secrets)
        self._aria_imap_pass = QLineEdit(
            protected_secrets.get("ARIA_IMAP_PASS", "")
        )
        self._aria_imap_pass.setEchoMode(QLineEdit.Password)
        self._aria_imap_pass.setPlaceholderText(
            "protected by the operating-system credential store"
        )
        igrid.addWidget(self._aria_imap_pass, 2, 1)
        igrid.addWidget(QLabel("Scan every (min):"), 3, 0)
        self._aria_inbox_interval = QLineEdit(str(getattr(self._cfg, "aria_inbox_interval_min", 5)))
        self._aria_inbox_interval.setFixedWidth(60)
        igrid.addWidget(self._aria_inbox_interval, 3, 1, Qt.AlignLeft)
        lay.addLayout(igrid)
        _note("Gmail / Outlook with 2FA need an app-password. Read-only: never marks read, moves, "
              "or deletes. Scoring is 100% local; flagged mail becomes an alert on the bus.")

        lay.addWidget(self._section("Research"))
        self._aria_egress_chk = QCheckBox(
            "Allow headless research fetches (else open vetted lookups in the browser)")
        self._aria_egress_chk.setChecked(getattr(self._cfg, "aria_research_egress", False))
        lay.addWidget(self._aria_egress_chk)
        _note("Research classifies an indicator (hash / IP / domain / CVE) and uses only allow-listed "
              "reputation/advisory sites (VirusTotal, NVD, CISA KEV, AbuseIPDB, URLhaus).")

        lay.addWidget(self._section("Microsoft Teams bot (two-way, opt-in)"))
        self._teams_chk = QCheckBox("Chat with ARIA from Microsoft Teams (needs an Azure Bot)")
        self._teams_chk.setChecked(getattr(self._cfg, "teams_bot_enabled", False))
        lay.addWidget(self._teams_chk)
        tgrid = QGridLayout()
        tgrid.setColumnStretch(1, 1)
        tgrid.addWidget(QLabel("App (client) ID:"), 0, 0)
        self._teams_app_id = QLineEdit(getattr(self._cfg, "teams_app_id", ""))
        self._teams_app_id.setPlaceholderText("Azure Bot Microsoft App ID")
        tgrid.addWidget(self._teams_app_id, 0, 1)
        tgrid.addWidget(QLabel("App password:"), 1, 0)
        self._teams_pw = QLineEdit(
            protected_secrets.get("ANGERONA_TEAMS_APP_PASSWORD", "")
        )
        self._teams_pw.setEchoMode(QLineEdit.Password)
        self._teams_pw.setPlaceholderText(
            "protected by the operating-system credential store"
        )
        tgrid.addWidget(self._teams_pw, 1, 1)
        tgrid.addWidget(QLabel("Allowed Teams AAD object ID(s):"), 2, 0)
        self._teams_users = QLineEdit(getattr(self._cfg, "teams_allowed_users", ""))
        self._teams_users.setPlaceholderText("immutable AAD object IDs (comma-separated)")
        tgrid.addWidget(self._teams_users, 2, 1)
        tgrid.addWidget(QLabel("Endpoint port:"), 3, 0)
        self._teams_port = QLineEdit(str(getattr(self._cfg, "teams_bot_port", 3978)))
        self._teams_port.setFixedWidth(80)
        tgrid.addWidget(self._teams_port, 3, 1, Qt.AlignLeft)
        lay.addLayout(tgrid)
        self._teams_skip_chk = QCheckBox(
            "JWT bypass unavailable in saved settings (direct-loopback tests only)"
        )
        self._teams_skip_chk.setChecked(False)
        self._teams_skip_chk.setEnabled(False)
        lay.addWidget(self._teams_skip_chk)
        _note("Create an Azure Bot, set its messaging endpoint to https://<your-tunnel>/api/messages, "
              "add the Microsoft Teams channel, then 'pip install pyjwt'. Only your allow-listed user "
              "is answered; chat/reads only (no remote state changes). Restart to apply.")

        lay.addWidget(self._section("Verify setup"))
        trow = QHBoxLayout()
        b_voice = QPushButton("\U0001F50A  Test voice")
        b_email = QPushButton("✉  Test email")
        b_push  = QPushButton("\U0001F4E3  Test channel push")
        b_teams = QPushButton("\U0001F4AC  Test Teams creds")
        b_voice.clicked.connect(self._aria_test_voice)
        b_email.clicked.connect(self._aria_test_email)
        b_push.clicked.connect(self._aria_test_push)
        b_teams.clicked.connect(self._aria_test_teams)
        trow.addWidget(b_voice); trow.addWidget(b_email); trow.addWidget(b_push)
        trow.addWidget(b_teams); trow.addStretch()
        lay.addLayout(trow)
        self._aria_test_status = QLabel("Save first, then use these to verify each feature end-to-end.")
        self._aria_test_status.setWordWrap(True)
        self._aria_test_status.setStyleSheet("color:#94a3b8; font-size:11px;")
        lay.addWidget(self._aria_test_status)

        lay.addStretch()
        return w

    # ── ARIA setup: live verification (each runs off-thread; result via signal) ─
    def _install_voice_model(self) -> None:
        """The only in-app path that may download a Vosk model: explicit click."""
        self._aria_model_btn.setEnabled(False)
        self._aria_model_status.setText("Downloading and verifying 39 MB to Angerona data…")
        self._voice_model_loading_token = begin_loading(
            "Downloading and verifying offline speech model…"
        )

        def _run() -> None:
            try:
                from angerona.connectors.voice import install_offline_model, offline_model_status
                message = install_offline_model()
                ready, _path = offline_model_status()
            except Exception as exc:
                message = f"Speech model setup failed: {exc}"
                ready = False
            self.voice_model_result.emit(message, ready)
        threading.Thread(target=_run, name="VoiceModelInstall", daemon=True).start()

    def _voice_model_finished(self, message: str, ready: bool) -> None:
        finish_loading(self._voice_model_loading_token)
        self._voice_model_loading_token = None
        self._aria_model_status.setText(message)
        self._aria_model_btn.setEnabled(not ready)
        self._aria_test_status.setText(message)

    def _aria_test_voice(self) -> None:
        self._aria_test_status.setText("Speaking a test line…")
        self._aria_test_loading_tokens.append(begin_loading("Testing local voice…"))

        def _run() -> None:
            try:
                from angerona.connectors.voice import Voice
                v = Voice(enabled=True, allow_cloud_tts=self._aria_voice_cloud_chk.isChecked())
                ok = v.speak("ARIA voice test. Angerona narration is online.")
                msg = (f"Voice OK — you should have heard ARIA.  ({v.status()})" if ok
                       else f"No audio produced. {v.last_error or 'no TTS backend found'}")
            except Exception as exc:
                msg = f"Voice test error: {exc}"
            self.aria_test_result.emit(msg)
        threading.Thread(target=_run, daemon=True).start()

    def _aria_test_email(self) -> None:
        host = self._aria_imap_host.text().strip()
        user = self._aria_imap_user.text().strip()
        pw   = self._aria_imap_pass.text()
        if not (host and user and pw):
            self._aria_test_status.setText("Enter IMAP host, mailbox, and password first.")
            return
        self._aria_test_status.setText(f"Connecting to {host} as {user}…")
        self._aria_test_loading_tokens.append(begin_loading("Retrieving mailbox status…"))

        def _run() -> None:
            try:
                from angerona.connectors.inbox_watcher import InboxWatcher
                w = InboxWatcher(host=host, user=user, password=pw, limit=15)
                r = w.test_connection()
                msg = (f"Email OK — scanned {r['scanned']} message(s), flagged {r['flagged']} suspicious."
                       if r["ok"] else f"Email connect failed: {r['error']}")
            except Exception as exc:
                msg = f"Email test error: {exc}"
            self.aria_test_result.emit(msg)
        threading.Thread(target=_run, daemon=True).start()

    def _aria_test_push(self) -> None:
        url = self._aria_push_url.text().strip()
        if not url:
            self._aria_test_status.setText("Enter a webhook URL first.")
            return
        kind = self._aria_push_kind.currentText()
        self._aria_test_status.setText(f"Sending a test message to your {kind} webhook…")
        self._aria_test_loading_tokens.append(begin_loading("Testing notification channel…"))

        def _run() -> None:
            try:
                from angerona.connectors.channel_push import ChannelPush, Target
                cp = ChannelPush(enabled=True, targets=[Target(kind, url)])
                res = cp.push("Angerona ARIA — channel push test. If you can read this, it works.",
                              level="CRITICAL")
                r0 = res[0] if res else None
                msg = (f"Push OK — delivered (HTTP {r0.status})." if r0 and r0.ok
                       else f"Push failed: {(r0.reason if r0 else 'no target')}.")
            except Exception as exc:
                msg = f"Push test error: {exc}"
            self.aria_test_result.emit(msg)
        threading.Thread(target=_run, daemon=True).start()

    def _aria_test_teams(self) -> None:
        app_id = self._teams_app_id.text().strip()
        pw = self._teams_pw.text().strip()
        if not (app_id and pw):
            self._aria_test_status.setText("Enter the Teams App ID and password first.")
            return
        self._aria_test_status.setText("Validating Teams bot credentials with Azure…")
        self._aria_test_loading_tokens.append(begin_loading("Validating Teams connection…"))

        def _run() -> None:
            try:
                from angerona.connectors.teams_bot import TeamsBot
                bot = TeamsBot(enabled=True, app_id=app_id, app_password=pw)
                token = bot._get_token()          # real OAuth against Azure (no tunnel needed)
                if token:
                    msg = ("Teams credentials OK — Azure issued a bot token. Finish setup: set "
                           "the messaging endpoint to https://<tunnel>/api/messages, add the "
                           "Teams channel, and 'pip install pyjwt' for inbound auth.")
                else:
                    msg = f"No token returned. {bot.last_error or 'check App ID / password'}"
            except Exception as exc:
                msg = f"Teams test error: {exc}"
            self.aria_test_result.emit(msg)
        threading.Thread(target=_run, daemon=True).start()

    def _aria_test_finished(self, message: str) -> None:
        self._aria_test_status.setText(message)
        if self._aria_test_loading_tokens:
            finish_loading(self._aria_test_loading_tokens.pop(0))

    def _tab_trusted_processes(self) -> QWidget:
        """Operator-supervised process learning and exact allowlisting."""
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setSpacing(8)
        lay.addWidget(self._section("Trusted process policy"))
        note = QLabel(
            "Trusted executables are excluded from process-attributed threat posture and "
            "automatic response. Angerona discovers candidates, but never silently trusts "
            "them: select only software you recognize. Exact executable paths are safest.")
        note.setWordWrap(True)
        note.setStyleSheet("color:#f59e0b; font-size:11px;")
        lay.addWidget(note)

        self._trusted_process_list = QListWidget()
        self._trusted_process_list.setMinimumHeight(120)
        lay.addWidget(self._trusted_process_list)

        add_row = QHBoxLayout()
        self._trusted_process_name = QLineEdit()
        self._trusted_process_name.setPlaceholderText("Exact process name, e.g. ProtonVPN.Client.exe")
        add_name = QPushButton("Trust name")
        browse = QPushButton("Browse executable…")
        remove = QPushButton("Remove selected")
        add_name.clicked.connect(self._trust_process_name)
        browse.clicked.connect(self._browse_trusted_process)
        remove.clicked.connect(self._remove_trusted_process)
        add_row.addWidget(self._trusted_process_name, 1)
        add_row.addWidget(add_name)
        add_row.addWidget(browse)
        add_row.addWidget(remove)
        lay.addLayout(add_row)

        lay.addWidget(self._section("Conservative normal-process learning"))
        self._process_baseline_chk = QCheckBox(
            "Learn stable signed executables and suggest them for review"
        )
        self._process_baseline_chk.setChecked(
            bool(getattr(self._cfg, "process_baseline_enabled", False))
        )
        self._process_baseline_chk.setToolTip(
            "Opt-in and local only. Observation never suppresses an alert. "
            "A candidate needs repeated observations across separate UTC days, "
            "a protected Windows/Program Files location, valid Authenticode, "
            "and an explicit Approve action."
        )
        lay.addWidget(self._process_baseline_chk)
        baseline_note = QLabel(
            "Learning stores only executable identity metadata locally: exact path, "
            "SHA-256, publisher, first/last observation, and counts. It never stores "
            "command lines, usernames, parent processes, or network activity. A "
            "changed executable becomes a new candidate and an approved hash mismatch "
            "immediately stops matching trust."
        )
        baseline_note.setWordWrap(True)
        baseline_note.setStyleSheet("color:#94a3b8; font-size:11px;")
        lay.addWidget(baseline_note)
        self._baseline_candidate_list = QListWidget()
        self._baseline_candidate_list.setMinimumHeight(150)
        lay.addWidget(self._baseline_candidate_list)
        baseline_row = QHBoxLayout()
        refresh_baseline = QPushButton("Refresh learned candidates")
        approve_baseline = QPushButton("Approve eligible candidate")
        dismiss_baseline = QPushButton("Dismiss for 30 days")
        reset_baseline = QPushButton("Reset learned state")
        refresh_baseline.clicked.connect(self._refresh_process_baseline)
        approve_baseline.clicked.connect(self._approve_process_baseline)
        dismiss_baseline.clicked.connect(self._dismiss_process_baseline)
        reset_baseline.clicked.connect(self._reset_process_baseline)
        for button in (
            refresh_baseline,
            approve_baseline,
            dismiss_baseline,
            reset_baseline,
        ):
            baseline_row.addWidget(button)
        baseline_row.addStretch(1)
        lay.addLayout(baseline_row)
        self._baseline_action_buttons = (
            approve_baseline,
            dismiss_baseline,
            reset_baseline,
        )
        self._baseline_status = QLabel("")
        self._baseline_status.setWordWrap(True)
        self._baseline_status.setStyleSheet("color:#94a3b8; font-size:11px;")
        lay.addWidget(self._baseline_status)

        lay.addWidget(self._section("Supervised learning — processes running now"))
        learn_note = QLabel(
            "Scan the current system, select a recognized executable, then trust its exact "
            "path immediately. This manual path remains available when a legitimate "
            "unsigned or user-installed application cannot qualify for conservative "
            "baseline review.")
        learn_note.setWordWrap(True)
        learn_note.setStyleSheet("color:#94a3b8; font-size:11px;")
        lay.addWidget(learn_note)
        self._running_process_list = QListWidget()
        self._running_process_list.setMinimumHeight(150)
        lay.addWidget(self._running_process_list)
        learn_row = QHBoxLayout()
        scan = QPushButton("Scan running processes")
        trust_selected = QPushButton("Trust selected exact path")
        scan.clicked.connect(self._scan_running_processes)
        trust_selected.clicked.connect(self._trust_selected_process)
        learn_row.addWidget(scan)
        learn_row.addWidget(trust_selected)
        learn_row.addStretch(1)
        self._trusted_process_status = QLabel("")
        self._trusted_process_status.setStyleSheet("color:#94a3b8; font-size:11px;")
        learn_row.addWidget(self._trusted_process_status)
        lay.addLayout(learn_row)

        self._refresh_trusted_processes()
        self._refresh_process_baseline()
        return w

    def _refresh_trusted_processes(self) -> None:
        from angerona.core import process_allowlist
        self._trusted_process_list.clear()
        for row in process_allowlist.entries(self._cfg.data_dir):
            label = row.get("path") or row.get("name") or "(unnamed)"
            digest = str(row.get("sha256") or "")
            source = str(row.get("source") or "legacy")
            binding = "hash-bound" if digest else "legacy path/name only"
            item = QListWidgetItem(f"{label}  [{binding}; {source}]")
            tooltip = (
                "Exact path" if row.get("path") else
                "Exact basename — applies only to pathless telemetry"
            )
            if digest:
                tooltip += f"\nSHA-256: {digest}"
            else:
                tooltip += (
                    "\nLegacy policy is not bound to file contents. Browse/re-approve "
                    "the executable to add a SHA-256 binding."
                )
            if row.get("publisher"):
                tooltip += f"\nPublisher: {row.get('publisher')}"
            item.setToolTip(tooltip)
            item.setData(Qt.UserRole, row.get("id"))
            self._trusted_process_list.addItem(item)

    def _refresh_process_baseline(self) -> None:
        learner = self._process_baseline
        self._baseline_candidate_list.clear()
        if learner is None:
            self._baseline_status.setText(
                "Normal-process learning is unavailable in this launch mode."
            )
            self._process_baseline_chk.setEnabled(False)
            for button in self._baseline_action_buttons:
                button.setEnabled(False)
            return
        snapshot = learner.snapshot()
        integrity_error = str(snapshot.get("integrity_error") or "")
        candidates = snapshot.get("candidates") or []
        for row in candidates:
            observations = int(row.get("observations", 0))
            days = len(row.get("days") or ())
            if row.get("eligible"):
                stage = "READY FOR OPERATOR REVIEW"
            elif not row.get("trusted_root"):
                stage = "MANUAL REVIEW ONLY — unprotected install location"
            elif str(row.get("signature_status", "")).casefold() != "valid":
                stage = (
                    "MANUAL REVIEW ONLY — Authenticode "
                    f"{row.get('signature_status') or 'unavailable'}"
                )
            else:
                stage = (
                    f"LEARNING — {observations}/3 observations, "
                    f"{days}/2 UTC days"
                )
            item = QListWidgetItem(
                f"{row.get('name', '?')}  —  {stage}\n"
                f"{row.get('path', '')}"
            )
            item.setData(Qt.UserRole, row.get("id"))
            item.setData(Qt.UserRole + 1, bool(row.get("eligible")))
            item.setToolTip(
                f"SHA-256: {row.get('sha256', '')}\n"
                f"Publisher: {row.get('publisher') or '(not available)'}\n"
                f"Root: {row.get('root_class') or '(not protected)'}\n"
                f"First seen: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(row.get('first_seen', 0))))}\n"
                f"Last seen: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(row.get('last_seen', 0))))}\n"
                f"Assessment: {row.get('reason', '')}"
            )
            self._baseline_candidate_list.addItem(item)
        metrics = snapshot.get("metrics") or {}
        if integrity_error:
            self._baseline_status.setText(
                "INTEGRITY LOCK: learned state could not be authenticated. "
                f"{integrity_error} Use Reset learned state to quarantine it."
            )
        else:
            self._baseline_status.setText(
                f"{len(candidates)} candidate(s) · "
                f"{metrics.get('accepted', 0)} accepted observation(s) · "
                f"{metrics.get('rejected', 0)} rejected · "
                f"{metrics.get('dropped', 0)} queue drop(s) · "
                f"queue {snapshot.get('queue_depth', 0)}/"
                f"{snapshot.get('queue_capacity', 0)}"
            )
        self._baseline_action_buttons[0].setEnabled(
            not integrity_error
            and any(bool(row.get("eligible")) for row in candidates)
        )
        self._baseline_action_buttons[1].setEnabled(
            not integrity_error and bool(candidates)
        )
        self._baseline_action_buttons[2].setEnabled(True)

    def _selected_process_baseline(self) -> tuple[str, bool]:
        item = self._baseline_candidate_list.currentItem()
        if item is None:
            return "", False
        return (
            str(item.data(Qt.UserRole) or ""),
            bool(item.data(Qt.UserRole + 1)),
        )

    def _run_process_baseline_action(self, label: str, action) -> None:
        for button in self._baseline_action_buttons:
            button.setEnabled(False)
        self._baseline_status.setText(f"{label}…")

        def _run() -> None:
            try:
                action()
                self.process_baseline_result.emit(f"{label}: complete.", True)
            except Exception as exc:
                self.process_baseline_result.emit(f"{label}: {exc}", False)

        threading.Thread(
            target=_run,
            daemon=True,
            name="ProcessBaselineAction",
        ).start()

    def _approve_process_baseline(self) -> None:
        candidate_id, eligible = self._selected_process_baseline()
        if not candidate_id:
            self._baseline_status.setText("Select a learned candidate first.")
            return
        if not eligible:
            self._baseline_status.setText(
                "That candidate is not eligible for conservative approval. "
                "Use the manual exact-path review below if you recognize it."
            )
            return
        self._run_process_baseline_action(
            "Revalidating and approving candidate",
            lambda: self._process_baseline.approve(candidate_id),
        )

    def _dismiss_process_baseline(self) -> None:
        candidate_id, _eligible = self._selected_process_baseline()
        if not candidate_id:
            self._baseline_status.setText("Select a learned candidate first.")
            return
        self._run_process_baseline_action(
            "Dismissing candidate for 30 days",
            lambda: self._process_baseline.dismiss(candidate_id),
        )

    def _reset_process_baseline(self) -> None:
        if QMessageBox.question(
            self,
            "Reset learned process state",
            "Quarantine all learned candidates and counters, then create a new "
            "empty authenticated state? Trusted-process approvals are not removed.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        ) != QMessageBox.StandardButton.Yes:
            return
        self._run_process_baseline_action(
            "Resetting authenticated learned state",
            self._process_baseline.reset_state,
        )

    def _process_baseline_action_finished(self, message: str, ok: bool) -> None:
        self._refresh_trusted_processes()
        self._refresh_process_baseline()
        self._baseline_status.setStyleSheet(
            f"color:{'#22c55e' if ok else '#ef4444'}; font-size:11px;"
        )
        self._baseline_status.setText(message)

    def _trust_process_name(self) -> None:
        from angerona.core import process_allowlist
        name = self._trusted_process_name.text().strip()
        try:
            process_allowlist.add(name=name, data_dir=self._cfg.data_dir)
        except Exception as exc:
            QMessageBox.warning(self, "Trust process", str(exc))
            return
        self._trusted_process_name.clear()
        self._refresh_trusted_processes()

    def _browse_trusted_process(self) -> None:
        from angerona.core import process_allowlist
        path, _ = QFileDialog.getOpenFileName(
            self, "Choose a trusted executable", "", "Executables (*.exe);;All files (*.*)")
        if not path:
            return
        try:
            process_allowlist.add(path=path, data_dir=self._cfg.data_dir)
        except Exception as exc:
            QMessageBox.warning(self, "Trust process", str(exc))
            return
        self._refresh_trusted_processes()

    def _remove_trusted_process(self) -> None:
        from angerona.core import process_allowlist
        item = self._trusted_process_list.currentItem()
        if item is None:
            return
        process_allowlist.remove(str(item.data(Qt.UserRole) or ""), self._cfg.data_dir)
        self._refresh_trusted_processes()

    def _scan_running_processes(self) -> None:
        from angerona.core import process_allowlist
        self._running_process_list.clear()
        rows = process_allowlist.running_processes()
        for row in rows:
            if process_allowlist.is_allowed(row.get("name", ""), row.get("path", ""),
                                              self._cfg.data_dir):
                continue
            label = f"{row.get('name', '?')}  —  {row.get('path') or 'path unavailable'}"
            item = QListWidgetItem(label)
            item.setData(Qt.UserRole, row)
            self._running_process_list.addItem(item)
        self._trusted_process_status.setText(
            f"{self._running_process_list.count()} candidate(s)")

    def _trust_selected_process(self) -> None:
        from angerona.core import process_allowlist
        item = self._running_process_list.currentItem()
        if item is None:
            return
        row = item.data(Qt.UserRole) or {}
        if not row.get("path"):
            if QMessageBox.question(
                    self, "Trust by name",
                    f"The exact path for {row.get('name', 'this process')} is unavailable. "
                    "Trust its basename everywhere instead?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
                return
        try:
            process_allowlist.add(row.get("name", ""), row.get("path", ""),
                                  self._cfg.data_dir)
        except Exception as exc:
            QMessageBox.warning(self, "Trust process", str(exc))
            return
        self._refresh_trusted_processes()
        self._scan_running_processes()

    def _tab_mobile(self) -> QWidget:
        """Mobile Response Bridge (Signal) config."""
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setSpacing(10)
        lay.addWidget(self._section("Mobile Response Bridge (Signal / signal-cli)"))

        self._mob_chk = QCheckBox("Enable Mobile Response Bridge")
        self._mob_chk.setChecked(getattr(self._cfg, "mobile_enabled", False))
        lay.addWidget(self._mob_chk)

        warn = QLabel(
            "⚠  Requires signal-cli installed and a registered Signal phone number. "
            "The executable must match both an exact SHA-256 and Authenticode subject. "
            "Commands are rate-limited and PIN-gated; the PIN stays in the operating-"
            "system protected credential store — never in plain text."
        )
        warn.setWordWrap(True)
        warn.setStyleSheet("color: #f59e0b; font-size: 11px;")
        lay.addWidget(warn)

        grid = QGridLayout(); grid.setColumnStretch(1, 1)
        grid.addWidget(QLabel("signal-cli path:"), 0, 0)
        self._mob_cli = QLineEdit(getattr(self._cfg, "mobile_signal_cli", ""))
        self._mob_cli.setPlaceholderText("C:\\Program Files\\signal-cli\\signal-cli.exe")
        grid.addWidget(self._mob_cli, 0, 1)
        self._mob_browse = QPushButton("Browse…")
        self._mob_browse.clicked.connect(self._browse_signal_cli)
        grid.addWidget(self._mob_browse, 0, 2)

        grid.addWidget(QLabel("Executable SHA-256 pin:"), 1, 0)
        self._mob_sha256 = QLineEdit(
            getattr(self._cfg, "mobile_signal_cli_sha256", "")
        )
        self._mob_sha256.setMaxLength(64)
        self._mob_sha256.setPlaceholderText("64 lowercase hexadecimal characters")
        grid.addWidget(self._mob_sha256, 1, 1, 1, 2)

        grid.addWidget(QLabel("Authenticode subject pin:"), 2, 0)
        self._mob_publisher = QLineEdit(
            getattr(self._cfg, "mobile_signal_cli_publisher", "")
        )
        self._mob_publisher.setMaxLength(512)
        self._mob_publisher.setPlaceholderText("Exact signer certificate Subject")
        grid.addWidget(self._mob_publisher, 2, 1, 1, 2)

        grid.addWidget(QLabel("Host number (this machine):"), 3, 0)
        self._mob_host = QLineEdit(getattr(self._cfg, "mobile_host_number", ""))
        self._mob_host.setPlaceholderText("+15551234567")
        grid.addWidget(self._mob_host, 3, 1, 1, 2)

        grid.addWidget(QLabel("Operator destination #:"), 4, 0)
        self._mob_dest = QLineEdit(getattr(self._cfg, "mobile_dest_number", ""))
        self._mob_dest.setPlaceholderText("+15557654321")
        grid.addWidget(self._mob_dest, 4, 1, 1, 2)

        grid.addWidget(QLabel("Hardware PIN (4-digit):"), 5, 0)
        self._mob_pin = QLineEdit()
        self._mob_pin.setEchoMode(QLineEdit.Password)
        self._mob_pin.setMaxLength(4)
        self._mob_pin.setPlaceholderText("•••• (leave blank to keep existing)")
        try:
            from PySide6.QtGui import QIntValidator
            self._mob_pin.setValidator(QIntValidator(0, 9999, self._mob_pin))
        except Exception:
            pass
        grid.addWidget(self._mob_pin, 5, 1, 1, 2)
        lay.addLayout(grid)

        note = QLabel(
            "The PIN uses current-user DPAPI on Windows, Keychain on macOS, or "
            "Secret Service on Linux. Type HELP from your phone for the command menu."
        )
        note.setWordWrap(True); note.setStyleSheet("color: #94a3b8; font-size: 11px;")
        lay.addWidget(note)

        self._mob_fields = [
            self._mob_cli,
            self._mob_browse,
            self._mob_sha256,
            self._mob_publisher,
            self._mob_host,
            self._mob_dest,
            self._mob_pin,
        ]
        def _lock(on: bool) -> None:
            for f in self._mob_fields:
                f.setEnabled(on)
        _lock(self._mob_chk.isChecked())
        self._mob_chk.toggled.connect(_lock)

        lay.addStretch()
        return w

    def _browse_signal_cli(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Locate signal-cli", "",
                                              "signal-cli (signal-cli*);;All files (*.*)")
        if path:
            self._mob_cli.setText(path)

    def _tab_apikeys(self) -> QWidget:
        w   = QWidget()
        lay = QVBoxLayout(w)
        lay.setSpacing(8)

        info = QLabel(HELP_TEXT_SHORT)
        info.setWordWrap(True)
        info.setStyleSheet("color: #94a3b8; font-size: 11px;")
        lay.addWidget(info)

        lay.addWidget(self._section("Cloud escalation API keys (optional)"))

        from angerona.core.provider_credentials import (
            PROVIDER_CREDENTIALS,
            provider_form_values,
        )

        grid = QGridLayout()
        grid.setColumnStretch(1, 1)
        current_values = provider_form_values()
        self._initial_key_values = dict(current_values)
        self._api_keys_dirty = False
        self._key_fields: dict[str, QLineEdit] = {}
        for _row, provider in enumerate(PROVIDER_CREDENTIALS):
            label = provider.label
            if provider.supports_pool:
                label += " (comma-separated pool)"
            grid.addWidget(QLabel(f"{label}:"), _row, 0)
            field = QLineEdit(current_values[provider.provider_id])
            field.setEchoMode(QLineEdit.Password)
            field.setPlaceholderText("(not set — clear and Save to remove)")
            grid.addWidget(field, _row, 1)
            self._key_fields[provider.provider_id] = field
            field.textChanged.connect(self._mark_api_keys_dirty)
        lay.addLayout(grid)

        btn_keys = QPushButton("Save keys")
        btn_keys.setFixedWidth(110)
        btn_keys.clicked.connect(lambda: self._save_api_keys(notify=True))
        lay.addWidget(btn_keys)

        lay.addWidget(self._section("Online AI consult order (first with a key wins)"))
        order_info = QLabel(
            "Use ▲ / ▼ to reorder. Consult AI, Sandbox Ask-AI, and SOAR AI review "
            "all try providers top-to-bottom; the first one with a key set above wins."
        )
        order_info.setWordWrap(True); order_info.setStyleSheet("color: #94a3b8; font-size: 11px;")
        lay.addWidget(order_info)

        _labels = {provider.provider_id: provider.label
                   for provider in PROVIDER_CREDENTIALS}
        _labels["ollama"] = "Local Ollama (offline fallback)"
        self._ai_order_list = QListWidget()
        configured_order = list(
            getattr(self._cfg, "ai_provider_order", None)
            or []
        )
        cur_order: list[str] = []
        for key in configured_order:
            if key in _labels and key not in cur_order:
                cur_order.append(key)
        for provider in PROVIDER_CREDENTIALS:
            if provider.provider_id in cur_order:
                continue
            insert_at = (
                cur_order.index("ollama")
                if "ollama" in cur_order else len(cur_order)
            )
            cur_order.insert(insert_at, provider.provider_id)
        if "ollama" not in cur_order:
            cur_order.append("ollama")
        for key in cur_order:
            it = QListWidgetItem(_labels.get(key, key))
            it.setData(Qt.UserRole, key)
            self._ai_order_list.addItem(it)
        self._ai_order_list.setFixedHeight(135)

        order_row = QHBoxLayout()
        order_row.addWidget(self._ai_order_list, 1)
        order_col = QVBoxLayout()
        btn_up = QPushButton("▲  Up"); btn_dn = QPushButton("▼  Down")
        btn_up.clicked.connect(lambda: self._move_ai_order(-1))
        btn_dn.clicked.connect(lambda: self._move_ai_order(1))
        order_col.addWidget(btn_up); order_col.addWidget(btn_dn); order_col.addStretch()
        order_row.addLayout(order_col)
        lay.addLayout(order_row)

        lay.addStretch()
        return w

    # ── SettingsDialog helpers & save ─────────────────────────────────────────

    def _move_ai_order(self, delta: int) -> None:
        lw = self._ai_order_list
        r = lw.currentRow()
        if r < 0: return
        nr = r + delta
        if 0 <= nr < lw.count():
            it = lw.takeItem(r); lw.insertItem(nr, it); lw.setCurrentRow(nr)

    def _section(self, title: str) -> QLabel:
        lbl = QLabel(title)
        lbl.setStyleSheet(
            "font-weight: bold; font-size: 12px; color: #1F9CFF; "
            "border-bottom: 1px solid #334155; padding-bottom: 3px; margin-top: 6px;"
        )
        return lbl

    def _refresh_autostart_status(self, enabled) -> None:
        from angerona.core.autostart import ui_copy as _autostart_ui_copy
        _section, _checkbox, _note, backend = _autostart_ui_copy()
        if enabled:
            self._autostart_status.setText(f"Status: enabled via {backend}")
            self._autostart_status.setStyleSheet("color: #22c55e; font-size: 11px;")
        elif enabled is False:
            self._autostart_status.setText("Status: no startup task found")
            self._autostart_status.setStyleSheet("color: #94a3b8; font-size: 11px;")
        else:
            self._autostart_status.setText(f"Status: could not detect ({backend})")
            self._autostart_status.setStyleSheet("color: #f59e0b; font-size: 11px;")

    def _on_check_updates(self) -> None:
        if callable(self._check_updates):
            try:
                self._check_updates()
            except Exception as exc:
                QMessageBox.warning(self, "Update check failed", str(exc))

    def _mark_api_keys_dirty(self, _text: str = "") -> None:
        self._api_keys_dirty = True

    def _save_api_keys(self, notify: bool = True) -> bool:
        from angerona.core.provider_credentials import save_provider_credentials

        updates = {
            provider_id: field.text().strip()
            for provider_id, field in self._key_fields.items()
        }
        try:
            save_provider_credentials(updates)
            self._initial_key_values = dict(updates)
            self._api_keys_dirty = False
            if notify:
                QMessageBox.information(
                    self,
                    "Keys saved",
                    "API keys were saved to the operating-system protected credential "
                    "store. Active modules pick them up without exposing the values.",
                )
            return True
        except Exception as exc:
            self._select_tab("API Keys")
            QMessageBox.warning(self, "Save failed", str(exc))
            return False

    def _save_mobile_pin(self) -> None:
        pin = self._mob_pin.text().strip()
        if not pin:
            return
        if not re.fullmatch(r"\d{4}", pin):
            QMessageBox.warning(
                self, "PIN save failed", "The response PIN must contain exactly 4 digits."
            )
            return
        try:
            from angerona.core.config import write_env_keys

            # Use the canonical cross-platform protected map.  Clear the legacy
            # nested-DPAPI slot only after the new value has been accepted by the
            # OS store; the bridge still reads it for existing installations.
            write_env_keys({
                "ANGERONA_MOBILE_PIN": pin,
                "ANGERONA_MOBILE_PIN_DPAPI": "",
            })
            self._mob_pin.clear()
        except Exception as exc:
            QMessageBox.warning(
                self, "PIN save failed",
                f"Could not save the PIN to the protected credential store: {exc}",
            )

    def _reset_usb_pin(self) -> bool:
        """Explicitly confirm a protected reset; never approve attached media."""
        pin = self._usb_pin.text().strip()
        confirmation = self._usb_pin_confirm.text().strip()
        if not re.fullmatch(r"\d{4,12}", pin):
            self._select_tab("System")
            QMessageBox.warning(
                self,
                "USB PIN not reset",
                "The removable-media approval PIN must contain 4–12 digits.",
            )
            return False
        if pin != confirmation:
            self._select_tab("System")
            QMessageBox.warning(
                self,
                "USB PIN not reset",
                "The new PIN and confirmation do not match.",
            )
            return False
        answer = QMessageBox.question(
            self,
            "Reset USB approval PIN",
            "Create this new protected USB PIN and revoke every current Angerona "
            "removable-media approval?\n\nAttached devices will remain untrusted "
            "until separately approved. This user-mode gate does not prevent raw "
            "operating-system file access.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if answer != QMessageBox.Yes:
            return False
        try:
            from angerona.core.usb_policy import configure_usb_pin

            result = configure_usb_pin(pin, confirmation)
            if not result.updated:
                raise RuntimeError(result.reason)
            self._usb_pin.clear()
            self._usb_pin_confirm.clear()
            self._usb_pin_status.setText("Protected PIN configured; approvals revoked")
            self._usb_pin_status.setStyleSheet("color: #22c55e; font-size: 11px;")
            QMessageBox.information(
                self,
                "USB PIN reset",
                "The new PIN is protected and all current Angerona USB approvals "
                "were revoked. Resetting did not approve any attached device.",
            )
            return True
        except Exception as exc:
            self._select_tab("System")
            QMessageBox.warning(
                self,
                "USB PIN not reset",
                "Could not save the removable-media PIN to the protected "
                f"credential store: {exc}",
            )
            return False

    def _save_usb_pin(self) -> bool:
        """Compatibility alias for the explicit, confirmed reset workflow."""
        return self._reset_usb_pin()

    def _save(self) -> None:
        """Validate, stage, and commit settings as one compensating transaction."""
        from angerona.core import autostart as autostart_module
        from angerona.core import config as config_module
        from angerona.core.fleet_credentials import (
            INTERNAL_FLEET_CREDENTIALS_KEY,
            LEGACY_FLEET_SERVICE_KEY,
        )
        from angerona.core.provider_credentials import canonical_updates
        from angerona.core.secure_store import read_secret_map

        # All widget values are copied into a detached Config first. Nothing
        # live, persisted, protected, or scheduled changes during validation.
        candidate = copy.deepcopy(self._cfg)
        if self._fleet_service_chk.isChecked():
            tenant = self._fleet_tenant.text().strip()
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{2,127}", tenant):
                self._select_tab("Enterprise")
                QMessageBox.warning(
                    self, "Invalid fleet tenant",
                    "Use 3-128 letters, numbers, dots, underscores, colons or hyphens.",
                )
                return
            try:
                port = int(self._fleet_port.text().strip())
                if not 1024 <= port <= 65535:
                    raise ValueError
            except ValueError:
                self._select_tab("Enterprise")
                QMessageBox.warning(
                    self, "Invalid fleet port",
                    "Choose an unused loopback port from 1024 through 65535.",
                )
                return
        if self._teams_chk.isChecked() and not self._teams_users.text().strip():
            self._select_tab("ARIA")
            QMessageBox.warning(
                self, "Teams allowlist required",
                "Add at least one immutable Teams AAD object ID. The bot fails "
                "closed when its allowlist is empty.",
            )
            return
        if self._aria_push_chk.isChecked() and not self._aria_push_url.text().strip():
            self._select_tab("ARIA")
            QMessageBox.warning(
                self, "Channel URL required",
                "Enter the approved channel/webhook URL or turn push off.",
            )
            return
        if self._aria_inbox_chk.isChecked() and not (
            self._aria_imap_host.text().strip()
            and self._aria_imap_user.text().strip()
        ):
            self._select_tab("ARIA")
            QMessageBox.warning(
                self, "Mailbox settings required",
                "Enter the IMAP host and mailbox, or turn inbox triage off.",
            )
            return

        candidate.ollama_host = self._ollama_host.text().strip()
        candidate.ollama_model = self._ollama_model.text().strip()
        candidate.github_repo = self._github_repo.text().strip()
        theme_key = self._theme_combo.currentData() or self._theme_combo.currentText()
        candidate.theme = theme_key or candidate.theme
        scale = self._ui_scale_combo.currentData()
        if scale == "auto" or scale is None:
            candidate.ui_scale_mode = "auto"
        else:
            candidate.ui_scale_mode = "fixed"
            try:
                candidate.ui_scale_fixed = float(int(scale)) / 100.0
            except (TypeError, ValueError):
                pass
        candidate.ui_motion_enabled = self._ui_motion_chk.isChecked()
        candidate.dashboard_mode = str(
            self._dashboard_mode_combo.currentData() or "classic"
        )
        candidate.holographic_orb_enabled = self._holographic_orb_chk.isChecked()
        candidate.process_baseline_enabled = self._process_baseline_chk.isChecked()
        candidate.require_signed_aar = self._require_signed_aar_chk.isChecked()
        candidate.entropy_pool_enabled = self._entropy_pool_chk.isChecked()
        candidate.adversary_combat_enabled = self._combat_enabled_chk.isChecked()
        candidate.adversary_combat_mode = str(
            self._combat_mode_combo.currentData() or "maximum"
        )
        candidate.adversary_combat_min_severity = str(
            self._combat_severity_combo.currentData() or "LOW"
        )
        candidate.adversary_combat_block_network = self._combat_block_chk.isChecked()
        candidate.adversary_combat_quarantine_files = (
            self._combat_quarantine_chk.isChecked()
        )
        candidate.adversary_combat_process_action = str(
            self._combat_process_combo.currentData() or "terminate"
        )
        candidate.adversary_combat_isolate_host = (
            self._combat_host_isolation_chk.isChecked()
        )
        candidate.adversary_combat_activate_honeypots = (
            self._combat_honeypot_chk.isChecked()
        )
        try:
            candidate.adversary_combat_isolation_threshold = max(
                1,
                min(100, int(self._combat_isolation_threshold.text().strip() or "3")),
            )
        except ValueError:
            candidate.adversary_combat_isolation_threshold = 3
        candidate.autostart_enabled = self._autostart_chk.isChecked()
        candidate.eco_mode = self._eco_chk.isChecked()
        candidate.blackbox_enabled = self._blackbox_chk.isChecked()
        candidate.deception_user_folders = self._deception_user_folders_chk.isChecked()
        candidate.mcp_enabled = self._mcp_chk.isChecked()
        try:
            candidate.mcp_port = int(self._mcp_port.text().strip() or "47923")
        except ValueError:
            pass
        candidate.ebpf_enabled = self._ebpf_chk.isChecked()
        candidate.fleet_service_enabled = self._fleet_service_chk.isChecked()
        candidate.fleet_tenant_id = self._fleet_tenant.text().strip() or "local"
        try:
            candidate.fleet_service_port = int(self._fleet_port.text().strip())
        except ValueError:
            pass
        candidate.siem_host = self._siem_host.text().strip()
        try:
            candidate.siem_port = int(self._siem_port.text().strip())
        except ValueError:
            candidate.siem_port = 0
        candidate.siem_protocol = str(self._siem_proto.currentData() or "tls")
        candidate.siem_min_severity = self._siem_severity.currentText()
        candidate.siem_allow_plaintext = self._siem_plaintext_chk.isChecked()
        candidate.siem_ca_file = self._siem_ca.text().strip()
        candidate.siem_include_raw = self._siem_raw_chk.isChecked()
        candidate.remote_bridge_mode = str(self._bridge_mode.currentData() or "")
        candidate.remote_bridge_peer = self._bridge_peer.text().strip()
        candidate.remote_bridge_bind = self._bridge_bind.text().strip()
        try:
            candidate.remote_bridge_port = int(self._bridge_port.text().strip())
        except ValueError:
            candidate.remote_bridge_port = 0
        candidate.remote_bridge_node_id = self._bridge_node.text().strip()
        candidate.remote_bridge_allow_nonloopback = (
            self._bridge_nonloop_chk.isChecked()
        )
        candidate.ioc_feed_url = self._ioc_url.text().strip()
        candidate.ioc_feed_sha256 = self._ioc_sha256.text().strip().casefold()

        candidate.aria_enabled = self._aria_chk.isChecked()
        candidate.perf_governor_enabled = (
            candidate.aria_enabled and self._aria_perf_chk.isChecked()
        )
        candidate.aria_persona = self._aria_persona_combo.currentText()
        candidate.aria_voice_enabled = (
            candidate.aria_enabled and self._aria_voice_chk.isChecked()
        )
        candidate.aria_conversation_awareness = (
            candidate.aria_enabled and self._aria_awareness_chk.isChecked()
        )
        candidate.aria_always_listen = (
            candidate.aria_enabled
            and candidate.aria_voice_enabled
            and candidate.aria_conversation_awareness
            and self._aria_always_listen_chk.isChecked()
        )
        try:
            candidate.aria_follow_up_seconds = max(
                0, min(60, int(self._aria_follow_up.text().strip() or "12"))
            )
        except ValueError:
            candidate.aria_follow_up_seconds = 12
        candidate.aria_hand_controls = (
            candidate.aria_enabled and self._aria_hands_chk.isChecked()
        )
        try:
            candidate.aria_camera_index = max(
                0, min(16, int(self._aria_camera_index.text().strip() or "0"))
            )
        except ValueError:
            candidate.aria_camera_index = 0
        candidate.aria_voice_cloud_tts = (
            candidate.aria_voice_enabled and self._aria_voice_cloud_chk.isChecked()
        )
        candidate.aria_cloud_fallback = (
            candidate.aria_enabled and self._aria_cloud_fallback_chk.isChecked()
        )
        candidate.alert_analysis_cloud_fallback = (
            self._alert_analysis_cloud_chk.isChecked()
        )
        candidate.aria_mic_device = str(self._aria_mic_combo.currentData() or "")
        candidate.aria_push_enabled = (
            candidate.aria_enabled and self._aria_push_chk.isChecked()
        )
        candidate.aria_push_kind = self._aria_push_kind.currentText()
        candidate.aria_push_url = self._aria_push_url.text().strip()
        candidate.aria_inbox_enabled = (
            candidate.aria_enabled and self._aria_inbox_chk.isChecked()
        )
        candidate.aria_imap_host = self._aria_imap_host.text().strip()
        candidate.aria_imap_user = self._aria_imap_user.text().strip()
        try:
            candidate.aria_inbox_interval_min = max(
                1, int(self._aria_inbox_interval.text().strip() or "5")
            )
        except ValueError:
            pass
        candidate.aria_research_egress = (
            candidate.aria_enabled and self._aria_egress_chk.isChecked()
        )
        candidate.teams_bot_enabled = (
            candidate.aria_enabled and self._teams_chk.isChecked()
        )
        candidate.teams_app_id = self._teams_app_id.text().strip()
        candidate.teams_allowed_users = self._teams_users.text().strip()
        candidate.teams_bot_skip_auth = False
        try:
            candidate.teams_bot_port = int(
                self._teams_port.text().strip() or "3978"
            )
        except ValueError:
            pass
        candidate.mobile_enabled = self._mob_chk.isChecked()
        candidate.mobile_signal_cli = self._mob_cli.text().strip()
        candidate.mobile_signal_cli_sha256 = (
            self._mob_sha256.text().strip().casefold()
        )
        candidate.mobile_signal_cli_publisher = self._mob_publisher.text().strip()
        candidate.mobile_host_number = self._mob_host.text().strip()
        candidate.mobile_dest_number = self._mob_dest.text().strip()
        order = [
            self._ai_order_list.item(index).data(Qt.UserRole)
            for index in range(self._ai_order_list.count())
            if self._ai_order_list.item(index).data(Qt.UserRole)
        ]
        if order:
            candidate.ai_provider_order = order

        bridge_key = self._bridge_key.text().strip()
        if bridge_key and (
            len(bridge_key) < 64
            or len(bridge_key) % 2
            or re.fullmatch(r"[0-9a-fA-F]+", bridge_key) is None
        ):
            QMessageBox.warning(
                self, "Remote Bridge key refused",
                "The shared key must contain at least 64 hexadecimal characters "
                "(32 bytes).",
            )
            self._select_tab("Integrations")
            return
        mobile_pin = self._mob_pin.text().strip()
        if mobile_pin and not re.fullmatch(r"\d{4}", mobile_pin):
            self._select_tab("Mobile Integration")
            QMessageBox.warning(
                self, "PIN save failed",
                "The response PIN must contain exactly 4 digits.",
            )
            return
        try:
            candidate.validate_mobile_settings()
        except ValueError as exc:
            QMessageBox.warning(self, "Mobile Bridge settings refused", str(exc))
            self._select_tab("Mobile Integration")
            return
        try:
            candidate.validate_integration_settings()
        except ValueError as exc:
            QMessageBox.warning(self, "Integration settings refused", str(exc))
            self._select_tab("Integrations")
            return

        provider_values = {
            provider_id: field.text().strip()
            for provider_id, field in self._key_fields.items()
        }
        try:
            secret_updates = (
                canonical_updates(provider_values) if self._api_keys_dirty else {}
            )
        except (KeyError, ValueError) as exc:
            self._select_tab("API Keys")
            QMessageBox.warning(self, "Provider credentials refused", str(exc))
            return
        if bridge_key:
            secret_updates["ANGERONA_BRIDGE_KEY"] = bridge_key.casefold()
        initial_connectors = getattr(
            self, "_initial_connector_secret_values", {}
        )
        imap_password = self._aria_imap_pass.text()
        teams_password = self._teams_pw.text()
        if imap_password != initial_connectors.get("ARIA_IMAP_PASS", ""):
            secret_updates["ARIA_IMAP_PASS"] = imap_password
        if teams_password != initial_connectors.get(
            "ANGERONA_TEAMS_APP_PASSWORD", ""
        ):
            secret_updates["ANGERONA_TEAMS_APP_PASSWORD"] = teams_password
        if mobile_pin:
            secret_updates.update({
                "ANGERONA_MOBILE_PIN": mobile_pin,
                "ANGERONA_MOBILE_PIN_DPAPI": "",
            })

        protected_before: dict[str, str] | None = None
        secure_store_touched = bool(
            secret_updates
            or candidate.aria_push_url
            or os.environ.get("ANGERONA_ARIA_PUSH_URL")
            or candidate.fleet_service_enabled
        )
        if secure_store_touched:
            try:
                try:
                    protected_before = read_secret_map(
                        candidate.data_dir, strict=True
                    )
                except TypeError as type_exc:
                    # Compatibility for an injected/legacy store adapter that
                    # predates the strict keyword. Production's canonical store
                    # supports strict reads; still validate the fallback shape.
                    if "strict" not in str(type_exc):
                        raise
                    protected_before = read_secret_map(candidate.data_dir)
                if not isinstance(protected_before, dict) or any(
                    not isinstance(name, str) or not isinstance(value, str)
                    for name, value in protected_before.items()
                ):
                    raise RuntimeError(
                        "protected credential snapshot has an invalid shape"
                    )
            except Exception as exc:
                QMessageBox.warning(
                    self, "Protected settings unavailable",
                    "No settings were changed because the existing protected "
                    f"credential map could not be read safely.\n\n{exc}",
                )
                return
        if candidate.fleet_service_enabled:
            import secrets

            protected = protected_before or {}
            if not protected.get(INTERNAL_FLEET_CREDENTIALS_KEY) and not protected.get(
                LEGACY_FLEET_SERVICE_KEY
            ):
                secret_updates[LEGACY_FLEET_SERVICE_KEY] = secrets.token_urlsafe(48)

        settings_path = candidate.settings_path
        settings_existed = settings_path.exists()
        try:
            settings_before = settings_path.read_bytes() if settings_existed else b""
        except OSError as exc:
            QMessageBox.warning(
                self, "Settings unavailable",
                f"The current settings file could not be snapshotted safely.\n\n{exc}",
            )
            return
        config_before = copy.deepcopy(vars(self._cfg))
        environment_before = dict(os.environ)
        current_autostart = bool(autostart_module.is_enabled())
        autostart_requested = (
            candidate.autostart_enabled
            != bool(config_before.get("autostart_enabled", current_autostart))
        )
        autostart_changed = False

        def _restore_settings_bytes() -> None:
            if not settings_existed:
                settings_path.unlink(missing_ok=True)
                return
            settings_path.parent.mkdir(parents=True, exist_ok=True)
            temp = settings_path.with_name(
                f".{settings_path.name}.{uuid.uuid4().hex}.rollback"
            )
            try:
                with temp.open("x+b") as handle:
                    handle.write(settings_before)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temp, settings_path)
            finally:
                temp.unlink(missing_ok=True)

        try:
            # One protected-map write prevents bridge/provider/mail/mobile/fleet
            # secrets from landing in different partial generations.
            if secret_updates:
                config_module.write_env_keys(secret_updates)
            candidate.save()
            # Make the settings persistence failure observable before changing
            # scheduled startup state or the live Config object.
            with settings_path.open("r+b") as handle:
                os.fsync(handle.fileno())
            if autostart_requested and current_autostart != candidate.autostart_enabled:
                result = (
                    autostart_module.enable_autostart()
                    if candidate.autostart_enabled
                    else autostart_module.disable_autostart()
                )
                if result is not True:
                    raise RuntimeError("the operating system refused the autostart change")
                autostart_changed = True

            # Commit the detached object only after both durable settings and
            # autostart have succeeded.
            self._cfg.__dict__.clear()
            self._cfg.__dict__.update(copy.deepcopy(vars(candidate)))
            for name, enabled in {
                "ANGERONA_REQUIRE_SIGNED_AAR": candidate.require_signed_aar,
                "ANGERONA_ENTROPY_POOL": candidate.entropy_pool_enabled,
                "ANGERONA_ADVERSARY_COMBAT_ENABLED": (
                    candidate.adversary_combat_enabled
                ),
                "ANGERONA_USER_FOLDER_DECEPTION": (
                    candidate.deception_user_folders
                ),
            }.items():
                if enabled:
                    os.environ[name] = "1"
                else:
                    os.environ.pop(name, None)
            if candidate.adversary_combat_enabled:
                os.environ["ANGERONA_ADVERSARY_COMBAT_MODE"] = (
                    candidate.adversary_combat_mode
                )
            else:
                os.environ.pop("ANGERONA_ADVERSARY_COMBAT_MODE", None)
            if order:
                os.environ["ANGERONA_AI_ORDER"] = ",".join(order)
            os.environ.pop("ANGERONA_FLEET_SERVICE_KEY", None)
            os.environ.pop(LEGACY_FLEET_SERVICE_KEY, None)
        except Exception as exc:
            rollback_errors: list[str] = []
            try:
                _restore_settings_bytes()
            except Exception as rollback_exc:
                rollback_errors.append(f"settings bytes: {rollback_exc}")
            if protected_before is not None:
                try:
                    restore_names = set(protected_before) | set(secret_updates) | {
                        "ANGERONA_ARIA_PUSH_URL"
                    }
                    config_module.write_env_keys({
                        name: protected_before.get(name, "")
                        for name in restore_names
                    })
                except Exception as rollback_exc:
                    rollback_errors.append(
                        f"protected credentials: {rollback_exc}"
                    )
            if autostart_changed:
                try:
                    restored = (
                        autostart_module.enable_autostart()
                        if current_autostart
                        else autostart_module.disable_autostart()
                    )
                    if restored is not True:
                        raise RuntimeError("operating system refused restoration")
                except Exception as rollback_exc:
                    rollback_errors.append(f"autostart: {rollback_exc}")
            self._cfg.__dict__.clear()
            self._cfg.__dict__.update(config_before)
            os.environ.clear()
            os.environ.update(environment_before)
            if rollback_errors:
                QMessageBox.critical(
                    self, "Settings rollback incomplete",
                    "The save failed and one or more original resources could not "
                    "be restored. Review the listed resources before retrying.\n\n"
                    f"Save failure: {exc}\nRollback failure: "
                    + "; ".join(rollback_errors),
                )
            else:
                QMessageBox.warning(
                    self, "Settings not saved",
                    "The save failed. The prior config object, settings bytes, "
                    "protected credentials, environment, and autostart state were "
                    f"restored.\n\n{exc}",
                )
            return

        if self._api_keys_dirty:
            self._initial_key_values = dict(provider_values)
            self._api_keys_dirty = False
        self._initial_connector_secret_values = {
            "ARIA_IMAP_PASS": imap_password,
            "ANGERONA_TEAMS_APP_PASSWORD": teams_password,
        }
        self._bridge_key.clear()
        if mobile_pin:
            self._mob_pin.clear()
        if callable(self._apply_theme):
            try:
                self._apply_theme(self._cfg.theme)
            except Exception:
                pass
        combat = self._combat_module()
        if combat is not None:
            try:
                if self._cfg.adversary_combat_enabled:
                    if getattr(combat, "status", "stopped") != "running":
                        combat.start()
                elif getattr(combat, "status", "stopped") == "running":
                    combat.stop()
                self._refresh_combat_actions()
            except Exception as exc:
                QMessageBox.warning(
                    self,
                    "Adversary Combat policy saved",
                    "The standing policy was saved, but its live module state "
                    f"could not be changed: {exc}",
                )
        if self._process_baseline is not None:
            self._process_baseline.set_enabled(
                self._cfg.process_baseline_enabled
            )
        self.accept()
