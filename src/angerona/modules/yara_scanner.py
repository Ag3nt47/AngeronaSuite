"""In-process YARA signature scanner with bounded, symlink-safe traversal.

The scanner uses the maintained ``yara-x`` package instead of launching a
writeable checkout/PATH executable from an elevated process. Rules are compiled
before activation and only changed files generate repeat alerts.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
from importlib.metadata import version as distribution_version
import os
import io
import re
import secrets
import stat as stat_module
import sys
import threading
import time
import zipfile
import weakref
from bisect import bisect_right
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

from angerona.core.atomic_io import replace_with_retry
from angerona.core.data_paths import data_dir, resource_root
from angerona.core.module_base import BaseModule, Severity
from angerona.core.eventbus import Event
from angerona.core.response_contract import authorize_response
from angerona.core.archive_safety import preflight_zip_bytes
from angerona.core.response_proof import ProducerResponseProofs, event_proof_digest, proof_digest


SCAN_DIRS = [
    Path(os.environ.get("USERPROFILE", str(Path.home()))) / "Downloads",
    data_dir() / "drill-sandbox",
]
MAX_FILES_PER_ROOT = 10_000
MAX_DISCOVERY_ENTRIES_PER_ROOT = 200_000
MAX_DIRECTORY_ENTRIES = 100_000
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 128
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_SCAN_CACHE = 20_000
_CURSOR_SCHEMA = "angerona.yara-fair-cursor.v1"
_CURSOR_SIG = "hmac_sha256"
_RUNTIME_ROOTS: set[Path] = set()
_RUNTIME_ROOTS_LOCK = threading.Lock()
_CONTROL_NATIVE_VERSION = "1.19.0"
_CONTROL_SOURCE_LIMIT = 1024 * 1024


class _YaraControlEnrollment:
    """Plain owner-liveness metadata; never owns a native object or wrapper."""

    __slots__ = ("enrollment_id", "generation", "source_epoch", "compile_input_sha256",
                 "recipe_sha256", "native_version", "active", "producer_ref", "owner",
                 "__weakref__")

    def __init__(self, producer, *, source_digest, recipe_digest, native_version):
        self.enrollment_id = secrets.token_hex(24)
        self.generation = producer.lifecycle_generation
        self.source_epoch = producer._control_source_epoch
        self.compile_input_sha256 = source_digest
        self.recipe_sha256 = recipe_digest
        self.native_version = native_version
        self.active = True
        self.producer_ref = weakref.ref(producer)
        self.owner = threading.get_ident()


class _OwnerControlScanner:
    """Native objects stay on the canonical scanner worker, including cleanup."""

    __slots__ = ("_rules", "_scanner", "enrollment", "owner", "serial", "__weakref__")

    def __init__(self, rules, scanner, enrollment):
        self._rules, self._scanner = rules, scanner
        self.enrollment = enrollment
        self.owner = threading.get_ident()
        self.serial = 0

    def __setattr__(self, name, value):
        if name in {"_rules", "_scanner", "enrollment", "owner"} and hasattr(self, name):
            raise AttributeError("Controlled native scanner bindings are immutable.")
        object.__setattr__(self, name, value)

    def _require_owner(self):
        if threading.get_ident() != self.owner:
            raise RuntimeError("Controlled YARA scanner requires its creator thread.")

    def begin_file_scan(self):
        self._require_owner()
        self.serial += 1
        return self.serial

    def scan(self, content):
        self._require_owner()
        if not self.enrollment.active:
            raise RuntimeError("Controlled YARA scanner enrollment was revoked.")
        return self._scanner.scan(content)

    def close(self):
        self._require_owner()
        self.enrollment.active = False
        object.__setattr__(self, "_scanner", None)
        object.__setattr__(self, "_rules", None)


def register_runtime_watch(path: str) -> bool:
    """Enroll the operator-selected drill target, with a bounded root count."""
    try:
        root = Path(path).expanduser().absolute()
        if root.exists() and (not root.is_dir() or root.is_symlink()
                              or YaraScannerModule._is_reparse(root.lstat())):
            return False
        with _RUNTIME_ROOTS_LOCK:
            if root not in _RUNTIME_ROOTS and len(_RUNTIME_ROOTS) >= 8:
                return False
            _RUNTIME_ROOTS.add(root)
        return True
    except (OSError, TypeError, ValueError):
        return False


def unregister_runtime_watch(path: str | None) -> None:
    if path:
        with _RUNTIME_ROOTS_LOCK:
            _RUNTIME_ROOTS.discard(Path(path).expanduser().absolute())


def scan_roots() -> tuple[Path, ...]:
    with _RUNTIME_ROOTS_LOCK:
        return tuple(dict.fromkeys([*SCAN_DIRS, *sorted(_RUNTIME_ROOTS)]))

SEVERITY_HINTS = {
    "mimikatz": Severity.CRITICAL,
    "eicar": Severity.MEDIUM,
    "angerona_byovd_probe": Severity.MEDIUM,
}


def _scan_interval() -> float:
    enabled = os.environ.get("ANGERONA_ADVERSARY_COMBAT_ENABLED", "0").strip().lower()
    mode = os.environ.get("ANGERONA_ADVERSARY_COMBAT_MODE", "").strip().lower()
    if enabled in {"1", "true", "yes", "on"} and mode == "maximum":
        return 2.0
    if enabled in {"1", "true", "yes", "on"}:
        return 15.0
    return 300.0


@dataclass(frozen=True)
class _TraversalBatch:
    paths: tuple[Path, ...]
    next_cursor: str
    discovered: int
    errors: int
    incomplete: bool
    wrapped: bool
    discovery_truncated: bool


class YaraScannerModule(BaseModule):
    background_pacing_allowed = True
    name = "YARA Scanner"
    version = "1.14.0"
    description = "Scans Downloads and the isolated drill sandbox with in-process YARA."
    category = "Signatures"
    enabled_by_default = True
    watchdog_work_budget_seconds = 600.0

    def __init__(self) -> None:
        super().__init__()
        self._rules_lock = threading.RLock()
        self._compiled_rules = None
        self._active_rules = ""
        self._seen_matches: dict[tuple[str, str], int] = {}
        self._scan_cache: OrderedDict[str, tuple[int, ...]] = OrderedDict()
        self._detection_receipts: OrderedDict[str, int] = OrderedDict()
        self._receipt_lock = threading.Lock()
        self._redteam_receipt_capability = None
        self._control_wake = threading.Event()
        self._control_wake_request = None
        self._control_source_epoch = secrets.token_hex(24)
        self._control_enrollments = {}
        self._control_enrollment_seals = {}
        self._control_owner_refs = {}
        self._control_proofs = ProducerResponseProofs()
        self._control_proof_metadata = OrderedDict()
        self._control_native_identity = None
        self._control_last_error = ""
        self._cursor_state: dict[str, object] = {
            "schema": _CURSOR_SCHEMA,
            "sequence": 0,
            "roots": {},
        }
        self._cursor_state_status = "unloaded"
        self._coverage_snapshot: dict[str, dict[str, object]] = {}
        self._last_coverage_alert = ""
        self._reload_failure = None

    def _repo_root(self) -> Path:
        return resource_root()

    def bind_manager(self, manager) -> None:
        self._community_config = manager.config

    def _find_rules(self) -> str:
        override = os.environ.get("ANGERONA_YARA_RULES", "").strip()
        if override:
            candidate = Path(override).expanduser().resolve()
            if candidate.is_file():
                return str(candidate)
        candidates = [
            self._repo_root() / "rules.yar",
            Path(sys.executable).resolve().parent / "rules.yar",
        ]
        bundle = getattr(sys, "_MEIPASS", "")
        if bundle:
            candidates.append(Path(bundle) / "rules.yar")
        for candidate in candidates:
            if candidate.is_file():
                return str(candidate.resolve())
        return ""

    @staticmethod
    def _compile_rules(rules_path: Path):
        try:
            import yara_x
        except ImportError as exc:
            raise RuntimeError("yara-x is not installed") from exc
        path = rules_path.resolve()
        compiler = yara_x.Compiler()
        compiler.add_include_dir(str(path.parent))
        compiler.add_source(path.read_text(encoding="utf-8", errors="strict"),
                            origin=str(path))
        return compiler.build()

    @staticmethod
    def _make_scanner(compiled):
        import yara_x
        scanner = yara_x.Scanner(compiled)
        try:
            scanner.set_timeout(10)
            scanner.max_matches_per_pattern(64)
            scanner.fast_scan(True)
        except BaseException:
            # A retained configuration traceback must not carry this
            # thread-bound native object into another thread's garbage collector.
            scanner = None
            raise
        return scanner

    def _report_reload_failure(self, rules, error: Exception) -> None:
        """Bound repeated coverage notices without skipping activation retries."""
        now = time.monotonic()
        reason = str(error)
        fingerprint = (type(error), reason)
        previous = self._reload_failure
        if previous is not None and previous[0] is rules and previous[1] == fingerprint:
            repeats = previous[3] + 1
            if now - previous[2] < 900.0:
                self._reload_failure = (rules, fingerprint, previous[2], repeats)
                return
        else:
            repeats = 0
        self.emit(
            f"YARA scanner reload rejected: {reason}", Severity.HIGH,
            disposition="health", finding_code="yara.rules.reload-rejected",
            response_authorized=False, repeats_since_last_report=repeats,
            repeat_interval_seconds=900,
        )
        self._reload_failure = (rules, fingerprint, now, 0)

    def bind_redteam_receipt_capability(self, capability, *, expected=None):
        # Revocation touches plain state only; native retirement stays on owner.
        with self._receipt_lock:
            if expected is not None and self._redteam_receipt_capability is not expected:
                return
            self._redteam_receipt_capability = capability
            self._control_source_epoch = secrets.token_hex(24)
            for enrollment in self._control_enrollments.values():
                enrollment.active = False
            self._control_wake_request = None
            self._control_wake.clear()
            if capability is not None and self.status == "running" and not self.stopping:
                self._control_wake_request = (self.lifecycle_generation, capability, None)
                self._control_wake.set()

    def signal_control_declaration(self, capability, enrollment, path):
        """Coalesce a read-only hint for an exact declaration in an admitted root.

        The issuer calls this after exclusive creation. The owner still uses
        ordinary traversal and the complete native scan/proof path. Neither this
        hint nor the plain enrollment token grants response authority.
        """
        try:
            candidate = Path(path)
            if (not self._control_enrollment_valid(enrollment)
                    or candidate.parent not in scan_roots()
                    or not candidate.name.startswith("_angerona_yara_control_")):
                return False
            with self._receipt_lock:
                if (capability is not self._redteam_receipt_capability
                        or not enrollment.active or enrollment.generation != self.lifecycle_generation
                        or self.stopping or self.status != "running"):
                    return False
                self._control_wake_request = (self.lifecycle_generation, capability, enrollment)
                self._control_wake.set()
                return True
        except (AttributeError, OSError, TypeError, ValueError):
            return False

    def _sleep_for_scan(self):
        self.sleep(_scan_interval(), _wake_event=self._control_wake)
        with self._receipt_lock:
            request = self._control_wake_request
            self._control_wake_request = None
            self._control_wake.clear()
            current = bool(request is not None
                and request[0] == self.lifecycle_generation
                and request[1] is self._redteam_receipt_capability
                and request[1] is not None and not self.stopping)
        if current and (request[2] is None or self._control_enrollment_valid(request[2])):
            # A hint can omit discretionary idle time, never the current
            # throttle/Chill/priority floor. This is a wait, not a new cycle.
            self.sleep(2.0, cycle_complete=False, _background_pacing=False)

    @staticmethod
    def _control_recipe(source_digest, source_size, native_version):
        return {"schema": "canonical-yara-compile-input-v1",
                "compile_input_sha256": source_digest, "source_bytes": source_size,
                "native_version": native_version,
                "compiler": "yara_x.compile-defaults-no-includes-imports-or-externals",
                "scanner_timeout_seconds": 10, "max_matches_per_pattern": 64,
                "fast_scan": True}

    @staticmethod
    def _enrollment_metadata(enrollment):
        return {name: getattr(enrollment, name) for name in
                ("enrollment_id", "generation", "source_epoch", "compile_input_sha256",
                 "recipe_sha256", "native_version")}

    def _make_control_scanner(self, source_snapshot: bytes):
        """Compile exact immutable input on its real worker; no caller native inputs."""
        import yara_x
        if (type(self) is not YaraScannerModule
                or self._thread is not threading.current_thread() or self.stopping
                or self._redteam_receipt_capability is None
                or type(source_snapshot) is not bytes
                or not 1 <= len(source_snapshot) <= _CONTROL_SOURCE_LIMIT
                or re.search(rb"\b(?:include|import)\b", source_snapshot, re.IGNORECASE)):
            raise ValueError("Controlled YARA requires its worker and bounded include-free source.")
        text = source_snapshot.decode("utf-8", errors="strict")
        native_version = distribution_version("yara-x")
        if native_version != _CONTROL_NATIVE_VERSION:
            raise RuntimeError("Controlled YARA native version has not been validated.")
        source_digest = hashlib.sha256(source_snapshot).hexdigest()
        recipe_digest = proof_digest(self._control_recipe(source_digest, len(source_snapshot), native_version))
        rules = scanner = wrapper = None
        try:
            rules = yara_x.compile(text)
            if type(rules) is not yara_x.Rules:
                raise RuntimeError("Controlled YARA did not compile native Rules.")
            scanner = yara_x.Scanner(rules)
            if type(scanner) is not yara_x.Scanner:
                raise RuntimeError("Controlled YARA did not construct a native Scanner.")
            scanner.set_timeout(10)
            scanner.max_matches_per_pattern(64)
            scanner.fast_scan(True)
            enrollment = _YaraControlEnrollment(self, source_digest=source_digest,
                recipe_digest=recipe_digest, native_version=native_version)
            wrapper = _OwnerControlScanner(rules, scanner, enrollment)
            with self._receipt_lock:
                if self.stopping or enrollment.source_epoch != self._control_source_epoch:
                    raise RuntimeError("Controlled YARA factory epoch was revoked.")
                for prior in self._control_enrollments.values():
                    prior.active = False
                self._control_enrollments = {enrollment.enrollment_id: enrollment}
                self._control_enrollment_seals = {enrollment.enrollment_id:
                    proof_digest(self._enrollment_metadata(enrollment))}
                self._control_owner_refs = {enrollment.enrollment_id: weakref.ref(wrapper)}
                self._control_native_identity = (yara_x, yara_x.compile, yara_x.Rules, yara_x.Scanner)
            return wrapper
        except BaseException:
            if wrapper is not None:
                wrapper.close()
            raise
        finally:
            # A configuration traceback must not carry these native aliases.
            rules = scanner = wrapper = None

    def _control_enrollment_valid(self, enrollment):
        # This method never sees/dereferences a live native-owning wrapper.
        try:
            if (type(self) is not YaraScannerModule or type(enrollment) is not _YaraControlEnrollment
                    or enrollment.producer_ref() is not self or not enrollment.active
                    or enrollment.generation != self.lifecycle_generation or self.stopping
                    or enrollment.source_epoch != self._control_source_epoch
                    or self._thread is None or not self._thread.is_alive()
                    or self.status != "running"
                    or type(self)._make_control_scanner.__code__ is not _CONTROL_FACTORY_CODE
                    or type(self)._scan_file.__code__ is not _CONTROL_SCAN_CODE):
                return False
            native, compiler, rules_type, scanner_type = self._control_native_identity
            if (native.compile is not compiler or native.Rules is not rules_type
                    or native.Scanner is not scanner_type):
                return False
            with self._receipt_lock:
                return bool(self._control_enrollments.get(enrollment.enrollment_id) is enrollment
                    and self._control_enrollment_seals.get(enrollment.enrollment_id)
                    == proof_digest(self._enrollment_metadata(enrollment)))
        except (AttributeError, TypeError, ValueError):
            return False

    def control_enrollment(self):
        """Read-only plain token for issuer-owned control creation, never native objects."""
        with self._receipt_lock:
            return next((value for value in self._control_enrollments.values() if value.active), None)

    def verify_control_detection_event(self, event):
        try:
            digest = event_proof_digest(event)
            with self._receipt_lock:
                metadata = self._control_proof_metadata.get(digest)
                enrollment = self._control_enrollments.get(metadata["enrollment_id"]) if metadata else None
                valid = bool(metadata and self._detection_receipts.get(digest) == self.lifecycle_generation
                    and self._control_proofs.verify(event, generation=self.lifecycle_generation,
                        now=time.monotonic(), review=metadata))
            return bool(valid and self._control_enrollment_valid(enrollment))
        except (AttributeError, TypeError, ValueError, OverflowError):
            return False

    def stop(self):
        with self._receipt_lock:
            for enrollment in self._control_enrollments.values():
                enrollment.active = False
            self._control_wake_request = None
            self._control_wake.clear()
        return super().stop()

    def _optional_control_scanner(self):
        if self._redteam_receipt_capability is None:
            return None
        try:
            with Path(self._active_rules).open("rb") as source:
                snapshot = source.read(_CONTROL_SOURCE_LIMIT + 1)
            scanner = self._make_control_scanner(snapshot)
            self._control_last_error = ""
            return scanner
        except Exception as exc:
            reason = str(exc)[:500]
            if reason != self._control_last_error:
                self._control_last_error = reason
                self.emit("YARA controlled validation unavailable; ordinary scanning continues.",
                    Severity.MEDIUM, disposition="health", response_authorized=False,
                    control_validation_reason=reason)
            return None

    def _activate(self, path: Path):
        with self._receipt_lock:
            self._control_source_epoch = secrets.token_hex(24)
            for enrollment in self._control_enrollments.values():
                enrollment.active = False
        compiled = self._compile_rules(path)
        # yara-x Scanner is thread-bound. Validate configuration here, then
        # release this temporary scanner on its creator thread. The run thread
        # owns its own scanner and can safely replace it after a rules reload.
        probe = self._make_scanner(compiled)
        del probe
        with self._rules_lock:
            self._compiled_rules = compiled
            self._active_rules = str(path.resolve())
            self._scan_cache.clear()
            self._seen_matches.clear()
        return compiled

    def reload_rules(self, candidate_text: str | None = None) -> bool:
        """Compile-gate base + generated rules, then atomically activate them."""
        base = self._find_rules()
        # Bundled rules are immutable application resources. Evolution output is
        # runtime state and must remain writable in frozen/protected installs.
        auto = data_dir() / "rules" / "auto_generated.yar"
        try:
            auto_text = (candidate_text if candidate_text is not None else
                         (auto.read_text(encoding="utf-8", errors="strict")
                          if auto.exists() else ""))
            if not base:
                raise RuntimeError("rules.yar not found")
            if not auto_text:
                self._activate(Path(base))
            else:
                runtime = data_dir() / "rules"
                runtime.mkdir(parents=True, exist_ok=True)
                active = runtime / "active-runtime.yar"
                candidate = runtime / "active-runtime.candidate.yar"
                candidate.write_text(
                    Path(base).read_text(encoding="utf-8", errors="strict")
                    + "\n\n// auto-generated (evolution engine)\n" + auto_text,
                    encoding="utf-8")
                compiled = self._compile_rules(candidate)
                probe = self._make_scanner(compiled)
                del probe
                if candidate_text is not None:
                    auto.parent.mkdir(parents=True, exist_ok=True)
                    auto_candidate = auto.with_suffix(".candidate")
                    auto_candidate.write_text(candidate_text, encoding="utf-8")
                    os.replace(auto_candidate, auto)
                os.replace(candidate, active)
                with self._rules_lock:
                    self._compiled_rules = compiled
                    self._active_rules = str(active.resolve())
                    self._scan_cache.clear()
                    self._seen_matches.clear()
            self.set_health(100, "validated rules active")
            self.emit(f"YARA rules reloaded ({Path(self._active_rules).name}).", Severity.INFO)
            return True
        except Exception as exc:
            self.last_error = str(exc)
            self.set_health(20, "generated YARA rejected by compile gate")
            self.emit(f"YARA candidate rejected: {exc}", Severity.HIGH)
            return False

    @staticmethod
    def _cursor_path() -> Path:
        return data_dir() / "sensor-cursors" / "yara-fair-traversal.json"

    @staticmethod
    def _cursor_key() -> bytes | None:
        try:
            key = bytes.fromhex((data_dir() / "bus.key").read_text(encoding="ascii").strip())
        except Exception:
            return None
        return key if len(key) == 32 else None

    @staticmethod
    def _cursor_canonical(value: dict[str, object]) -> bytes:
        body = {key: item for key, item in value.items() if key != _CURSOR_SIG}
        return json.dumps(
            body,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

    def _load_cursor_state(self) -> str:
        path = self._cursor_path()
        key = self._cursor_key()
        if key is None:
            self._cursor_state_status = "key-unavailable"
            return self._cursor_state_status
        try:
            raw = path.read_bytes()
        except FileNotFoundError:
            self._cursor_state_status = "new"
            return self._cursor_state_status
        except OSError:
            self._cursor_state_status = "unreadable"
            return self._cursor_state_status
        try:
            if len(raw) > 64 * 1024:
                raise ValueError("cursor state exceeds 64 KiB")
            value = json.loads(raw.decode("utf-8"))
            if not isinstance(value, dict) or set(value) != {
                "schema", "sequence", "roots", _CURSOR_SIG,
            }:
                raise ValueError("cursor state schema mismatch")
            if value["schema"] != _CURSOR_SCHEMA:
                raise ValueError("cursor state version mismatch")
            sequence = int(value["sequence"])
            roots = value["roots"]
            supplied = str(value[_CURSOR_SIG])
            expected = hmac.new(
                key,
                self._cursor_canonical(value),
                hashlib.sha256,
            ).hexdigest()
            if sequence < 0 or not isinstance(roots, dict) or len(roots) > 16:
                raise ValueError("cursor state bounds invalid")
            if len(supplied) != 64 or not hmac.compare_digest(supplied, expected):
                raise ValueError("cursor state authentication failed")
            clean_roots: dict[str, dict[str, object]] = {}
            for token, record in roots.items():
                if (
                    not isinstance(token, str)
                    or len(token) != 64
                    or not isinstance(record, dict)
                    or set(record) != {"cursor", "incomplete_since", "wraps"}
                ):
                    raise ValueError("cursor root record invalid")
                cursor = str(record["cursor"])
                if len(cursor) > 4096 or "\x00" in cursor:
                    raise ValueError("cursor value invalid")
                incomplete_since = float(record["incomplete_since"])
                if not math.isfinite(incomplete_since):
                    raise ValueError("cursor timestamp invalid")
                clean_roots[token] = {
                    "cursor": cursor,
                    "incomplete_since": max(0.0, incomplete_since),
                    "wraps": max(0, int(record["wraps"])),
                }
            self._cursor_state = {
                "schema": _CURSOR_SCHEMA,
                "sequence": sequence,
                "roots": clean_roots,
            }
        except (KeyError, TypeError, ValueError, UnicodeError, json.JSONDecodeError):
            self._cursor_state_status = "invalid"
            return self._cursor_state_status
        self._cursor_state_status = "ok"
        return self._cursor_state_status

    def _save_cursor_state(self) -> bool:
        # Never overwrite evidence of corruption or an unverifiable state.
        if self._cursor_state_status not in {"new", "ok"}:
            return False
        key = self._cursor_key()
        if key is None:
            self._cursor_state_status = "key-unavailable"
            return False
        payload = dict(self._cursor_state)
        payload["sequence"] = int(payload.get("sequence", 0)) + 1
        payload[_CURSOR_SIG] = hmac.new(
            key,
            self._cursor_canonical(payload),
            hashlib.sha256,
        ).hexdigest()
        path = self._cursor_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(
            f"{path.name}.{os.getpid()}.{threading.get_ident()}.tmp"
        )
        try:
            with temporary.open("w", encoding="utf-8", newline="\n") as handle:
                json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
            replace_with_retry(temporary, path)
        except OSError as exc:
            self.last_error = str(exc)
            self._cursor_state_status = "write-failed"
            return False
        finally:
            temporary.unlink(missing_ok=True)
        self._cursor_state = {key: value for key, value in payload.items() if key != _CURSOR_SIG}
        self._cursor_state_status = "ok"
        return True

    @staticmethod
    def _root_token(root: Path) -> str:
        try:
            canonical = str(root.resolve()).casefold()
        except OSError:
            canonical = str(root.absolute()).casefold()
        return hashlib.sha256(canonical.encode("utf-8", errors="surrogatepass")).hexdigest()

    @staticmethod
    def _is_reparse(stat_result: os.stat_result) -> bool:
        return bool(int(getattr(stat_result, "st_file_attributes", 0)) & 0x400)

    @classmethod
    def _fair_batch(
        cls, root: Path, cursor: str, *, checkpoint: Callable[[int], bool] | None = None,
    ) -> _TraversalBatch:
        """Inventory one bounded root and rotate after the durable relative cursor."""
        candidates: list[tuple[str, Path]] = []
        stack = [root]
        errors = 0
        discovered_entries = 0
        discovery_truncated = False
        work = 0
        while stack and not discovery_truncated:
            current = stack.pop()
            try:
                entries = []
                with os.scandir(current) as iterator:
                    for entry in iterator:
                        work += 1
                        if checkpoint is not None and not checkpoint(work):
                            discovery_truncated = True
                            break
                        discovered_entries += 1
                        if (
                            discovered_entries > MAX_DISCOVERY_ENTRIES_PER_ROOT
                            or len(entries) >= MAX_DIRECTORY_ENTRIES
                        ):
                            discovery_truncated = True
                            break
                        entries.append(entry)
            except OSError:
                errors += 1
                continue
            entries.sort(key=lambda item: (item.name.casefold(), item.name))
            child_dirs: list[Path] = []
            for entry in entries:
                work += 1
                if checkpoint is not None and not checkpoint(work):
                    discovery_truncated = True
                    break
                try:
                    stat_result = entry.stat(follow_symlinks=False)
                    if entry.is_symlink() or cls._is_reparse(stat_result):
                        continue
                    path = Path(entry.path)
                    if entry.is_dir(follow_symlinks=False):
                        child_dirs.append(path)
                    elif entry.is_file(follow_symlinks=False):
                        relative = path.relative_to(root).as_posix()
                        candidates.append((relative, path))
                except (OSError, ValueError):
                    errors += 1
            stack.extend(reversed(child_dirs))

        candidates.sort(key=lambda item: (item[0].casefold(), item[0]))
        cursor_key = (cursor.casefold(), cursor)
        # The inventory is already sorted by this exact key. Locate the split
        # in logarithmic time and allocate only the bounded selected batch,
        # rather than casefolding every path twice and copying the inventory.
        split = bisect_right(
            candidates, cursor_key, key=lambda item: (item[0].casefold(), item[0]),
        )
        wrapped = bool(cursor and split == len(candidates))
        selected = candidates[split:split + MAX_FILES_PER_ROOT]
        if len(selected) < MAX_FILES_PER_ROOT:
            selected.extend(candidates[:min(split, MAX_FILES_PER_ROOT - len(selected))])
        next_cursor = selected[-1][0] if selected else cursor
        return _TraversalBatch(
            paths=tuple(item[1] for item in selected),
            next_cursor=next_cursor,
            discovered=len(candidates),
            errors=errors,
            incomplete=(len(candidates) > len(selected) or discovery_truncated),
            wrapped=wrapped,
            discovery_truncated=discovery_truncated,
        )

    @classmethod
    def _iter_files(cls, root: Path) -> Iterator[Path]:
        """Compatibility iterator backed by the fair, bounded inventory."""
        yield from cls._fair_batch(root, "").paths

    @staticmethod
    def _severity_for(rule: str) -> Severity:
        low = rule.lower()
        for token, severity in SEVERITY_HINTS.items():
            if token in low:
                return severity
        return Severity.HIGH

    @staticmethod
    def _file_identity(value: os.stat_result) -> tuple[int, ...]:
        return (value.st_dev, value.st_ino, value.st_size,
                value.st_mtime_ns, value.st_nlink)

    @staticmethod
    def _cache_usn(value: object) -> int:
        # Zero represents unavailable proof, never a reusable Windows token.
        return value if type(value) is int and 0 < value < (1 << 63) else 0

    @staticmethod
    def _event_digest(event: Event) -> str:
        return hashlib.sha256(json.dumps({
            "module": event.module, "message": event.message,
            "severity": int(event.severity), "ts": event.ts,
            "details": event.details,
        }, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False).encode("utf-8")).hexdigest()

    def verify_detection_event(self, event: Event) -> bool:
        """Verify an exact observation retained by this detector generation.

        Bus authentication alone identifies a ledger entry, not the code that
        produced it. Generic emit() calls cannot manufacture a scan receipt.
        This is same-process provenance, not an OS isolation boundary.
        """
        try:
            if event.module != self.name or self._bus is None:
                return False
            digest = YaraScannerModule._event_digest(event)
            with self._receipt_lock:
                return self._detection_receipts.get(digest) == self.lifecycle_generation
        except (TypeError, ValueError, OverflowError):
            return False

    @staticmethod
    def _response_classification(
        path: Path, payload: bytes, *, observed_content_sha256: str,
        observed_file_identity: dict[str, int],
    ) -> str:
        # A keyword in a report or source file must not quarantine that file.
        # Automatic authority is independent of editable rule names/metadata.
        marker = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
        if marker in payload or b"ANGERONA-BYOVD-DRILL-BENIGN-MARKER" in payload:
            from types import SimpleNamespace
            from angerona.core.practice_scope import provenance_for_event
            provenance = provenance_for_event(SimpleNamespace(details={
                "path": str(path),
                "observed_content_sha256": observed_content_sha256,
                "observed_file_identity": observed_file_identity,
            }))
            if provenance is not None and provenance.kind in {"shark", "red-team"}:
                return "registered-antimalware-probe"
            standard = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}" + b"$" + marker + b"!$H+H*"
            if payload[:68] == standard and not payload[68:].strip(b" \t\r\n\x1a"):
                return "standard-antimalware-test"
        if payload.startswith(b"MZ") and b"PE\x00\x00" in payload[:4096]:
            lowered = payload.lower()
            if all(token in lowered for token in
                   (b"sekurlsa::", b"logonpasswords", b"gentilkiwi")):
                return "credential-dumper-binary-signatures"
        return ""

    @staticmethod
    def _archive_contents(
        payload: bytes, *, checkpoint: Callable[[int], bool] | None = None,
    ):
        preflight_zip_bytes(payload, max_files=MAX_ARCHIVE_MEMBERS)
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            remaining = MAX_ARCHIVE_BYTES
            for member_index, member in enumerate(archive.infolist(), start=1):
                if member.is_dir():
                    continue
                if checkpoint is not None and not checkpoint(member_index):
                    raise InterruptedError("archive inspection stopped before complete coverage")
                if (member.flag_bits & 1 or member.file_size > remaining
                        or member.file_size > 1000 * max(1, member.compress_size)):
                    raise OSError("archive expansion or encryption prevents complete inspection")
                with archive.open(member) as stream:
                    content = stream.read(remaining + 1)
                if len(content) > remaining:
                    raise OSError("archive expansion budget exceeded")
                remaining -= len(content)
                yield member.filename[:512], content

    def _event_for_match(self, path, rule, member, digest, observed_file_identity,
                         classification, archive_error, *, control_details=None):
        # Construction alone grants no native receipt or response authority.
        details = {
            "path": str(path), "artifact_path": str(path), "rule": rule,
            "observed_content_sha256": digest,
            "observed_file_identity": observed_file_identity,
            "evidence_type": "native_analytic_detection", "detector_verdict": "positive",
            "producer_generation": self.lifecycle_generation,
            "detector_receipt_nonce": secrets.token_hex(16),
            "response_authorized": False, "scan_complete": not bool(archive_error),
        }
        if archive_error:
            details["coverage_reason"] = archive_error
        if member:
            details["archive_member"] = member
        if classification:
            details.update(authorize_response(("quarantine_file",), path=path))
            details["response_classification"] = classification
        else:
            details["response_withheld_reason"] = "heuristic signature requires corroboration"
        if control_details is not None:
            details.update(control_details)
        return Event(self.name, f"YARA match: {rule} {path}",
                     self._severity_for(rule), time.time(), details)

    def _scan_file(self, scanner, path: Path, *, control_scanner=None) -> str:
        capability = None
        control_event = None
        reservation = None
        try:
            path = Path(os.path.abspath(path))
            # A separate optional owner scanner is eligible only for an exact
            # issuer declaration. Unsupported controls never stop normal scans.
            if (type(control_scanner) is _OwnerControlScanner
                    and self._thread is threading.current_thread()
                    and path.name.startswith("_angerona_yara_control_")):
                control_capability = self._redteam_receipt_capability
                try:
                    declared = bool(control_capability is not None
                        and control_capability.is_yara_control_path(
                            self, str(path), control_scanner.enrollment))
                except Exception:
                    declared = False
                if declared:
                    scanner = control_scanner
            controlled = False
            scan_serial = 0
            if (type(scanner) is _OwnerControlScanner
                    and self._thread is threading.current_thread()
                    and scanner.owner == threading.get_ident()
                    and type(scanner).scan.__code__ is _CONTROL_WRAPPER_SCAN_CODE
                    and self._control_enrollment_valid(scanner.enrollment)):
                # Only the owner may dereference this weak native-wrapper ref.
                reference = self._control_owner_refs.get(scanner.enrollment.enrollment_id)
                controlled = bool(reference is not None and reference() is scanner)
                if controlled:
                    scan_serial = scanner.begin_file_scan()
                    capability = self._redteam_receipt_capability
            before = path.stat(follow_symlinks=False)
            if (self._is_reparse(before) or stat_module.S_ISLNK(before.st_mode)
                    or not stat_module.S_ISREG(before.st_mode) or before.st_nlink != 1):
                return "reparse-skipped"
            if before.st_size > MAX_FILE_BYTES:
                return "oversize-skipped"
            identity = self._file_identity(before)
            cache_key = str(path)
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            with os.fdopen(os.open(path, flags), "rb") as handle:
                opened = os.fstat(handle.fileno())
                if self._file_identity(opened) != identity:
                    raise OSError("file changed before signature inspection")
                observed_file_identity = {
                    "device": int(opened.st_dev),
                    "inode": int(opened.st_ino),
                    "birthtime_ns": int(getattr(opened, "st_birthtime_ns", 0) or 0),
                }
                # Windows ChangeTime can collide during rapid same-size writes.
                # Require stable descriptor-bound USN proof for metadata-only
                # cache reuse; unavailable proof still permits a content scan.
                from angerona.modules.file_integrity import FileIntegrityModule
                change_token = FileIntegrityModule._handle_change_token(handle.fileno())
                usn = (self._cache_usn(FileIntegrityModule._handle_usn(handle.fileno()))
                       if os.name == "nt" else 0)
                cacheable = os.name != "nt" or usn > 0
                if not cacheable:
                    self._scan_cache.pop(cache_key, None)
                confirmed_change = FileIntegrityModule._handle_change_token(handle.fileno())
                confirmed_usn = (
                    self._cache_usn(FileIntegrityModule._handle_usn(handle.fileno()))
                    if os.name == "nt" else 0
                )
                if (confirmed_change != change_token or confirmed_usn != usn
                        or self._file_identity(os.fstat(handle.fileno())) != identity
                        or self._file_identity(path.stat(follow_symlinks=False)) != identity):
                    self._scan_cache.pop(cache_key, None)
                    raise OSError("file changed before signature inspection")
                scan_identity = (id(scanner), *identity, change_token, usn)
                if cacheable and self._scan_cache.get(cache_key) == scan_identity:
                    self._scan_cache.move_to_end(cache_key)
                    return "scanned"
                self._scan_cache.pop(cache_key, None)
                payload = handle.read(int(opened.st_size) + 1)
                if len(payload) > MAX_FILE_BYTES:
                    raise OSError("file grew beyond signature budget")
                if len(payload) != int(opened.st_size):
                    raise OSError("file changed size during signature inspection")
                digest = hashlib.sha256(payload).hexdigest()
                results = scanner.scan(payload)
                matches = {str(match.identifier): "" for match in results.matching_rules}
                classification = self._response_classification(
                    path, payload, observed_content_sha256=digest,
                    observed_file_identity=observed_file_identity,
                )
                archive_error = str(getattr(scanner, "community_error", ""))[:500]
                # Inspect ZIP members in memory only; no extraction, recursion,
                # archive paths, encryption, or unbounded decompression.
                if payload.startswith(b"PK\x03\x04"):
                    try:
                        for member, content in self._archive_contents(
                            payload,
                            checkpoint=lambda count: self.background_checkpoint(count, batch_size=8),
                        ):
                            for match in scanner.scan(content).matching_rules:
                                matches.setdefault(str(match.identifier), member)
                            if getattr(scanner, "community_error", ""):
                                archive_error = str(scanner.community_error)[:500]
                            classification = classification or self._response_classification(
                                path, content, observed_content_sha256=digest,
                                observed_file_identity=observed_file_identity,
                            )
                    except Exception as exc:
                        # Loss of archive coverage must not erase a positive
                        # signature already proved in the outer bytes or an
                        # earlier member. Never cache this as a complete scan.
                        archive_error = f"{type(exc).__name__}: {exc}"[:500]
                final_change = FileIntegrityModule._handle_change_token(handle.fileno())
                final_usn = (self._cache_usn(FileIntegrityModule._handle_usn(handle.fileno()))
                             if os.name == "nt" else 0)
                if (self._file_identity(os.fstat(handle.fileno())) != identity
                        or final_change != change_token or final_usn != usn
                        or self._file_identity(path.stat(follow_symlinks=False)) != identity):
                    raise OSError("file changed during signature inspection")
                # Only the one declared inert recipe may need preparation while
                # the scanner descriptor is held. Ordinary detections continue
                # to be constructed/retained/published one at a time below.
                expected_rule = {".txt": "EICAR_Test_File", ".html": "EICAR_Test_File", ".zip": "EICAR_Test_File",
                                 ".sys": "Angerona_BYOVD_Probe"}.get(path.suffix.lower())
                if (controlled and capability is not None and classification
                        and not archive_error and expected_rule in matches):
                    try:
                        member = matches[expected_rule]
                        reservation = capability.reserve_yara_observation(self,
                            enrollment=scanner.enrollment, path=str(path), rule=expected_rule,
                            archive_member=member, observed_content_sha256=digest,
                            observed_file_identity=observed_file_identity,
                            scan_serial=scan_serial, scan_complete=True)
                        if reservation is not None:
                            metadata = {**self._enrollment_metadata(scanner.enrollment),
                                        "scan_serial": scan_serial}
                            control_details = {"yara_control_claim_id": reservation.claim_id,
                                "yara_control_scan_serial": scan_serial,
                                **{"yara_control_" + key: value for key, value in metadata.items()
                                   if key not in {"generation", "scan_serial"}}}
                            control_event = self._event_for_match(path, expected_rule, member,
                                digest, observed_file_identity, classification, archive_error,
                                control_details=control_details)
                            # Retain before sealing, then release this lock.
                            # This is bounded to one new controlled Event.
                            with self._receipt_lock:
                                event_digest = self._event_digest(control_event)
                                self._detection_receipts[event_digest] = self.lifecycle_generation
                                while len(self._detection_receipts) > 4096:
                                    self._detection_receipts.popitem(last=False)
                                self._control_proofs.retain(control_event,
                                    generation=self.lifecycle_generation,
                                    now=time.monotonic(), review=metadata)
                                self._control_proof_metadata[event_digest] = metadata
                                while len(self._control_proof_metadata) > 4096:
                                    self._control_proof_metadata.popitem(last=False)
                            if not capability.seal_yara_observation(self, reservation, control_event):
                                capability.cancel_yara_publication(self, reservation)
                                control_event = None
                    except Exception as exc:
                        # A held control cannot suppress ordinary scan evidence.
                        self._control_last_error = str(exc)[:500]
                        if reservation is not None:
                            capability.cancel_yara_publication(self, reservation)
                        control_event = None
            # The scanner's descriptor and every producer/issuer lock have
            # been released. Preserve baseline per-event ordinary receipt
            # availability, even when this file matches more than 4096 rules.
            for rule, member in matches.items():
                event = (control_event if control_event is not None
                         and rule == control_event.details["rule"] else
                         self._event_for_match(path, rule, member, digest,
                            observed_file_identity, classification, archive_error))
                with self._receipt_lock:
                    self._detection_receipts[self._event_digest(event)] = self.lifecycle_generation
                    while len(self._detection_receipts) > 4096:
                        self._detection_receipts.popitem(last=False)
                # Re-exposing the ordinary receipt does not reissue the sealed
                # claim or touch its strict producer proof/monotonic deadline.
                if self._bus is not None:
                    try:
                        self.publish_event(event)
                    except BaseException:
                        if reservation is not None and event is control_event:
                            # May already be reserved/moved by inline delivery:
                            # issuer cancellation must preserve that custody.
                            capability.cancel_yara_publication(self, reservation)
                        raise
            if archive_error:
                self.last_error = archive_error
                return "failed"
            if cacheable:
                self._scan_cache[cache_key] = scan_identity
                self._scan_cache.move_to_end(cache_key)
                while len(self._scan_cache) > MAX_SCAN_CACHE:
                    self._scan_cache.popitem(last=False)
            return "scanned"
        except Exception as exc:
            if capability is not None and reservation is not None:
                capability.cancel_yara_publication(self, reservation)
            self.last_error = str(exc)
            return "failed"
        finally:
            # Exception frames can outlive the worker. Detach native aliases
            # while still on the scanner's owning thread.
            scanner = None
            control_scanner = None
            results = None
            match = None

    def self_test(self) -> tuple[bool, str]:
        marker = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
        try:
            import yara_x
            rule = yara_x.compile(
                'rule EICAR_Min { strings: $e = "' + marker + '" condition: $e }')
            # Exercise the same scanner against inert bytes in memory, without
            # creating a disk artifact that other security tools may inspect.
            # Earlier readiness timeouts were not causally attributed to host
            # AV or disk I/O. Production file scanning is covered independently
            # by the Scan Center regression suite.
            scanner = self._make_scanner(rule)
            sample = (marker + " :: Angerona benign self-test").encode("ascii")
            matches = scanner.scan(sample).matching_rules
            if not any(str(m.identifier) == "EICAR_Min" for m in matches):
                return False, "FAIL - in-process YARA did not detect the EICAR marker"
            if scanner.scan(b"ordinary Angerona diagnostic text").matching_rules:
                return False, "FAIL - in-process YARA matched the benign comparison sample"
            active = self._find_rules()
            if active:
                self._compile_rules(Path(active))
            return True, "PASS - in-process YARA detected the test marker and ignored benign bytes"
        except Exception as exc:
            return False, f"FAIL - {exc}"
        finally:
            scanner = None
            matches = None

    def run(self) -> None:
        self._reload_failure = None
        replacement = None
        control_scanner = None
        control_capability = None
        control_rules = None
        control_epoch = None
        community_runtime = None
        community_warning = ""
        config = getattr(self, "_community_config", None)
        if config is not None:
            from angerona.core.community_yara_runtime import CommunityYaraRuntime
            community_runtime = CommunityYaraRuntime(config)
        rules = self._find_rules()
        if not rules:
            self.status = "error"
            self.set_health(0, "rules.yar not found")
            self.emit("YARA disabled: rules.yar not found.", Severity.MEDIUM)
            return
        try:
            compiled = self._activate(Path(rules))
            scanner = self._make_scanner(compiled)
        except Exception as exc:
            self.status = "error"
            self.last_error = str(exc)
            self.set_health(0, "in-process YARA unavailable")
            self.emit(f"YARA disabled: {exc}", Severity.MEDIUM)
            return

        try:
            state_status = self._load_cursor_state()
            if state_status not in {"new", "ok"}:
                self.set_health(40, f"fair traversal cursor unavailable ({state_status})")
            self.emit(f"YARA scanner active ({Path(rules).name}).", Severity.INFO)
            while not self.stopping:
                with self._rules_lock:
                    active_rules = self._compiled_rules
                if active_rules is not compiled:
                    try:
                        replacement = self._make_scanner(active_rules)
                    except Exception as exc:
                        self.last_error = str(exc)
                        self.set_health(20, "reloaded YARA rules could not be activated")
                        self._report_reload_failure(active_rules, exc)
                        self.sleep(_scan_interval())
                        continue
                    scanner = replacement
                    compiled = active_rules
                # Successful activation (or return to the still-active rules)
                # ends the failure episode; a later recurrence reports at once.
                if self._reload_failure is not None:
                    self.emit(
                        "YARA rule activation available again; reload failure episode ended.",
                        Severity.INFO, disposition="health", response_authorized=False,
                        finding_code="yara.rules.reload-recovered",
                        repeats_since_last_report=self._reload_failure[3],
                    )
                    self._reload_failure = None
                    self.last_error = ""
                normal_scanner = scanner
                if community_runtime is not None:
                    normal_scanner = community_runtime.compose(scanner)
                    community_status = community_runtime.snapshot()
                    warning = community_status["reason"] if community_status["state"] == "unavailable" else ""
                    if warning and warning != community_warning:
                        self.emit("Community YARA coverage unavailable: " + warning,
                            Severity.MEDIUM, disposition="health", response_authorized=False)
                    community_warning = warning
                if (control_capability is not self._redteam_receipt_capability
                        or control_rules is not compiled
                        or control_epoch != self._control_source_epoch
                        or (control_scanner is not None and not control_scanner.enrollment.active)):
                    if control_scanner is not None:
                        control_scanner.close()
                    control_scanner = self._optional_control_scanner()
                    control_capability = self._redteam_receipt_capability
                    control_rules = compiled
                    control_epoch = self._control_source_epoch
                scanned = 0
                failed = 0
                skipped = 0
                traversal_errors = 0
                incomplete_roots = 0
                truncated_roots = 0
                existing_roots = 0
                cycle_coverage: dict[str, dict[str, object]] = {}
                roots_state = self._cursor_state.setdefault("roots", {})
                if not isinstance(roots_state, dict):
                    roots_state = {}
                    self._cursor_state["roots"] = roots_state
                for root in scan_roots():
                    if self.stopping:
                        break
                    if not root.is_dir():
                        continue
                    existing_roots += 1
                    token = self._root_token(root)
                    record = roots_state.get(token)
                    if not isinstance(record, dict):
                        record = {"cursor": "", "incomplete_since": 0.0, "wraps": 0}
                    batch = self._fair_batch(
                        root, str(record.get("cursor", "")),
                        checkpoint=lambda count: self.background_checkpoint(count, batch_size=256),
                    )
                    if self.stopping:
                        break
                    traversal_errors += batch.errors
                    incomplete_roots += int(batch.incomplete)
                    truncated_roots += int(batch.discovery_truncated)
                    for path_index, path in enumerate(batch.paths):
                        if not self.background_checkpoint(path_index, batch_size=8):
                            break
                        if self.stopping:
                            break
                        if community_runtime is not None:
                            # A traversal may span thousands of files. Check the
                            # memory/5-second cache before even a scan-cache hit.
                            normal_scanner = community_runtime.compose(scanner)
                            community_status = community_runtime.snapshot()
                            warning = community_status["reason"] if community_status["state"] == "unavailable" else ""
                            if warning and warning != community_warning:
                                self.emit("Community YARA coverage unavailable: " + warning,
                                    Severity.MEDIUM, disposition="health", response_authorized=False)
                            community_warning = warning
                        if control_scanner is not None:
                            outcome = self._scan_file(normal_scanner, path, control_scanner=control_scanner)
                        else:
                            outcome = self._scan_file(normal_scanner, path)
                        if outcome == "scanned":
                            scanned += 1
                        elif outcome == "failed":
                            failed += 1
                        else:
                            skipped += 1
                    if self.stopping:
                        break
                    now = time.time()
                    incomplete_since = float(record.get("incomplete_since", 0.0) or 0.0)
                    if batch.incomplete and incomplete_since <= 0:
                        incomplete_since = now
                    elif not batch.incomplete:
                        incomplete_since = 0.0
                    roots_state[token] = {
                        "cursor": batch.next_cursor,
                        "incomplete_since": incomplete_since,
                        "wraps": int(record.get("wraps", 0)) + int(batch.wrapped),
                    }
                    cycle_coverage[token] = {
                        "root": str(root),
                        "visited": len(batch.paths),
                        "discovered": batch.discovered,
                        "errors": batch.errors,
                        "incomplete": batch.incomplete,
                        "discovery_truncated": batch.discovery_truncated,
                        "wrapped": batch.wrapped,
                        "oldest_unscanned_age_seconds": (
                            max(0.0, now - incomplete_since) if incomplete_since > 0 else 0.0
                        ),
                    }
                if self.stopping:
                    break
                self._coverage_snapshot = cycle_coverage
                state_saved = self._save_cursor_state()

                if self._cursor_state_status not in {"new", "ok"} or not state_saved:
                    health = 35
                    note = (
                        "YARA scanning active but authenticated fair cursor is unavailable "
                        f"({self._cursor_state_status}); coverage continuity is unproven"
                    )
                elif truncated_roots:
                    health = 35
                    note = (
                        f"YARA discovery bound reached in {truncated_roots} root(s); "
                        f"visited {scanned}, failures {failed}, traversal errors {traversal_errors}"
                    )
                elif traversal_errors or failed:
                    health = 60
                    note = (
                        f"YARA coverage partial: scanned {scanned}, skipped {skipped}, "
                        f"file failures {failed}, traversal errors {traversal_errors}"
                    )
                elif incomplete_roots:
                    health = 75
                    note = (
                        f"YARA fair rotation incomplete in {incomplete_roots} root(s): "
                        f"scanned {scanned}, skipped {skipped}; durable cursor will resume"
                    )
                elif skipped:
                    health = 85
                    note = (
                        f"YARA traversal complete but {skipped} bounded/reparse file(s) "
                        f"were not content-scanned; scanned {scanned}"
                    )
                elif existing_roots == 0:
                    health = 50
                    note = "no configured YARA scan root currently exists"
                else:
                    health = 100
                    note = (
                        f"complete YARA traversal: scanned {scanned}, skipped {skipped}, "
                        f"roots {existing_roots}"
                    )
                if community_warning:
                    health = min(health, 55)
                    note += "; community rule coverage unavailable"
                self.set_health(health, note)
                alert_key = f"{health}:{truncated_roots}:{traversal_errors}:{failed}"
                if health < 70 and alert_key != self._last_coverage_alert:
                    self._last_coverage_alert = alert_key
                    self.emit(
                        note,
                        Severity.HIGH if health <= 35 else Severity.MEDIUM,
                        finding_code="yara.coverage.incomplete",
                        response_authorized=False,
                        coverage=cycle_coverage,
                    )
                elif health >= 70:
                    self._last_coverage_alert = ""
                if len(self._seen_matches) > 4096:
                    self._seen_matches.clear()
                self._sleep_for_scan()
        finally:
            normal_scanner = None
            if community_runtime is not None:
                community_runtime.close()
            community_runtime = None
            scanner = None
            replacement = None
            if control_scanner is not None:
                control_scanner.close()
            control_scanner = None


_CONTROL_FACTORY_CODE = YaraScannerModule._make_control_scanner.__code__
_CONTROL_SCAN_CODE = YaraScannerModule._scan_file.__code__
_CONTROL_WRAPPER_SCAN_CODE = _OwnerControlScanner.scan.__code__
