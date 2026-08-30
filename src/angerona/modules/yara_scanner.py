"""In-process YARA signature scanner with bounded, symlink-safe traversal.

The scanner uses the maintained ``yara-python`` package instead of launching a
writeable checkout/PATH executable from an elevated process. Rules are compiled
before activation and only changed files generate repeat alerts.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from angerona.core.atomic_io import replace_with_retry
from angerona.core.data_paths import data_dir, resource_root
from angerona.core.module_base import BaseModule, Severity


SCAN_DIRS = [
    Path(os.environ.get("USERPROFILE", str(Path.home()))) / "Downloads",
    data_dir() / "drill-sandbox",
]
MAX_FILES_PER_ROOT = 10_000
MAX_DISCOVERY_ENTRIES_PER_ROOT = 200_000
MAX_DIRECTORY_ENTRIES = 100_000
MAX_FILE_BYTES = 64 * 1024 * 1024
_CURSOR_SCHEMA = "angerona.yara-fair-cursor.v1"
_CURSOR_SIG = "hmac_sha256"

SEVERITY_HINTS = {
    "mimikatz": Severity.CRITICAL,
    "eicar": Severity.MEDIUM,
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
    name = "YARA Scanner"
    version = "1.12.1"
    description = "Scans Downloads and the isolated drill sandbox with in-process YARA."
    category = "Signatures"
    enabled_by_default = True
    watchdog_work_budget_seconds = 600.0

    def __init__(self) -> None:
        super().__init__()
        self._rules_lock = threading.RLock()
        self._compiled_rules = None
        self._scanner = None
        self._active_rules = ""
        self._seen_matches: dict[tuple[str, str], int] = {}
        self._cursor_state: dict[str, object] = {
            "schema": _CURSOR_SCHEMA,
            "sequence": 0,
            "roots": {},
        }
        self._cursor_state_status = "unloaded"
        self._coverage_snapshot: dict[str, dict[str, object]] = {}
        self._last_coverage_alert = ""

    def _repo_root(self) -> Path:
        return resource_root()

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
        scanner.set_timeout(10)
        scanner.max_matches_per_pattern(64)
        scanner.fast_scan(True)
        return scanner

    def _activate(self, path: Path):
        compiled = self._compile_rules(path)
        scanner = self._make_scanner(compiled)
        with self._rules_lock:
            self._compiled_rules = compiled
            self._scanner = scanner
            self._active_rules = str(path.resolve())
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
                if candidate_text is not None:
                    auto.parent.mkdir(parents=True, exist_ok=True)
                    auto_candidate = auto.with_suffix(".candidate")
                    auto_candidate.write_text(candidate_text, encoding="utf-8")
                    os.replace(auto_candidate, auto)
                os.replace(candidate, active)
                with self._rules_lock:
                    self._compiled_rules = compiled
                    self._scanner = self._make_scanner(compiled)
                    self._active_rules = str(active.resolve())
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
    def _fair_batch(cls, root: Path, cursor: str) -> _TraversalBatch:
        """Inventory one bounded root and rotate after the durable relative cursor."""
        candidates: list[tuple[str, Path]] = []
        stack = [root]
        errors = 0
        discovered_entries = 0
        discovery_truncated = False
        while stack and not discovery_truncated:
            current = stack.pop()
            try:
                entries = []
                with os.scandir(current) as iterator:
                    for entry in iterator:
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
        after = [item for item in candidates if (item[0].casefold(), item[0]) > cursor_key]
        before = [item for item in candidates if (item[0].casefold(), item[0]) <= cursor_key]
        wrapped = bool(cursor and not after)
        ordered = after + before
        selected = ordered[:MAX_FILES_PER_ROOT]
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

    def _scan_file(self, scanner, path: Path) -> str:
        try:
            stat = path.stat(follow_symlinks=False)
            if self._is_reparse(stat):
                return "reparse-skipped"
            if stat.st_size > MAX_FILE_BYTES:
                return "oversize-skipped"
            results = scanner.scan_file(str(path))
            for match in results.matching_rules:
                rule = str(match.identifier)
                key = (str(path), rule)
                if self._seen_matches.get(key) == stat.st_mtime_ns:
                    continue
                self._seen_matches[key] = stat.st_mtime_ns
                # Structured evidence lets the threat layer match this exact
                # path against short-lived in-memory drill provenance.  Never
                # infer practice status from the attacker-controlled filename,
                # rule name, or display message.
                self.emit(
                    f"YARA match: {rule} {path}",
                    self._severity_for(rule),
                    path=str(path),
                    artifact_path=str(path),
                    rule=rule,
                )
            return "scanned"
        except Exception as exc:
            # Every unreadable/transient/timeout result participates in coverage
            # health; silent failure would turn a hostile locked-file prefix into
            # false proof of a complete scan.
            self.last_error = str(exc)
            return "failed"

    def self_test(self) -> tuple[bool, str]:
        marker = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
        try:
            import yara_x
            rule = yara_x.compile(
                'rule EICAR_Min { strings: $e = "' + marker + '" condition: $e }')
            # Exercise the same scanner against inert bytes in memory. Writing
            # an EICAR-named marker to disk made the readiness probe contend with
            # the host AV and occasionally exceed the harness deadline even
            # though yara-x completed correctly; production file scanning is
            # covered independently by the Scan Center regression suite.
            scanner = self._make_scanner(rule)
            sample = (marker + " :: Angerona benign self-test").encode("ascii")
            matches = scanner.scan(sample).matching_rules
            if not any(str(m.identifier) == "EICAR_Min" for m in matches):
                return False, "FAIL - in-process YARA did not detect the EICAR marker"
            active = self._find_rules()
            if active:
                self._compile_rules(Path(active))
            return True, "PASS - in-process YARA compiled rules and detected EICAR"
        except Exception as exc:
            return False, f"FAIL - {exc}"

    def run(self) -> None:
        rules = self._find_rules()
        if not rules:
            self.status = "error"
            self.set_health(0, "rules.yar not found")
            self.emit("YARA disabled: rules.yar not found.", Severity.MEDIUM)
            return
        try:
            compiled = self._activate(Path(rules))
        except Exception as exc:
            self.status = "error"
            self.last_error = str(exc)
            self.set_health(0, "in-process YARA unavailable")
            self.emit(f"YARA disabled: {exc}", Severity.MEDIUM)
            return

        state_status = self._load_cursor_state()
        if state_status not in {"new", "ok"}:
            self.set_health(40, f"fair traversal cursor unavailable ({state_status})")
        self.emit(f"YARA scanner active ({Path(rules).name}).", Severity.INFO)
        while not self.stopping:
            with self._rules_lock:
                scanner = self._scanner
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
            for root in SCAN_DIRS:
                if self.stopping:
                    break
                if not root.is_dir():
                    continue
                existing_roots += 1
                token = self._root_token(root)
                record = roots_state.get(token)
                if not isinstance(record, dict):
                    record = {"cursor": "", "incomplete_since": 0.0, "wraps": 0}
                batch = self._fair_batch(root, str(record.get("cursor", "")))
                traversal_errors += batch.errors
                incomplete_roots += int(batch.incomplete)
                truncated_roots += int(batch.discovery_truncated)
                for path in batch.paths:
                    if self.stopping:
                        break
                    outcome = self._scan_file(scanner, path)
                    if outcome == "scanned":
                        scanned += 1
                    elif outcome == "failed":
                        failed += 1
                    else:
                        skipped += 1
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
            self.sleep(_scan_interval())
