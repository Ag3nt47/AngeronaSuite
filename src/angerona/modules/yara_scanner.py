"""In-process YARA signature scanner with bounded, symlink-safe traversal.

The scanner uses the maintained ``yara-python`` package instead of launching a
writeable checkout/PATH executable from an elevated process. Rules are compiled
before activation and only changed files generate repeat alerts.
"""
from __future__ import annotations

import os
import sys
import tempfile
import threading
from pathlib import Path
from typing import Iterator

from angerona.core.data_paths import data_dir, resource_root
from angerona.core.module_base import BaseModule, Severity


SCAN_DIRS = [
    Path(os.environ.get("USERPROFILE", str(Path.home()))) / "Downloads",
    data_dir() / "drill-sandbox",
]
MAX_FILES_PER_ROOT = 10_000
MAX_FILE_BYTES = 64 * 1024 * 1024

SEVERITY_HINTS = {
    "mimikatz": Severity.CRITICAL,
    "eicar": Severity.MEDIUM,
}


class YaraScannerModule(BaseModule):
    name = "YARA Scanner"
    description = "Scans Downloads and the isolated drill sandbox with in-process YARA."
    category = "Signatures"
    enabled_by_default = True

    def __init__(self) -> None:
        super().__init__()
        self._rules_lock = threading.RLock()
        self._compiled_rules = None
        self._scanner = None
        self._active_rules = ""
        self._seen_matches: dict[tuple[str, str], int] = {}

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
    def _iter_files(root: Path) -> Iterator[Path]:
        """Bound traversal and never follow junctions/symlinks outside a scan root."""
        stack = [root]
        yielded = 0
        while stack and yielded < MAX_FILES_PER_ROOT:
            current = stack.pop()
            try:
                with os.scandir(current) as entries:
                    for entry in entries:
                        if yielded >= MAX_FILES_PER_ROOT:
                            return
                        try:
                            if entry.is_symlink():
                                continue
                            if entry.is_dir(follow_symlinks=False):
                                stack.append(Path(entry.path))
                            elif entry.is_file(follow_symlinks=False):
                                yielded += 1
                                yield Path(entry.path)
                        except OSError:
                            continue
            except OSError:
                continue

    @staticmethod
    def _severity_for(rule: str) -> Severity:
        low = rule.lower()
        for token, severity in SEVERITY_HINTS.items():
            if token in low:
                return severity
        return Severity.HIGH

    def _scan_file(self, scanner, path: Path) -> None:
        try:
            stat = path.stat()
            if stat.st_size > MAX_FILE_BYTES:
                return
            results = scanner.scan_file(str(path))
            for match in results.matching_rules:
                rule = str(match.identifier)
                key = (str(path), rule)
                if self._seen_matches.get(key) == stat.st_mtime_ns:
                    continue
                self._seen_matches[key] = stat.st_mtime_ns
                self.emit(f"YARA match: {rule} {path}", self._severity_for(rule))
        except Exception as exc:
            # Unreadable/transient files are expected in Downloads; a rule timeout
            # is recorded for diagnostics but does not collapse scanner health.
            self.last_error = str(exc)

    def self_test(self) -> tuple[bool, str]:
        marker = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
        try:
            import yara_x
            rule = yara_x.compile(
                'rule EICAR_Min { strings: $e = "' + marker + '" condition: $e }')
            with tempfile.TemporaryDirectory(prefix="angerona_yara_") as folder:
                sample = Path(folder) / "eicar_test.txt"
                sample.write_text(marker + " :: Angerona benign self-test", encoding="ascii")
                scanner = self._make_scanner(rule)
                matches = scanner.scan_file(str(sample)).matching_rules
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

        self.set_health(100, "")
        self.emit(f"YARA scanner active ({Path(rules).name}).", Severity.INFO)
        while not self.stopping:
            with self._rules_lock:
                scanner = self._scanner
            for root in SCAN_DIRS:
                if self.stopping:
                    break
                if not root.is_dir():
                    continue
                for path in self._iter_files(root):
                    if self.stopping:
                        break
                    self._scan_file(scanner, path)
            if len(self._seen_matches) > 4096:
                self._seen_matches.clear()
            self.sleep(300)
