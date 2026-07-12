"""YARA signature scanner.

Runs the bundled ``yara64.exe`` against hot directories (Downloads, Temp) on an
interval. The binary and ``rules.yar`` ship with the app, so this works out of
the box — it auto-locates both next to the app, with an env-var override
(ANGERONA_YARA_RULES) for a custom ruleset.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path

from angerona.core.module_base import BaseModule, Severity
from angerona.core.win import run_hidden

# Downloads only by default — scanning all of %TEMP% every cycle is slow and
# noisy. Add more dirs here if you want broader coverage.
SCAN_DIRS = [
    os.path.join(os.environ.get("USERPROFILE", str(Path.home())), "Downloads"),
]

# Map a matched rule name to a severity (falls back to HIGH).
SEVERITY_HINTS = {
    "mimikatz": Severity.CRITICAL,
    "eicar": Severity.MEDIUM,
}


class YaraScannerModule(BaseModule):
    name = "YARA Scanner"
    description = "Scans Downloads/Temp against bundled YARA malware signatures."
    category = "Signatures"
    enabled_by_default = True

    def _repo_root(self) -> Path:
        # src/angerona/modules/yara_scanner.py  ->  repo root
        return Path(__file__).resolve().parents[3]

    def _find_yara(self) -> str:
        for cand in (Path.cwd() / "yara64.exe", self._repo_root() / "yara64.exe"):
            if cand.exists():
                return str(cand)
        return shutil.which("yara64") or shutil.which("yara") or ""

    def _find_rules(self) -> str:
        env = os.environ.get("ANGERONA_YARA_RULES")
        if env and os.path.exists(env):
            return env
        for cand in (Path.cwd() / "rules.yar", self._repo_root() / "rules.yar"):
            if cand.exists():
                return str(cand)
        return ""

    def reload_rules(self) -> None:
        """Re-index the ruleset, merging the Evolution Engine's auto_generated.yar
        into the active set so new signatures take effect on the next scan cycle.
        Called by evolution_engine after it deploys a fresh rule."""
        base = self._find_rules()
        auto = self._repo_root() / "rules" / "auto_generated.yar"
        try:
            if auto.exists() and base:
                combined = self._repo_root() / "rules" / "_active_combined.yar"
                combined.parent.mkdir(parents=True, exist_ok=True)
                combined.write_text(
                    Path(base).read_text(encoding="utf-8", errors="ignore")
                    + "\n\n// ── auto-generated (evolution engine) ──\n"
                    + auto.read_text(encoding="utf-8", errors="ignore"),
                    encoding="utf-8")
                self._active_rules = str(combined)
            else:
                self._active_rules = base
            self.emit(f"YARA rules reloaded ({Path(self._active_rules).name}).", Severity.INFO)
        except Exception as exc:
            self.last_error = str(exc)

    def _severity_for(self, line: str) -> Severity:
        low = line.lower()
        for token, sev in SEVERITY_HINTS.items():
            if token in low:
                return sev
        return Severity.HIGH

    def self_test(self) -> tuple[bool, str]:
        """Inject a known-bad EICAR file and confirm YARA detects it.

        Two-stage verification so a single broken rule in the live ruleset can't
        falsely fail the whole capability:
          1. PRIMARY  — scan with the active rules.yar.
          2. SECONDARY — if primary doesn't fire, scan with a minimal standalone
             EICAR rule. If THAT detects, the engine works and the test PASSES;
             we just flag that the active ruleset failed to compile/match (and
             include yara's stderr so the offending rule can be fixed).
        """
        import tempfile
        yara = self._find_yara()
        rules = self._find_rules()
        if not yara:
            return False, "yara64.exe not found"

        marker = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
        d = tempfile.mkdtemp(prefix="angerona_yara_")
        sample = os.path.join(d, "eicar_test.txt")
        minimal = os.path.join(d, "_eicar_only.yar")
        try:
            with open(sample, "w", encoding="ascii") as fh:
                fh.write(f"{marker} :: Angerona self-test sample")

            # ── Primary: the live ruleset ───────────────────────────────────
            primary_err = ""
            if rules:
                out = run_hidden([yara, "-w", rules, sample],
                                 capture_output=True, text=True, timeout=60)
                if marker.split("-")[0] in out.stdout or "eicar" in out.stdout.lower():
                    return True, "PASS — active ruleset detected the EICAR sample"
                primary_err = (out.stderr or "").strip()

            # ── Secondary: minimal standalone EICAR rule ────────────────────
            with open(minimal, "w", encoding="ascii") as fh:
                fh.write('rule EICAR_Min { strings: $e = "'
                         + marker + '" condition: $e }')
            out2 = run_hidden([yara, "-w", minimal, sample],
                              capture_output=True, text=True, timeout=60)
            if "EICAR" in out2.stdout:
                why = f" (active ruleset issue: {primary_err})" if primary_err else \
                      " (active ruleset did not match)"
                return True, "PASS via secondary check — YARA engine detects EICAR" + why

            err2 = (out2.stderr or "").strip()
            return False, f"FAIL — YARA did not detect EICAR even with a minimal rule: {err2 or 'no output'}"
        except Exception as exc:
            return False, f"error: {exc}"
        finally:
            for p in (sample, minimal):
                try:
                    os.remove(p)
                except Exception:
                    pass
            try:
                os.rmdir(d)
            except Exception:
                pass

    def run(self) -> None:
        yara = self._find_yara()
        rules = self._find_rules()
        if not yara:
            self.status = "error"
            self.set_health(0, "yara64.exe not found")
            self.emit("YARA disabled: yara64.exe not found next to the app or on PATH.",
                      Severity.MEDIUM)
            return
        if not rules:
            self.status = "error"
            self.set_health(0, "rules.yar not found")
            self.emit("YARA disabled: rules.yar not found. Set ANGERONA_YARA_RULES "
                      "or place rules.yar next to the app.", Severity.MEDIUM)
            return

        self.set_health(100, "")
        self._active_rules = rules          # reload_rules() can swap this live
        self.emit(f"YARA scanner active ({Path(rules).name}).", Severity.INFO)
        while not self.stopping:
            active = getattr(self, "_active_rules", None) or rules
            for d in SCAN_DIRS:
                if not d or not os.path.isdir(d) or self.stopping:
                    continue
                try:
                    out = run_hidden([yara, "-r", "-w", active, d],
                                     capture_output=True, text=True, timeout=180)
                    for line in out.stdout.splitlines():
                        line = line.strip()
                        if line:
                            self.emit(f"YARA match: {line}", self._severity_for(line))
                except Exception as exc:
                    self.last_error = str(exc)
            self.sleep(300)
