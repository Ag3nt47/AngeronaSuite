"""self_healer.py — Self-Debugging Co-Pilot (CODE: HEAL).

A strict "Try → Heal → Stage" loop. Giving an AI autonomous write-access to live
EDR code is unacceptable, so this module NEVER overwrites a running file. It
diagnoses crashes and *stages* a proposed patch for a human to review and apply.

Three phases
------------
1. The Catch (Try)
   ``BaseModule._wrapped_run`` already writes a JSON crash bundle to
   ``diagnostics/crash_snapshots/`` when a module quarantines after 3 crashes.
   HEAL tails that directory — so it hooks the existing crash path with zero
   changes to module_base.py. Each bundle carries the module name, the exact
   exception, and the full traceback.

2. The Diagnosis (Heal)
   HEAL resolves the failing source file from the traceback, reads it, and packs
   {traceback, source} into a strictly-constrained Ollama prompt instructing the
   model to return the corrected file as raw Python only.

3. The Judgment Gate (Stage)
   The returned code is *parsed with ast* before anything is written — a patch
   that doesn't even compile is discarded. Valid patches are written to
   ``staged_patches/<MODULE>_fix_v<N>.py`` and a HIGH alert is emitted with the
   staged path. The operator reviews and applies via the GUI "Apply Patch"
   button; HEAL itself has no write access to live modules.

Scope note
----------
Whole-*process* restart (if the Python interpreter dies) is the Watchdog's job,
not this module's — HEAL operates at the module-thread layer. See the
integration guide for wiring the process-level respawn.

Standard library only (json, os, re, ast, time, threading, urllib).
"""
from __future__ import annotations

import ast
import json
import os
import re
import time
import urllib.request
from pathlib import Path
from typing import Optional

from angerona.core.module_base import BaseModule, Severity


# ── Paths (mirror module_base._get_snapshot_dir) ──────────────────────────────
def _data_base() -> Path:
    base = os.environ.get("ANGERONA_DATA") or os.path.join(
        os.environ.get("LOCALAPPDATA", str(Path.home())), "Angerona"
    )
    return Path(base)


def _snapshot_dir() -> Path:
    d = _data_base() / "diagnostics" / "crash_snapshots"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _staged_dir() -> Path:
    d = _data_base() / "staged_patches"
    d.mkdir(parents=True, exist_ok=True)
    return d


# ── LLM prompt (strict: raw Python only) ─────────────────────────────────────
_HEAL_SYSTEM_PROMPT = (
    "You are an on-call Python developer fixing a crashed module in a security "
    "product. You are given a traceback and the FULL current source of the file "
    "that crashed. Identify the logic or syntax error and return the COMPLETE "
    "corrected file.\n"
    "OUTPUT RULES — follow exactly:\n"
    "  * Output ONLY valid Python source for the whole file.\n"
    "  * No markdown, no code fences, no commentary, no explanation.\n"
    "  * Preserve all imports, class names, and public function signatures.\n"
    "  * Change only what is necessary to fix the traceback."
)

_OLLAMA_HOST    = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
_OLLAMA_MODEL   = os.environ.get("ANGERONA_MODEL", "llama3")
_HEAL_TIMEOUT_S = 120.0     # code-gen is slow; HEAL runs in its own daemon thread
_MAX_SOURCE_CHARS = 24000   # guard against pathologically large files in the prompt


class SelfHealer(BaseModule):
    name = "HEAL"
    CODE = "HEAL"
    description = "Diagnoses crashed modules and stages LLM-proposed patches for operator review."
    category = "Resilience"
    version = "1.0.0"

    POLL_S = 10.0

    def __init__(self) -> None:
        super().__init__()
        self._seen: set[str] = set()
        self._staged = 0

    # ── Phase 1: catch (tail the crash-snapshot dir) ─────────────────────────
    def run(self) -> None:
        snap_dir = _snapshot_dir()
        # Don't retro-heal snapshots that predate this launch.
        try:
            self._seen = {p.name for p in snap_dir.glob("*.json")}
        except Exception:
            self._seen = set()

        while not self.stopping:
            self.sleep(self.POLL_S)
            try:
                for snap in sorted(snap_dir.glob("*.json")):
                    if snap.name in self._seen:
                        continue
                    self._seen.add(snap.name)
                    self._handle_snapshot(snap)
            except Exception as exc:
                self.set_health(70, f"poll error: {exc}")
            else:
                self.set_health(100, f"{self._staged} patches staged")

    def _handle_snapshot(self, snap: Path) -> None:
        try:
            bundle = json.loads(snap.read_text(encoding="utf-8"))
        except Exception as exc:
            self.emit(f"HEAL could not read crash snapshot {snap.name}: {exc}",
                      Severity.LOW)
            return

        module_name = bundle.get("module", "unknown")
        tb = bundle.get("traceback", "")
        if not tb:
            return

        src_path = self._source_from_traceback(tb)
        if not src_path:
            self.emit(f"HEAL: crash in '{module_name}' but couldn't resolve a "
                      "project source file from the traceback — skipping.",
                      Severity.LOW, module=module_name)
            return

        # ── Phase 2: diagnose ───────────────────────────────────────────────
        try:
            source = Path(src_path).read_text(encoding="utf-8")
        except Exception as exc:
            self.emit(f"HEAL: source '{src_path}' unreadable ({exc}) — skipping.",
                      Severity.LOW)
            return

        patched = self._request_fix(module_name, tb, source[:_MAX_SOURCE_CHARS])
        if not patched:
            self.emit(f"HEAL: no usable patch generated for '{module_name}'.",
                      Severity.MEDIUM, module=module_name)
            return

        # ── Phase 3: judgment gate (must parse) + stage ─────────────────────
        try:
            ast.parse(patched)
        except SyntaxError as exc:
            self.emit(f"HEAL: proposed patch for '{module_name}' rejected — it "
                      f"does not parse ({exc}). Not staged.",
                      Severity.MEDIUM, module=module_name)
            return

        staged_path = self._stage(src_path, patched)
        if staged_path:
            self._staged += 1
            self.emit(
                f"Bug detected in module {module_name}. Proposed patch staged for "
                f"review: {staged_path}",
                Severity.HIGH,
                module=module_name,
                source_file=src_path,
                staged_patch=str(staged_path),
            )

    # ── Helpers ───────────────────────────────────────────────────────────────
    @staticmethod
    def _source_from_traceback(tb: str) -> Optional[str]:
        """Pick the deepest project .py frame from a traceback.

        Skips stdlib / site-packages so we heal our own code, not a library.
        """
        frames = re.findall(r'File "([^"]+\.py)", line \d+', tb)
        if not frames:
            return None
        skip = ("site-packages", "dist-packages", os.sep + "lib" + os.sep + "python")
        project = [f for f in frames if not any(s in f for s in skip)]
        candidates = project or frames
        # deepest frame = last one in the traceback
        chosen = candidates[-1]
        return chosen if os.path.exists(chosen) else None

    def _request_fix(self, module_name: str, tb: str, source: str) -> Optional[str]:
        user = json.dumps({
            "module": module_name,
            "traceback": tb,
            "source_code": source,
        }, default=str)
        payload = json.dumps({
            "model": _OLLAMA_MODEL,
            "messages": [
                {"role": "system", "content": _HEAL_SYSTEM_PROMPT},
                {"role": "user",   "content": user},
            ],
            "stream": False,
            "keep_alive": "30m",
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{_OLLAMA_HOST}/api/chat", data=payload,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=_HEAL_TIMEOUT_S) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            content = (data.get("message", {}) or {}).get("content", "")
            return self._strip_fences(content)
        except Exception as exc:
            self.last_error = str(exc)
            self.set_health(50, f"Ollama unreachable for heal: {exc}")
            return None

    @staticmethod
    def _strip_fences(text: str) -> str:
        """Remove ```python … ``` fences the model may add despite instructions."""
        text = text.strip()
        m = re.search(r"```(?:python)?\s*(.*?)```", text, re.DOTALL)
        if m:
            return m.group(1).strip()
        return text

    def _stage(self, src_path: str, patched: str) -> Optional[Path]:
        stem = Path(src_path).stem
        n = 1
        while (_staged_dir() / f"{stem}_fix_v{n}.py").exists():
            n += 1
        out = _staged_dir() / f"{stem}_fix_v{n}.py"
        try:
            header = (f"# HEAL staged patch for {src_path}\n"
                      f"# Generated {time.strftime('%Y-%m-%d %H:%M:%S')} — REVIEW BEFORE APPLYING\n")
            out.write_text(header + patched, encoding="utf-8")
            return out
        except Exception as exc:
            self.emit(f"HEAL: failed to write staged patch: {exc}", Severity.MEDIUM)
            return None

    def self_test(self) -> tuple[bool, str]:
        try:
            _ = _snapshot_dir(); _ = _staged_dir()
            return True, f"watching crash snapshots; {self._staged} staged this session"
        except Exception as exc:
            return False, f"path setup failed: {exc}"


def register() -> BaseModule:
    return SelfHealer()
