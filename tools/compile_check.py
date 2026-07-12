#!/usr/bin/env python
"""
Fast syntax gate for Angerona — stdlib only, no venv / PySide6 / imports needed.

Byte-compiles every .py under src/angerona and reports any file that fails to
parse (SyntaxError / IndentationError), with file:line. This is the cheap first
line of defence that catches orphaned/duplicated edit fragments (e.g. a stray
`taged"])` tail or a mis-indented duplicate `return`) BEFORE the heavier
run-selfcheck.bat tries to import the package and dies at import time.

Usage:
    python tools/compile_check.py            # check src/angerona
    python tools/compile_check.py <dir>...   # check specific dirs/files

Exit code 0 = all files parse; 1 = at least one failed (count on stderr).
"""
from __future__ import annotations

import os
import py_compile
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_ROOT = HERE.parent / "src" / "angerona"


def _iter_py(targets: list[str]) -> list[Path]:
    files: list[Path] = []
    roots = [Path(t) for t in targets] if targets else [DEFAULT_ROOT]
    for root in roots:
        if root.is_file() and root.suffix == ".py":
            files.append(root)
        elif root.is_dir():
            for dirpath, dirnames, filenames in os.walk(root):
                # skip caches / virtualenvs / build artefacts
                dirnames[:] = [d for d in dirnames
                               if d not in {"__pycache__", "venv", ".venv", "build", ".git"}]
                for fn in filenames:
                    if fn.endswith(".py"):
                        files.append(Path(dirpath) / fn)
    return sorted(set(files))


def main(argv: list[str]) -> int:
    files = _iter_py(argv)
    if not files:
        print(f"[!] no .py files found under: {argv or [str(DEFAULT_ROOT)]}", file=sys.stderr)
        return 1

    failures: list[tuple[Path, str]] = []
    for f in files:
        try:
            py_compile.compile(str(f), doraise=True)
        except py_compile.PyCompileError as exc:
            # exc.exc_value carries the SyntaxError with filename + lineno
            failures.append((f, str(exc.exc_value).strip()))
        except Exception as exc:  # pragma: no cover — unexpected read error
            failures.append((f, f"{type(exc).__name__}: {exc}"))

    print(f"compile-check: {len(files)} file(s) scanned, {len(failures)} failed.")
    for f, msg in failures:
        try:
            rel = f.relative_to(DEFAULT_ROOT.parent.parent)
        except ValueError:
            rel = f
        print(f"  [!] {rel}\n        {msg}")

    if failures:
        print(f"\nFAIL — {len(failures)} file(s) do not parse.", file=sys.stderr)
        return 1
    print("OK — every file parses.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
