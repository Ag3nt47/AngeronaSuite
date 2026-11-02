"""Observe pytest's real module exit without changing its arguments or verdict.

The optional independent journal survives a broken stdout pipe. Its atexit
markers bracket callbacks registered during pytest; callbacks registered before
this wrapper and subsequent native finalization are outside that boundary.
An explicit console opt-in mirrors bounded stage markers while CI is running.
"""
from __future__ import annotations

import atexit
import json
import os
from pathlib import Path
import runpy
import sys
import time


def _console_diagnostics():
    if os.environ.get("ANGERONA_PYTEST_CONSOLE_DIAGNOSTICS") != "1":
        return lambda *_args, **_fields: None
    try:
        write, flush = sys.stdout.write, sys.stdout.flush
    except Exception:
        return lambda *_args, **_fields: None
    encode, clock = json.dumps, time.monotonic
    kinds = frozenset({
        "process-start", "pytest-system-exit", "pytest-exception", "pytest-returned",
        "pytest-entrypoint-finished", "python-atexit-begin", "python-atexit-end",
    })
    allowed_fields = ("python", "argument_count", "exit_code", "exit_code_type", "exception_type")
    prefix, limit = "CI_PYTEST_STAGE ", 1024
    remaining = 7

    def record(kind, **fields):
        nonlocal remaining
        if kind not in kinds or remaining <= 0:
            return
        remaining -= 1
        try:
            row = {"kind": kind, "monotonic": clock()}
            for name in allowed_fields:
                if name not in fields:
                    continue
                value = fields[name]
                if type(value) is str:
                    row[name] = value[:128]
                elif value is None or type(value) is bool:
                    row[name] = value
                elif type(value) is int and value.bit_length() <= 64:
                    row[name] = value
            line = prefix + encode(row, ensure_ascii=True, separators=(",", ":")) + "\n"
            if len(line) > limit:
                line = prefix + encode({"kind": kind, "monotonic": row["monotonic"]}) + "\n"
            write(line)
            flush()
        except Exception:
            # Output diagnostics cannot replace pytest's verdict. Deliberately
            # leave cancellation and other BaseException subclasses untouched.
            pass

    return record


def _journal():
    path = os.environ.get("ANGERONA_PYTEST_EXIT_PATH")
    if not path:
        return (lambda *_args, **_fields: None), (lambda: None)
    try:
        stream = Path(path).open("x", encoding="utf-8", buffering=1)
    except (OSError, ValueError):
        # A diagnostic failure must not replace pytest's own process verdict.
        try:
            sys.stderr.write("CI pytest exit journal could not be opened.\n")
        except (OSError, ValueError):
            pass
        return (lambda *_args, **_fields: None), (lambda: None)

    # Keep independent references: tests can temporarily replace these module
    # attributes, and standard output may already have failed during shutdown.
    encode, clock, write, flush = json.dumps, time.monotonic, stream.write, stream.flush
    close = stream.close

    def record(kind, **fields):
        try:
            write(encode({"kind": kind, "monotonic": clock(), **fields}) + "\n")
            flush()
        except (OSError, ValueError):
            pass

    def finish():
        try:
            record("python-atexit-end")
        finally:
            # Retire only after pytest's callbacks and the final marker. A
            # failed diagnostic close must preserve the original exit result.
            try:
                close()
            except (OSError, ValueError):
                pass

    return record, finish


def main() -> None:
    if __package__ in {None, ""}:
        # ``python tools/ci_pytest.py`` otherwise exposes only tools/ at
        # sys.path[0]. run_module does not reproduce python -m's root entry,
        # so root-level helpers and the tools namespace become unimportable.
        # Anchor the explicitly selected script's checkout, never an arbitrary
        # working directory. Module-mode invocation already has its own path.
        repository = str(Path(__file__).resolve().parents[1])
        if repository not in sys.path:
            sys.path.insert(0, repository)
    journal_record, finish_journal = _journal()
    console_record = _console_diagnostics()

    def record(kind, **fields):
        journal_record(kind, **fields)
        console_record(kind, **fields)

    def finish():
        try:
            finish_journal()
        finally:
            console_record("python-atexit-end")

    register_exit = atexit.register
    register_exit(finish)
    record("process-start", python=sys.version.split()[0], argument_count=len(sys.argv) - 1)
    try:
        # Launch the actual pytest __main__, including its console stdout-flush
        # behavior. Direct-file mode has established its checkout import root.
        runpy.run_module("pytest", run_name="__main__", alter_sys=True)
    except SystemExit as exc:
        code = exc.code
        fields = {"exit_code_type": type(code).__name__[:128]}
        if code is None:
            fields["exit_code"] = code
        elif isinstance(code, int):
            fields["exit_code"] = int.__int__(code)
        record("pytest-system-exit", **fields)
        raise
    except BaseException as exc:
        record("pytest-exception", exception_type=type(exc).__name__[:128])
        raise
    else:
        record("pytest-returned")
    finally:
        record("pytest-entrypoint-finished")
        register_exit(record, "python-atexit-begin")


if __name__ == "__main__":
    main()
