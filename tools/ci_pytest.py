"""Observe pytest's real module exit without changing its arguments or verdict.

The optional independent journal survives a broken stdout pipe. Its atexit
markers bracket callbacks registered during pytest; callbacks registered before
this wrapper and subsequent native finalization are outside that boundary.
"""
from __future__ import annotations

import atexit
import json
import os
from pathlib import Path
import runpy
import sys
import time


def _journal():
    path = os.environ.get("ANGERONA_PYTEST_EXIT_PATH")
    if not path:
        return lambda *_args, **_fields: None
    try:
        stream = Path(path).open("x", encoding="utf-8", buffering=1)
    except (OSError, ValueError):
        # A diagnostic failure must not replace pytest's own process verdict.
        try:
            sys.stderr.write("CI pytest exit journal could not be opened.\n")
        except (OSError, ValueError):
            pass
        return lambda *_args, **_fields: None

    # Keep independent references: tests can temporarily replace these module
    # attributes, and standard output may already have failed during shutdown.
    encode, clock, write, flush = json.dumps, time.monotonic, stream.write, stream.flush

    def record(kind, **fields):
        try:
            write(encode({"kind": kind, "monotonic": clock(), **fields}) + "\n")
            flush()
        except (OSError, ValueError):
            pass

    return record


def main() -> None:
    record = _journal()
    register_exit = atexit.register
    register_exit(record, "python-atexit-end")
    record("process-start", python=sys.version.split()[0], argument_count=len(sys.argv) - 1)
    try:
        # Launch the actual pytest __main__, including its console stdout-flush
        # behavior. Module execution preserves the repository-root import path.
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
