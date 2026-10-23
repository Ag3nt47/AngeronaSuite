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
    record, finish_journal = _journal()
    register_exit = atexit.register
    register_exit(finish_journal)
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
