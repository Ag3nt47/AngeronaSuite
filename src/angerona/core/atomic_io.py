"""Small bounded helpers for durable writes on antivirus-inspected Windows hosts."""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Callable

_RETRYABLE_WINDOWS_ERRORS = {5, 32, 33}


def replace_with_retry(
    source: Path,
    destination: Path,
    *,
    attempts: int = 7,
    base_delay_seconds: float = 0.015,
    replace: Callable[[Path, Path], None] = os.replace,
    sleeper: Callable[[float], None] = time.sleep,
) -> None:
    """Atomically replace a file, tolerating short antivirus sharing locks.

    The retry window is deliberately short and bounded.  Non-sharing failures
    fail immediately, and the final exception is always surfaced to the caller.
    """
    attempts = int(attempts)
    delay = float(base_delay_seconds)
    if not 1 <= attempts <= 20 or not 0 <= delay <= 0.25:
        raise ValueError("invalid atomic-replace retry budget")
    for index in range(attempts):
        try:
            replace(Path(source), Path(destination))
            return
        except PermissionError:
            if index + 1 >= attempts:
                raise
        except OSError as exc:
            if (
                index + 1 >= attempts
                or getattr(exc, "winerror", None) not in _RETRYABLE_WINDOWS_ERRORS
            ):
                raise
        sleeper(min(0.25, delay * (2 ** index)))
