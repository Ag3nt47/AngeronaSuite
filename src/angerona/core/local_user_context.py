"""Bounded local username hints for display and privacy, never authorization."""
from __future__ import annotations

import getpass
import os


class LocalUsernameUnavailable(RuntimeError):
    """No usable local username hint could be obtained."""


def local_username_hint() -> str:
    """Preserve getpass behavior, with a native OS fallback when unavailable.

    On Windows, missing username environment variables can make getpass raise
    ImportError on Python 3.12 or OSError on newer versions. os.getlogin uses
    Windows GetUserNameW instead of those variables. Neither result establishes
    a principal, enrollment, approval, or authenticated identity.
    """
    for lookup in (getpass.getuser, os.getlogin):
        try:
            value = lookup()
        except (ImportError, OSError):
            continue
        if (type(value) is str and 1 <= len(value) <= 256
                and value.strip() and value.isprintable()):
            return value
    raise LocalUsernameUnavailable("local username display/privacy context is unavailable")
