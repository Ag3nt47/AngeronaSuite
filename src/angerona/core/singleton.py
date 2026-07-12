"""Single-instance guard.

Closing Angerona's window only hides it to the tray (it keeps protecting in the
background). Relaunching without using tray → Quit would otherwise start a
*second* full instance — every module twice, including a second YARA scanner
spawning scan windows. This guard makes the second launch detect the first and
exit cleanly.

Implementation: bind a listening socket on a fixed loopback port. Only one
process can hold it; the bind fails for any later instance. Keep the returned
socket alive for the lifetime of the app.
"""
from __future__ import annotations

import socket
from typing import Optional

_LOCK_PORT = 47921  # arbitrary loopback port reserved for the instance lock


def acquire_single_instance() -> Optional[socket.socket]:
    """Return a held socket if we're the only instance, else None."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Deliberately do NOT set SO_REUSEADDR — we want the second bind to fail.
    try:
        s.bind(("127.0.0.1", _LOCK_PORT))
        s.listen(1)
        return s
    except OSError:
        try:
            s.close()
        except Exception:
            pass
        return None
