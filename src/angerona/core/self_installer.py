"""Report ARIA's optional capabilities without mutating the live interpreter.

Optional Python packages are a software-supply-chain boundary.  Angerona's
audited installer consumes the repository's exact, hashed release lock; an
already-running GUI must not reach out to a package index and change the code it
is executing.  This module therefore provides discovery and setup guidance
only.  ``install()`` is retained as a compatibility entry point, but it always
refuses runtime mutation and directs the operator to the verified installer.
"""
from __future__ import annotations

import importlib.util
from typing import Callable, Iterable, List, Optional

# capability → (human description, [(import_name, pip_package), …])
# import_name is what we probe to see if it's already present; pip_package is
# what actually gets installed (they often differ, e.g. jwt ← PyJWT).
CAPABILITIES: dict[str, dict] = {
    "voice": {
        "desc": "Talk to ARIA and hear spoken replies (offline speech-to-text + text-to-speech)",
        "reqs": [("vosk", "vosk"), ("sounddevice", "sounddevice"), ("pyttsx3", "pyttsx3")],
    },
    "windows-speech": {
        "desc": "Windows SAPI voice (alternative text-to-speech backend)",
        "reqs": [("win32com", "pywin32")],
    },
    "teams": {
        "desc": "Two-way Microsoft Teams bot (chat with ARIA from Teams)",
        "reqs": [("jwt", "PyJWT"), ("requests", "requests")],
    },
    "hand-controls": {
        "desc": "Local camera hand-gesture navigation (frames are not retained)",
        "reqs": [("cv2", "opencv-python"), ("mediapipe", "mediapipe")],
    },
    "realtime-etw": {
        "desc": "Real-time ETW process sensor (event-driven, closes the polling gap)",
        "reqs": [("etw", "pywintrace")],
    },
    "network-arp": {
        "desc": "ARP-spoofing / poisoning watchdog on the local segment",
        "reqs": [("scapy", "scapy")],
    },
}

# Every package name that this module is ever allowed to hand to pip. Any request
# outside this set is refused — the LLM/operator cannot smuggle in an arbitrary
# package through a capability name.
_ALLOWED_PACKAGES = {pkg for spec in CAPABILITIES.values() for _, pkg in spec["reqs"]}


def _have(mod: str) -> bool:
    try:
        return importlib.util.find_spec(mod) is not None
    except Exception:
        return False


def capability_status() -> dict:
    """Report each capability: description, whether it's ready, and what's missing."""
    out: dict = {}
    for cap, spec in CAPABILITIES.items():
        missing = [pkg for mod, pkg in spec["reqs"] if not _have(mod)]
        out[cap] = {"desc": spec["desc"], "ready": not missing, "missing": missing}
    return out


def _resolve(caps: Optional[Iterable[str]]) -> List[str]:
    """Expand capability names (or 'all') into the missing pip packages to install."""
    names = list(caps) if caps else ["all"]
    if any(c.lower() in ("all", "everything", "*") for c in names):
        names = list(CAPABILITIES)
    pkgs: List[str] = []
    for cap in names:
        spec = CAPABILITIES.get(cap.lower().strip())
        if not spec:
            continue
        for mod, pkg in spec["reqs"]:
            if not _have(mod) and pkg not in pkgs:
                pkgs.append(pkg)
    return pkgs


def summary() -> str:
    """One-line-per-capability status the console/ARIA can print."""
    lines = ["ARIA capabilities:"]
    for cap, st in capability_status().items():
        mark = "[ready]" if st["ready"] else "[missing] " + ", ".join(st["missing"])
        lines.append(f"  - {cap:<15} {mark} - {st['desc']}")
    lines.append(
        "\nUse Install-Angerona.bat to add missing capabilities from Angerona's "
        "exact, SHA-256-locked release set. ARIA never changes its live Python "
        "environment."
    )
    return "\n".join(lines)


def capabilities_ready(caps: Optional[Iterable[str]] = None) -> bool:
    """Return whether every requested capability is already importable."""
    return not _resolve(caps)


def install(caps: Optional[Iterable[str]] = None,
            on_line: Optional[Callable[[str], None]] = None,
            timeout: float = 1200.0) -> str:
    """Refuse live package mutation and return verified setup guidance.

    ``on_line`` and ``timeout`` remain accepted so older callers do not break.
    They deliberately cannot alter this fail-closed policy.
    """
    del on_line, timeout
    pkgs = _resolve(caps)
    if not pkgs:
        return "Nothing to install — every requested capability is already present."

    # Keep the allow-list invariant even though this function no longer invokes
    # pip.  It prevents future callers from turning the compatibility entry point
    # back into an arbitrary-package channel by accident.
    bad = [p for p in pkgs if p not in _ALLOWED_PACKAGES]
    if bad:
        return f"Refused: {', '.join(bad)} is not on the approved capability list."
    return (
        "Runtime package installation refused; no interpreter changes were made.\n"
        f"Missing approved packages: {', '.join(pkgs)}.\n"
        "Close Angerona, run Install-Angerona.bat from the verified release, then "
        "restart. The installer uses requirements-release-hashed.txt with exact "
        "versions, SHA-256 hashes, binary wheels only, and no dependency drift."
    )


def self_test() -> tuple[bool, str]:
    """Offline sanity: the allow-list is non-empty, status is well-formed, and a
    bogus capability resolves to nothing (no accidental installs)."""
    try:
        assert _ALLOWED_PACKAGES, "allow-list empty"
        st = capability_status()
        assert "voice" in st and set(("ready", "missing", "desc")) <= set(st["voice"])
        assert _resolve(["does-not-exist"]) == [], "unknown capability must resolve to nothing"
        # every resolvable package stays within the allow-list
        assert set(_resolve(["all"])) <= _ALLOWED_PACKAGES
        report = install(["does-not-exist"])
        assert report.startswith("Nothing to install")
        return True, f"OK - {len(CAPABILITIES)} capabilities, {len(_ALLOWED_PACKAGES)} approved packages"
    except AssertionError as exc:
        return False, f"FAIL - {exc}"
    except Exception as exc:  # pragma: no cover
        return False, f"ERROR - {type(exc).__name__}: {exc}"


if __name__ == "__main__":
    ok, detail = self_test()
    print(f"[self_installer] self_test: {'PASS' if ok else 'FAIL'} - {detail}")
    print(summary())
    raise SystemExit(0 if ok else 1)
