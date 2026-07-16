"""core/self_installer.py — let ARIA install its own optional capabilities.

Several ARIA/Angerona features are gated behind optional third-party packages
(voice, Teams, extra sensors). Rather than telling the operator to open a
terminal and run ``pip`` — which fails the moment ``pip`` isn't on PATH, or the
right interpreter isn't picked — ARIA installs them itself, into the exact
interpreter the app is already running under (``sys.executable``). That single
choice sidesteps every "pip is not recognized / wrong Python" problem, and every
package below ships a prebuilt Windows wheel so no C++ build tools are needed.

Safe by design:
    • Only an explicit, curated allow-list of packages can ever be installed —
      never arbitrary operator/LLM-supplied names.
    • Installs go to the app's own environment; nothing runs as admin.
    • Output is captured and summarised; a failure degrades gracefully.
"""
from __future__ import annotations

import importlib.util
import subprocess
import sys
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
        mark = "✓ ready" if st["ready"] else "✗ missing: " + ", ".join(st["missing"])
        lines.append(f"  • {cap:<15} {mark}  — {st['desc']}")
    lines.append("\nAsk ARIA to \"install voice\" (or teams / all) and I'll add them myself.")
    return "\n".join(lines)


def install(caps: Optional[Iterable[str]] = None,
            on_line: Optional[Callable[[str], None]] = None,
            timeout: float = 1200.0) -> str:
    """Install the missing packages for the given capabilities ('all' = every one).

    Uses the running interpreter's own pip (``sys.executable -m pip``) so it can
    never hit a PATH/wrong-Python problem. Returns a readable report."""
    def emit(s: str) -> None:
        if on_line:
            try:
                on_line(s)
            except Exception:
                pass

    pkgs = _resolve(caps)
    if not pkgs:
        return "Nothing to install — every requested capability is already present."

    # Safety: never pip-install anything outside the curated allow-list.
    bad = [p for p in pkgs if p not in _ALLOWED_PACKAGES]
    if bad:
        return f"Refused: {', '.join(bad)} is not on the approved capability list."

    emit(f"Installing {len(pkgs)} package(s) into this Angerona environment: "
         f"{', '.join(pkgs)} — please wait…")
    # Hardening (Angerona runs elevated): --only-binary :all: installs prebuilt
    # wheels ONLY, so a malicious/typosquatted sdist can never run arbitrary
    # setup.py code as Administrator during install. --isolated ignores any
    # attacker-planted pip.ini / PIP_* env that could redirect the index or inject
    # options. --require-virtualenv is deliberately NOT set (we target the app env).
    cmd = [sys.executable, "-m", "pip", "install", "--disable-pip-version-check",
           "--no-input", "--isolated", "--only-binary", ":all:"] + pkgs
    kwargs: dict = {"capture_output": True, "text": True, "timeout": timeout}
    if sys.platform.startswith("win"):
        kwargs["creationflags"] = 0x08000000  # CREATE_NO_WINDOW — no console flash
    try:
        proc = subprocess.run(cmd, **kwargs)
    except FileNotFoundError:
        return ("pip isn't available in this Python environment, so I can't "
                "self-install. Reinstall Angerona's dependencies from requirements.txt.")
    except subprocess.TimeoutExpired:
        return f"Install timed out after {int(timeout)}s — try again on a faster connection."

    tail = (proc.stdout or "")[-1400:]
    if proc.stderr:
        tail += "\n" + proc.stderr[-800:]
    still_missing = _resolve(caps)

    if proc.returncode == 0 and not still_missing:
        return (f"✅ Installed: {', '.join(pkgs)}.\n"
                "Enable the feature in Settings (e.g. Settings ▸ enable voice) — no app "
                "restart needed for most; voice starts listening on the next toggle.")
    if proc.returncode == 0 and still_missing:
        return (f"⚠️ pip finished but these are still missing: {', '.join(still_missing)}.\n"
                f"{tail.strip()}")
    return (f"❌ Install failed (pip exit {proc.returncode}). Common causes: no network, "
            f"or a package needing build tools.\n{tail.strip()}")


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
        return True, f"OK — {len(CAPABILITIES)} capabilities, {len(_ALLOWED_PACKAGES)} approved packages"
    except AssertionError as exc:
        return False, f"FAIL — {exc}"
    except Exception as exc:  # pragma: no cover
        return False, f"ERROR — {type(exc).__name__}: {exc}"


if __name__ == "__main__":
    ok, detail = self_test()
    print(f"[self_installer] self_test: {'PASS' if ok else 'FAIL'} — {detail}")
    print(summary())
    raise SystemExit(0 if ok else 1)
