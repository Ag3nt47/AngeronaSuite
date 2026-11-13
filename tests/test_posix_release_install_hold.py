"""Offline policy: no unverified POSIX payload can be copied or launched.

The helper is deliberately held, not a completed signed binary installer.
Tests inspect its tiny shell source without running a shell or installer.
"""
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "Install-Angerona-Release.sh"


def source():
    return SCRIPT.read_text(encoding="utf-8")


def test_binary_installation_has_explicit_unconditional_failure_and_no_insecure_override():
    text = source()
    assert text.rstrip().endswith("exit 1")
    assert "HELD: authenticated Linux/macOS binary installation is not available." in text
    assert "archive-to-payload binding is not implemented" in text
    assert "No application files, launchers or preferences were changed." in text
    # These are the only argument-dependent branches. There is no host, UID,
    # environment, archive-name or user-supplied command authority to fall back to.
    assert text.count("exit 0") == 1
    assert '--help|-h)' in text
    assert set(re.findall(r'\$(?:\{[^}]+\}|[A-Za-z_][A-Za-z0-9_]*|[#0-9@*])', text)) == {"$#", "$1"}
    assert "$(" not in text and chr(96) not in text


def test_no_filesystem_or_payload_execution_command_remains_reachable():
    text = source()
    forbidden = re.compile(r"^\s*(?:install|cp|mv|rm|mkdir|chmod|chown|ditto|open|nohup|exec|python[0-9.]*|gh|curl|wget|tar|unzip|source|\.)\s", re.MULTILINE)
    assert forbidden.search(text) is None
    assert not re.search(r"(?:^|\s)(?:eval|sudo|su)\s", text)
    # stderr is the only redirection; no launcher/desktop/payload output path.
    assert [line.strip() for line in text.splitlines() if ">" in line] == [
        "'Use --help for the supported source-setup route and the current preview limit.' >&2"
    ]
    assert not re.search(r"(?:^|[^&])&\s*$", text, re.MULTILINE)


def test_help_is_informational_and_never_claims_completed_binary_verification():
    text = source()
    assert "Linux/macOS binary installation is currently unavailable." in text
    assert "official outer archive must be authenticated" in text
    assert "its installed payload bound to those exact bytes" in text
    assert "For reviewed source setup, use install-angerona.sh from the official source checkout." in text
    assert "--no-launch" in text
    assert not re.search(r"\b(?:PASS|VERIFIED|SUCCESS)\b", text)
