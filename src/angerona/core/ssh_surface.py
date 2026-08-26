"""Read-only SSH exposure, key, runtime, and authentication evidence helpers.

This module deliberately does not run ``sshd -T``, contact a listener, edit an
OpenSSH file, capture credentials, or delete a key.  It turns bounded local
evidence into privacy-minimized observations for :mod:`ssh_surface_guard`.

The implementation is conservative in two important ways:

* OpenSSH's first-obtained-value semantics are honored for ordinary global
  directives.  ``Include`` and ``Match`` boundaries are reported as ambiguity
  rather than guessed through.
* Learned drift state is HMAC authenticated with a purpose-separated key
  derived from Angerona's 32-byte ``bus.key``.  A missing key, missing first
  baseline, or unauthenticated file is never described as trusted.
"""
from __future__ import annotations

import base64
import binascii
import fnmatch
import hashlib
import hmac
import ipaddress
import json
import math
import os
import re
import secrets
import stat
import sys
import time
from dataclasses import dataclass, field, replace
from itertools import islice
from pathlib import Path
from typing import Callable, Iterable, Mapping, Sequence

from defusedxml import ElementTree as SafeET


MAX_CONFIG_BYTES = 1024 * 1024
MAX_CONFIG_LINES = 8192
MAX_CONFIG_LINE_CHARS = 16 * 1024
MAX_AUTH_USERS = 128
MAX_AUTH_FILES = 256
MAX_AUTH_LINES = 4096
MAX_AUTH_FILE_BYTES = 1024 * 1024
MAX_KEY_BLOB_BYTES = 32 * 1024
MAX_HOST_KEYS = 32
MAX_RUNTIME_ROWS = 512
MAX_LOG_LINES = 2048
MAX_LOG_LINE_CHARS = 8192
MAX_LOG_BYTES = 1024 * 1024
MAX_LOG_EVIDENCE = 256
MAX_BASELINE_BYTES = 1024 * 1024
MAX_BASELINE_ITEMS = 1024
MAX_CONFIG_GRAPH_FILES = 32
MAX_CONFIG_GRAPH_DEPTH = 4
MAX_CONFIG_GRAPH_BYTES = 2 * 1024 * 1024
MAX_CONFIG_DIRECTORY_ROWS = 1024
MAX_WINDOWS_EVENT_ROWS = 256
MAX_SSH_PATH_CHARS = 4096

_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_BASELINE_DOMAIN = b"angerona/ssh-surface-baseline/v1\x00"
_PRIVACY_DOMAIN = b"angerona/ssh-surface-privacy/v1\x00"
_BASELINE_SCHEMA = 2
_LEGACY_BASELINE_SCHEMA = 1
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[a-z][a-z0-9_-]{0,20}:v1:[0-9a-f]{24,64}$")


class SSHSurfaceError(ValueError):
    """Base exception for rejected or ambiguous SSH evidence."""


class SSHConfigLimitError(SSHSurfaceError):
    """Raised when a configuration exceeds a strict parser bound."""


class SSHBaselineIntegrityError(SSHSurfaceError):
    """Raised internally when learned drift state fails authentication."""


@dataclass(frozen=True)
class SSHDirective:
    keyword: str
    arguments: tuple[str, ...]
    line: int
    scope: str


@dataclass(frozen=True)
class SSHOption:
    keyword: str
    arguments: tuple[str, ...]
    line: int | None
    state: str

    @property
    def value(self) -> str | None:
        return self.arguments[0] if self.arguments else None


@dataclass(frozen=True)
class ParsedSSHDConfig:
    directives: tuple[SSHDirective, ...]
    effective: Mapping[str, SSHDirective]
    errors: tuple[str, ...]
    include_lines: tuple[int, ...]
    match_lines: tuple[int, ...]
    digest: str

    def option(self, keyword: str) -> SSHOption:
        """Return a global option without pretending an earlier Include is inert."""
        name = str(keyword).strip().casefold()
        directive = self.effective.get(name)
        if directive is None:
            state = "ambiguous_include" if self.include_lines else "absent"
            return SSHOption(name, (), None, state)
        if any(line < directive.line for line in self.include_lines):
            return SSHOption(name, directive.arguments, directive.line, "ambiguous_include")
        return SSHOption(name, directive.arguments, directive.line, "explicit")

    def global_directives(self, keyword: str) -> tuple[SSHDirective, ...]:
        name = str(keyword).strip().casefold()
        return tuple(
            item for item in self.directives
            if item.scope == "global" and item.keyword == name
        )


@dataclass(frozen=True)
class SSHPostureFinding:
    code: str
    severity: str
    summary: str
    setting: str
    state: str
    recommendation: str


@dataclass(frozen=True)
class SSHPurposeKeys:
    baseline_key: bytes
    privacy_key: bytes


@dataclass(frozen=True)
class AuthorizedKeyCandidate:
    owner: str
    root: Path
    path: Path
    expected_uid: int | None = None
    expected_windows_owner: str | None = None


@dataclass(frozen=True)
class SSHLocalAccount:
    """Bounded local account data used only for per-user path expansion."""

    username: str
    home: Path
    uid: int | None = None


@dataclass(frozen=True)
class AuthorizedKeyEntry:
    fingerprint: str
    entry_digest: str
    algorithm: str
    owner_token: str
    path_token: str
    restrictions: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, object]:
        return {
            "fingerprint": self.fingerprint,
            "entry_digest": self.entry_digest,
            "algorithm": self.algorithm,
            "owner_token": self.owner_token,
            "path_token": self.path_token,
            "restrictions": list(self.restrictions),
        }


@dataclass(frozen=True)
class SSHInventoryIssue:
    code: str
    severity: str
    subject_token: str


@dataclass(frozen=True)
class AuthorizedKeyInventory:
    entries: tuple[AuthorizedKeyEntry, ...]
    issues: tuple[SSHInventoryIssue, ...]
    users_examined: int
    files_examined: int
    lines_examined: int
    dropped: int


@dataclass(frozen=True)
class SSHConfiguredSourceEvidence:
    source_token: str
    kind: str
    state: str
    digest: str | None
    custody: str

    def as_dict(self) -> dict[str, object]:
        return {
            "source_token": self.source_token,
            "kind": self.kind,
            "state": self.state,
            "digest": self.digest,
            "custody": self.custody,
        }


@dataclass(frozen=True)
class SSHConfigObservation:
    parsed: ParsedSSHDConfig
    aggregate_digest: str
    sources: tuple[SSHConfiguredSourceEvidence, ...]
    authorized_key_candidates: tuple[AuthorizedKeyCandidate, ...]
    issues: tuple[str, ...]
    files_observed: int


@dataclass(frozen=True)
class SSHServiceEvidence:
    service_token: str
    executable_token: str
    state: str
    start_mode: str
    renamed: bool
    nonstandard_binary: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "service_token": self.service_token,
            "executable_token": self.executable_token,
            "state": self.state,
            "start_mode": self.start_mode,
            "renamed": self.renamed,
            "nonstandard_binary": self.nonstandard_binary,
        }


@dataclass(frozen=True)
class SSHListenerEvidence:
    listener_token: str
    bind_token: str
    port: int
    scope: str
    service_token: str

    def as_dict(self) -> dict[str, object]:
        return {
            "listener_token": self.listener_token,
            "bind_token": self.bind_token,
            "port": self.port,
            "scope": self.scope,
            "service_token": self.service_token,
        }


@dataclass(frozen=True)
class SSHProcessEvidence:
    process_token: str
    executable_token: str
    role: str
    nonstandard_binary: bool
    forwarding_flags: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, object]:
        return {
            "process_token": self.process_token,
            "executable_token": self.executable_token,
            "role": self.role,
            "nonstandard_binary": self.nonstandard_binary,
            "forwarding_flags": list(self.forwarding_flags),
        }


@dataclass(frozen=True)
class SSHConnectionEvidence:
    connection_token: str
    local_token: str
    remote_token: str
    state: str
    direction: str
    process_token: str

    def as_dict(self) -> dict[str, object]:
        return {
            "connection_token": self.connection_token,
            "local_token": self.local_token,
            "remote_token": self.remote_token,
            "state": self.state,
            "direction": self.direction,
            "process_token": self.process_token,
        }


@dataclass(frozen=True)
class SSHRuntimeEvidence:
    services: tuple[SSHServiceEvidence, ...]
    listeners: tuple[SSHListenerEvidence, ...]
    issues: tuple[str, ...] = ()
    processes: tuple[SSHProcessEvidence, ...] = ()
    connections: tuple[SSHConnectionEvidence, ...] = ()


@dataclass(frozen=True)
class SSHLogEvidence:
    kind: str
    severity: str
    source_token: str
    account_token: str
    count: int
    new_source: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "severity": self.severity,
            "source_token": self.source_token,
            "account_token": self.account_token,
            "count": self.count,
            "new_source": self.new_source,
        }


@dataclass(frozen=True)
class SSHLogAnalysis:
    evidence: tuple[SSHLogEvidence, ...]
    observed_source_tokens: tuple[str, ...]
    lines_examined: int
    bytes_examined: int
    dropped_lines: int
    dropped_evidence: int


@dataclass(frozen=True)
class WindowsOpenSSHEvent:
    channel: str
    event_id: int
    record_id: int
    message: str


@dataclass(frozen=True)
class SSHBaselineComparison:
    status: str
    baseline_trusted: bool
    reason: str
    changes: Mapping[str, object] = field(default_factory=dict)

    @property
    def drifted(self) -> bool:
        return any(bool(value) for value in self.changes.values())


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    out: dict[str, object] = {}
    for key, value in pairs:
        if key in out:
            raise SSHBaselineIntegrityError(f"duplicate baseline field: {key}")
        out[key] = value
    return out


def _purpose_token(key: bytes, purpose: bytes, value: object, prefix: str) -> str:
    if isinstance(value, bytes):
        material = value[:65536]
    else:
        material = str(value).encode("utf-8", "surrogatepass")[:4096]
    digest = hmac.new(key, purpose + b"\x00" + material, hashlib.sha256).hexdigest()
    return f"{prefix}:v1:{digest[:32]}"


def load_ssh_purpose_keys(
    data_root: Path | str | None = None,
    *,
    master_key: bytes | None = None,
) -> SSHPurposeKeys | None:
    """Load and domain-separate Angerona's key; never create or rotate it here."""
    key = master_key
    if key is not None and (not isinstance(key, bytes) or len(key) != 32):
        raise ValueError("SSH purpose-key override must contain exactly 32 bytes")
    if key is None:
        if data_root is None:
            from angerona.core.data_paths import data_dir
            root = data_dir()
        else:
            root = Path(data_root)
        path = root / "bus.key"
        try:
            encoded = safe_read_bounded(path, max_bytes=256).decode(
                "ascii", "strict"
            ).strip()
            key = bytes.fromhex(encoded)
        except (OSError, UnicodeError, ValueError):
            return None
        if len(key) != 32:
            return None
    return SSHPurposeKeys(
        baseline_key=hmac.new(key, _BASELINE_DOMAIN, hashlib.sha256).digest(),
        privacy_key=hmac.new(key, _PRIVACY_DOMAIN, hashlib.sha256).digest(),
    )


def _lex_openssh_line(line: str) -> tuple[str, ...]:
    """Tokenize one OpenSSH line, honoring comments, quotes, and escapes."""
    tokens: list[str] = []
    current: list[str] = []
    quote = ""
    escaped = False
    token_started = False
    for char in line:
        if escaped:
            current.append(char)
            escaped = False
            token_started = True
            continue
        if char == "\\":
            escaped = True
            token_started = True
            continue
        if quote:
            if char == quote:
                quote = ""
            else:
                current.append(char)
            token_started = True
            continue
        if char == '"':
            quote = char
            token_started = True
            continue
        if char == "#":
            break
        if char.isspace():
            if token_started:
                tokens.append("".join(current))
                current = []
                token_started = False
            continue
        current.append(char)
        token_started = True
    if escaped:
        raise SSHSurfaceError("trailing escape")
    if quote:
        raise SSHSurfaceError("unterminated quote")
    if token_started:
        tokens.append("".join(current))
    return tuple(tokens)


def parse_sshd_config(
    content: str | bytes,
    *,
    max_bytes: int = MAX_CONFIG_BYTES,
    max_lines: int = MAX_CONFIG_LINES,
    max_line_chars: int = MAX_CONFIG_LINE_CHARS,
) -> ParsedSSHDConfig:
    """Parse one bounded sshd_config without expanding Include or executing sshd."""
    if type(max_bytes) is not int or not 1 <= max_bytes <= 16 * 1024 * 1024:
        raise ValueError("invalid sshd_config byte bound")
    if type(max_lines) is not int or not 1 <= max_lines <= 65536:
        raise ValueError("invalid sshd_config line bound")
    if type(max_line_chars) is not int or not 1 <= max_line_chars <= 64 * 1024:
        raise ValueError("invalid sshd_config line-length bound")
    if isinstance(content, bytes):
        raw = content
        try:
            text = raw.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise SSHSurfaceError("sshd_config is not valid UTF-8") from exc
    elif isinstance(content, str):
        if len(content) > max_bytes:
            raise SSHConfigLimitError("sshd_config exceeds byte bound")
        text = content
        raw = content.encode("utf-8")
    else:
        raise TypeError("sshd_config content must be text or bytes")
    if len(raw) > max_bytes:
        raise SSHConfigLimitError("sshd_config exceeds byte bound")
    if "\x00" in text:
        raise SSHSurfaceError("sshd_config contains NUL data")
    lines = text.splitlines()
    if len(lines) > max_lines:
        raise SSHConfigLimitError("sshd_config exceeds line bound")

    directives: list[SSHDirective] = []
    effective: dict[str, SSHDirective] = {}
    errors: list[str] = []
    include_lines: list[int] = []
    match_lines: list[int] = []
    scope = "global"
    for number, line in enumerate(lines, 1):
        if len(line) > max_line_chars:
            raise SSHConfigLimitError(f"sshd_config line {number} exceeds bound")
        try:
            tokens = _lex_openssh_line(line)
        except SSHSurfaceError as exc:
            errors.append(f"line:{number}:{exc}")
            continue
        if not tokens:
            continue
        keyword = tokens[0].casefold()
        arguments = tokens[1:]
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", keyword):
            errors.append(f"line:{number}:invalid-keyword")
            continue
        if keyword == "match":
            match_lines.append(number)
            scope = "match"
            if not arguments:
                errors.append(f"line:{number}:empty-match")
            directives.append(SSHDirective(keyword, arguments, number, scope))
            continue
        directive = SSHDirective(keyword, arguments, number, scope)
        directives.append(directive)
        if not arguments:
            errors.append(f"line:{number}:missing-argument")
            continue
        if scope == "global":
            if keyword == "include":
                include_lines.append(number)
            # OpenSSH generally assigns each scalar only when it is unset.
            # Multi-valued directives remain available through global_directives.
            effective.setdefault(keyword, directive)

    return ParsedSSHDConfig(
        directives=tuple(directives),
        effective=effective,
        errors=tuple(errors),
        include_lines=tuple(include_lines),
        match_lines=tuple(match_lines),
        digest=hashlib.sha256(raw).hexdigest(),
    )


def _finding(
    code: str,
    severity: str,
    summary: str,
    setting: str,
    state: str,
    recommendation: str,
) -> SSHPostureFinding:
    return SSHPostureFinding(code, severity, summary, setting, state, recommendation)


def _yes_no(value: str | None) -> bool | None:
    if value is None:
        return None
    normalized = value.casefold()
    if normalized in {
        "yes", "true", "on", "1", "all", "local", "remote",
        "clientspecified", "point-to-point", "ethernet",
    }:
        return True
    if normalized in {"no", "false", "off", "0", "none"}:
        return False
    return None


def _integer(value: str | None) -> int | None:
    try:
        parsed = int(str(value), 10)
    except (TypeError, ValueError):
        return None
    return parsed if 0 <= parsed <= 1_000_000 else None


def evaluate_sshd_posture(
    parsed: ParsedSSHDConfig,
    *,
    platform: str | None = None,
) -> tuple[SSHPostureFinding, ...]:
    """Return conservative hardening findings; values never contain identities."""
    target = (platform or sys.platform).casefold()
    findings: list[SSHPostureFinding] = []
    if parsed.errors:
        findings.append(_finding(
            "ssh.config.syntax_ambiguous", "high",
            "OpenSSH configuration contains syntax that could not be evaluated safely.",
            "sshd_config", "ambiguous", "Review the reported line numbers with sshd's native validator.",
        ))
    if parsed.match_lines:
        findings.append(_finding(
            "ssh.config.match_scope", "medium",
            "Conditional Match blocks require identity-specific evaluation.",
            "Match", "conditional", "Review every Match branch and keep privileged access explicitly allowlisted.",
        ))

    def option(name: str) -> SSHOption:
        value = parsed.option(name)
        if value.state == "ambiguous_include":
            findings.append(_finding(
                f"ssh.config.include_ambiguity.{name.casefold()}", "high",
                f"{name} may be set by an earlier Include and cannot be inferred safely.",
                name, "unknown", "Resolve the bounded Include chain with an operator-approved native configuration test.",
            ))
        return value

    password = option("PasswordAuthentication")
    password_value = _yes_no(password.value) if password.state == "explicit" else (
        True if password.state == "absent" else None
    )
    if password_value is not False:
        findings.append(_finding(
            "ssh.auth.password_enabled" if password_value else "ssh.auth.password_unknown",
            "high", "Password SSH authentication is enabled or not provably disabled.",
            "PasswordAuthentication", "enabled" if password_value else "unknown",
            "Disable password authentication after verified public-key or hardware-backed access is available.",
        ))

    keyboard_options = [
        parsed.option("KbdInteractiveAuthentication"),
        parsed.option("ChallengeResponseAuthentication"),
    ]
    explicit_keyboard = sorted(
        (item for item in keyboard_options if item.state == "explicit"),
        key=lambda item: item.line or 0,
    )
    keyboard_ambiguous = any(item.state == "ambiguous_include" for item in keyboard_options)
    keyboard_value = (
        _yes_no(explicit_keyboard[0].value) if explicit_keyboard and not keyboard_ambiguous
        else (None if keyboard_ambiguous else True)
    )
    if keyboard_value is not False:
        findings.append(_finding(
            "ssh.auth.keyboard_interactive_enabled" if keyboard_value else "ssh.auth.keyboard_interactive_unknown",
            "high", "Keyboard-interactive SSH authentication is enabled or uncertain.",
            "KbdInteractiveAuthentication", "enabled" if keyboard_value else "unknown",
            "Explicitly disable keyboard-interactive and legacy challenge-response authentication.",
        ))

    empty = option("PermitEmptyPasswords")
    if empty.state == "explicit" and _yes_no(empty.value) is True:
        findings.append(_finding(
            "ssh.auth.empty_passwords", "critical", "SSH permits empty-password accounts.",
            "PermitEmptyPasswords", "enabled", "Set PermitEmptyPasswords no and review affected accounts.",
        ))

    root = option("PermitRootLogin")
    root_value = root.value.casefold() if root.value and root.state == "explicit" else (
        "prohibit-password" if root.state == "absent" else "unknown"
    )
    if root_value not in {
        "yes", "no", "prohibit-password", "forced-commands-only", "without-password", "unknown"
    }:
        root_value = "invalid-or-unknown"
    if root_value != "no":
        findings.append(_finding(
            "ssh.auth.root_access", "high" if root_value == "yes" else "medium",
            "Direct root SSH access is allowed or not provably disabled.",
            "PermitRootLogin", root_value,
            "Set PermitRootLogin no and use separately attributable least-privilege accounts.",
        ))

    allow_users = option("AllowUsers")
    allow_groups = option("AllowGroups")
    if allow_users.state == "absent" and allow_groups.state == "absent":
        findings.append(_finding(
            "ssh.auth.allowlist_missing", "high", "SSH login identities are not constrained by an explicit allowlist.",
            "AllowUsers/AllowGroups", "absent", "Define the smallest explicit user or group allowlist required for administration.",
        ))
    elif "ambiguous_include" in {allow_users.state, allow_groups.state}:
        findings.append(_finding(
            "ssh.auth.allowlist_unknown", "high", "An SSH identity allowlist could not be verified across Include precedence.",
            "AllowUsers/AllowGroups", "unknown", "Verify a least-privilege allowlist in the fully resolved configuration.",
        ))

    for directive in parsed.directives:
        if directive.keyword == "match" and "administrators" in {
            item.casefold() for item in directive.arguments
        }:
            findings.append(_finding(
                "ssh.auth.administrator_group", "medium",
                "A privileged Administrators Match branch exposes a high-value remote access path.",
                "Match Group administrators", "conditional",
                "Constrain membership, require key-only authentication, and audit the shared administrator key file ACL.",
            ))
            break

    forwarding = option("AllowTcpForwarding")
    forward_value = _yes_no(forwarding.value) if forwarding.state == "explicit" else (
        True if forwarding.state == "absent" else None
    )
    if forward_value is not False:
        findings.append(_finding(
            "ssh.forwarding.tcp_enabled" if forward_value else "ssh.forwarding.tcp_unknown",
            "high", "SSH TCP forwarding can create an unmonitored pivot or tunnel.",
            "AllowTcpForwarding", "enabled" if forward_value else "unknown",
            "Set AllowTcpForwarding no unless a narrow, documented Match exception is required.",
        ))
    stream = option("AllowStreamLocalForwarding")
    stream_value = _yes_no(stream.value) if stream.state == "explicit" else (
        True if stream.state == "absent" else None
    )
    if stream_value is not False:
        findings.append(_finding(
            "ssh.forwarding.streamlocal_enabled" if stream_value else "ssh.forwarding.streamlocal_unknown",
            "medium", "SSH Unix-domain/socket forwarding is enabled or uncertain.",
            "AllowStreamLocalForwarding", "enabled" if stream_value else "unknown",
            "Disable stream-local forwarding unless a narrow operational exception is documented.",
        ))
    for name, code, summary, severity in (
        ("PermitTunnel", "ssh.forwarding.tun_enabled", "SSH layer-3 tunnel devices are enabled.", "high"),
        ("GatewayPorts", "ssh.forwarding.gateway_ports", "Forwarded ports may bind beyond loopback.", "high"),
        ("X11Forwarding", "ssh.forwarding.x11", "SSH X11 forwarding expands the remote attack surface.", "medium"),
        ("PermitUserEnvironment", "ssh.auth.user_environment", "Users may influence the SSH session environment.", "high"),
    ):
        value = option(name)
        # Some releases accept constrained non-boolean values (for example a
        # PermitUserEnvironment pattern list or GatewayPorts clientspecified).
        # Anything explicit other than a recognized "no" remains exposure.
        if value.state == "explicit" and _yes_no(value.value) is not False:
            findings.append(_finding(
                code, severity, summary, name, "enabled", f"Set {name} no unless a reviewed exception is required.",
            ))

    log_level = option("LogLevel")
    log_value = log_level.value.upper() if log_level.value and log_level.state == "explicit" else (
        "INFO" if log_level.state == "absent" else "UNKNOWN"
    )
    if log_value not in {"QUIET", "FATAL", "ERROR", "INFO", "VERBOSE", "DEBUG", "DEBUG1", "DEBUG2", "DEBUG3", "UNKNOWN"}:
        log_value = "UNKNOWN"
    if log_value not in {"VERBOSE", "DEBUG", "DEBUG1", "DEBUG2", "DEBUG3"}:
        findings.append(_finding(
            "ssh.logging.weak", "medium", "SSH authentication logging lacks strong connection and key detail.",
            "LogLevel", log_value.casefold(), "Use LogLevel VERBOSE and protect/forward the resulting audit trail.",
        ))

    auth_tries = option("MaxAuthTries")
    auth_value = _integer(auth_tries.value) if auth_tries.state == "explicit" else (
        6 if auth_tries.state == "absent" else None
    )
    if auth_value is None or auth_value > 3:
        findings.append(_finding(
            "ssh.rate.max_auth_tries", "medium", "SSH permits too many authentication attempts per connection.",
            "MaxAuthTries", str(auth_value) if auth_value is not None else "unknown", "Set MaxAuthTries to 3 or fewer.",
        ))
    grace = option("LoginGraceTime")
    grace_value = _parse_duration(grace.value) if grace.state == "explicit" else (
        120 if grace.state == "absent" else None
    )
    if grace_value is None or grace_value > 30:
        findings.append(_finding(
            "ssh.rate.login_grace", "medium", "Unauthenticated SSH sessions remain open too long.",
            "LoginGraceTime", str(grace_value) if grace_value is not None else "unknown", "Set LoginGraceTime to 30 seconds or less.",
        ))
    sessions = option("MaxSessions")
    session_value = _integer(sessions.value) if sessions.state == "explicit" else (
        10 if sessions.state == "absent" else None
    )
    if session_value is None or session_value > 2:
        findings.append(_finding(
            "ssh.session.max_sessions", "medium", "One SSH connection may multiplex too many sessions.",
            "MaxSessions", str(session_value) if session_value is not None else "unknown", "Set a low MaxSessions value consistent with administration needs.",
        ))
    startups = option("MaxStartups")
    startup_value = _parse_max_startups(startups.value) if startups.state == "explicit" else (
        (10, 30, 100) if startups.state == "absent" else None
    )
    if startup_value is None or startup_value[2] > 30 or startup_value[0] > 10:
        findings.append(_finding(
            "ssh.rate.max_startups", "medium", "The unauthenticated SSH connection limiter is weak or unknown.",
            "MaxStartups", ":".join(map(str, startup_value)) if startup_value else "unknown",
            "Use a bounded MaxStartups policy with a low hard ceiling and monitor drops.",
        ))
    alive = option("ClientAliveInterval")
    alive_value = _integer(alive.value) if alive.state == "explicit" else (
        0 if alive.state == "absent" else None
    )
    if alive_value in {None, 0}:
        findings.append(_finding(
            "ssh.session.idle_timeout", "low", "SSH does not enforce a server-side idle-session check.",
            "ClientAliveInterval", "disabled" if alive_value == 0 else "unknown",
            "Set a bounded ClientAliveInterval and ClientAliveCountMax for abandoned sessions.",
        ))

    # Windows OpenSSH frequently uses a privileged shared key file under this
    # branch. The branch itself is evidence, not attribution to any actor.
    if target.startswith("win") and not any(
        finding.code == "ssh.auth.administrator_group" for finding in findings
    ):
        admin_key = any(
            item.keyword == "authorizedkeysfile"
            and any("administrators_authorized_keys" in arg.casefold() for arg in item.arguments)
            for item in parsed.directives
        )
        if admin_key:
            findings.append(_finding(
                "ssh.auth.administrator_key_file", "medium",
                "A shared privileged administrator key file is configured.",
                "AuthorizedKeysFile", "privileged-shared-file",
                "Verify Administrators/SYSTEM-only ACLs and prefer individually attributable access.",
            ))
    return tuple(_dedupe_findings(findings))


def _dedupe_findings(findings: Iterable[SSHPostureFinding]) -> list[SSHPostureFinding]:
    seen: set[str] = set()
    out: list[SSHPostureFinding] = []
    for item in findings:
        if item.code not in seen:
            seen.add(item.code)
            out.append(item)
    return out


def _parse_duration(value: str | None) -> int | None:
    if not value:
        return None
    match = re.fullmatch(r"(?i)(\d+)([smhdw]?)", value.strip())
    if not match:
        return None
    amount = int(match.group(1))
    scale = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
    result = amount * scale[match.group(2).casefold()]
    return result if result <= 365 * 86400 else None


def _parse_max_startups(value: str | None) -> tuple[int, int, int] | None:
    if not value:
        return None
    parts = value.split(":")
    try:
        if len(parts) == 1:
            number = int(parts[0])
            result = (number, 100, number)
        elif len(parts) == 3:
            result = tuple(int(item) for item in parts)  # type: ignore[assignment]
        else:
            return None
    except ValueError:
        return None
    start, rate, full = result
    if not (1 <= start <= full <= 10000 and 1 <= rate <= 100):
        return None
    return start, rate, full


def canonical_sshd_config_candidates(
    platform: str | None = None,
    *,
    environ: Mapping[str, str] | None = None,
) -> tuple[Path, ...]:
    """Return bounded canonical candidates without searching the whole host."""
    target = (platform or sys.platform).casefold()
    env = environ if environ is not None else os.environ
    if target.startswith("win") or target == "windows":
        program_data = Path(env.get("ProgramData") or r"C:\ProgramData")
        system_root = Path(env.get("SystemRoot") or r"C:\Windows")
        return (
            program_data / "ssh" / "sshd_config",
            system_root / "System32" / "OpenSSH" / "sshd_config",
        )
    if target in {"darwin", "mac", "macos", "osx"}:
        return (
            Path("/private/etc/ssh/sshd_config"),
            Path("/etc/ssh/sshd_config"),
            Path("/usr/local/etc/ssh/sshd_config"),
        )
    return (
        Path("/etc/ssh/sshd_config"),
        Path("/usr/local/etc/ssh/sshd_config"),
    )


def _is_link_or_reparse(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        int(getattr(info, "st_file_attributes", 0)) & _REPARSE_POINT
    )


def path_has_link_or_reparse(path: Path | str) -> bool:
    """Best-effort component walk; unreadable components fail closed as unsafe."""
    target = Path(path)
    if not target.is_absolute():
        return True
    current = Path(target.anchor)
    for part in target.parts[1:]:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            return True
        if _is_link_or_reparse(info):
            return True
    return False


def safe_read_bounded(path: Path | str, *, max_bytes: int) -> bytes:
    """Read one ordinary, non-link file with a before/after identity check."""
    target = Path(path)
    if type(max_bytes) is not int or not 1 <= max_bytes <= 16 * 1024 * 1024:
        raise ValueError("invalid bounded-read size")
    if path_has_link_or_reparse(target):
        raise OSError("SSH evidence path traverses a symlink or reparse point")
    before = target.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > max_bytes:
        raise OSError("SSH evidence is not an ordinary bounded file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(target), flags)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or (
            getattr(before, "st_dev", None), getattr(before, "st_ino", None), before.st_size
        ) != (
            getattr(opened, "st_dev", None), getattr(opened, "st_ino", None), opened.st_size
        ):
            raise OSError("SSH evidence changed file type")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > max_bytes:
            raise OSError("SSH evidence exceeds read bound")
    finally:
        os.close(fd)
    after = target.lstat()
    if _is_link_or_reparse(after) or (
        getattr(before, "st_dev", None), getattr(before, "st_ino", None), before.st_size,
        getattr(before, "st_mtime_ns", None), getattr(before, "st_ctime_ns", None),
    ) != (
        getattr(after, "st_dev", None), getattr(after, "st_ino", None), after.st_size,
        getattr(after, "st_mtime_ns", None), getattr(after, "st_ctime_ns", None),
    ):
        raise OSError("SSH evidence changed during read")
    return data


def verify_windows_ssh_acl(
    path: Path | str,
    *,
    expected_owner: str | None = None,
) -> bool | None:
    """Verify Windows replacement custody for an SSH file and its parent chain.

    ``expected_owner`` admits the named local user for a per-user source.  When
    it is omitted, only SYSTEM and Builtin Administrators may own or mutate the
    target.  ``None`` means that the complete chain could not be proven; the
    caller must expose that state rather than treating it as safe.

    This intentionally checks more than the leaf DACL.  A writer with delete or
    child-creation rights on any ancestor can replace a protected-looking leaf
    through rename/delete semantics.
    """
    try:
        import ntsecuritycon  # type: ignore[import]
        import win32security  # type: ignore[import]
    except ImportError:
        return None
    target = Path(path)
    if not target.is_absolute():
        return None
    try:
        allowed = {"S-1-5-18", "S-1-5-32-544"}
        if expected_owner is not None:
            account = str(expected_owner).strip()
            if not account or len(account) > 256 or "\x00" in account:
                return None
            if re.fullmatch(r"S-\d(?:-\d+){1,15}", account, re.IGNORECASE):
                allowed.add(account.upper())
            else:
                lookup = getattr(win32security, "LookupAccountName", None)
                if lookup is None:
                    return None
                account_sid = lookup(None, account)[0]
                allowed.add(win32security.ConvertSidToStringSid(account_sid).upper())

        chain: list[Path] = []
        current = target
        for _index in range(64):
            chain.append(current)
            parent = current.parent
            if parent == current:
                break
            current = parent
        else:
            return None
        if not chain or chain[-1].parent != chain[-1]:
            return None

        base_write_mask = int(
            ntsecuritycon.FILE_GENERIC_WRITE
            | ntsecuritycon.FILE_ALL_ACCESS
            | ntsecuritycon.DELETE
            | ntsecuritycon.WRITE_DAC
            | ntsecuritycon.WRITE_OWNER
            | 0x40000000  # GENERIC_WRITE before generic-right mapping.
            | 0x10000000  # GENERIC_ALL before generic-right mapping.
        )
        delete_child = int(getattr(ntsecuritycon, "FILE_DELETE_CHILD", 0x00000040))
        inherit_only = int(getattr(win32security, "INHERIT_ONLY_ACE", 0x08))
        allowed_types = {
            int(getattr(win32security, "ACCESS_ALLOWED_ACE_TYPE", 0)),
            int(getattr(win32security, "ACCESS_ALLOWED_OBJECT_ACE_TYPE", 5)),
            int(getattr(win32security, "ACCESS_ALLOWED_CALLBACK_ACE_TYPE", 9)),
            int(getattr(win32security, "ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE", 11)),
        }
        denied_or_audit_types = {
            1, 2, 3, 6, 7, 8, 10, 12, 13, 14, 15, 16,
        }
        for component_index, component in enumerate(chain):
            security = win32security.GetNamedSecurityInfo(
                str(component),
                win32security.SE_FILE_OBJECT,
                win32security.OWNER_SECURITY_INFORMATION
                | win32security.DACL_SECURITY_INFORMATION,
            )
            owner = security.GetSecurityDescriptorOwner()
            dacl = security.GetSecurityDescriptorDacl()
            if owner is None or dacl is None:
                return False
            owner_sid = win32security.ConvertSidToStringSid(owner).upper()
            if owner_sid not in allowed:
                return False
            dangerous = base_write_mask | (delete_child if component_index else 0)
            for ace_index in range(int(dacl.GetAceCount())):
                ace = dacl.GetAce(ace_index)
                if not isinstance(ace, tuple) or len(ace) < 3:
                    return None
                header = ace[0]
                if not isinstance(header, tuple) or len(header) < 2:
                    return None
                ace_type = int(header[0])
                ace_flags = int(header[1])
                if ace_flags & inherit_only:
                    continue
                if ace_type not in allowed_types:
                    if ace_type not in denied_or_audit_types:
                        return None
                    continue
                mask = int(ace[1])
                sid = win32security.ConvertSidToStringSid(ace[-1]).upper()
                if mask & dangerous and sid not in allowed:
                    return False
        return True
    except Exception:
        return None


def _ssh_file_custody(
    path: Path,
    platform: str,
    *,
    expected_windows_owner: str | None = None,
) -> str:
    if platform.startswith("win") or platform == "windows":
        result = (
            verify_windows_ssh_acl(path, expected_owner=expected_windows_owner)
            if expected_windows_owner is not None
            else verify_windows_ssh_acl(path)
        )
        return "verified" if result is True else ("unsafe" if result is False else "unknown")
    try:
        info = path.lstat()
    except OSError:
        return "unknown"
    return "unsafe" if stat.S_IMODE(info.st_mode) & 0o022 else "verified"


def _configured_source_token(
    privacy_key: bytes,
    *,
    kind: str,
    identity: object,
) -> str:
    return _purpose_token(
        privacy_key,
        b"ssh-configured-source",
        f"{kind}\x00{identity}",
        "sourcefile",
    )


def _static_ssh_path(
    value: str,
    *,
    base: Path,
    environ: Mapping[str, str],
) -> Path | None:
    text = str(value or "").strip().strip('"')
    program_data = environ.get("ProgramData") or r"C:\ProgramData"
    text = re.sub(r"(?i)__PROGRAMDATA__", lambda _match: program_data, text)
    text = re.sub(r"(?i)%PROGRAMDATA%", lambda _match: program_data, text)
    if (
        not text
        or len(text) > MAX_SSH_PATH_CHARS
        or text.casefold() == "none"
        or any(marker in text for marker in ("%", "$", "~", "\x00"))
    ):
        return None
    candidate = Path(text)
    if not candidate.is_absolute():
        candidate = base / candidate
    try:
        return Path(os.path.abspath(str(candidate)))
    except OSError:
        return None


def _normalized_local_accounts(
    platform: str,
    environ: Mapping[str, str],
    supplied: Iterable[SSHLocalAccount] | None,
) -> tuple[tuple[SSHLocalAccount, ...], bool]:
    """Return bounded account/home records and whether enumeration was complete."""
    rows: list[SSHLocalAccount] = []
    complete = True
    if supplied is not None:
        for index, raw in enumerate(supplied):
            if index >= MAX_AUTH_USERS:
                complete = False
                break
            if not isinstance(raw, SSHLocalAccount):
                complete = False
                continue
            rows.append(raw)
    elif platform.startswith("win") or platform == "windows":
        # Profile directories are a bounded fallback, not proof of a complete
        # account database.  The result therefore stays explicitly incomplete.
        complete = False
        profile = environ.get("USERPROFILE")
        username = environ.get("USERNAME")
        if profile and username:
            rows.append(SSHLocalAccount(username=username, home=Path(profile)))
        users_root = Path(environ.get("SystemDrive", "C:")) / "Users"
        try:
            candidates = sorted(
                islice(users_root.iterdir(), MAX_AUTH_USERS + 1),
                key=lambda item: item.name.casefold(),
            )
            if len(candidates) > MAX_AUTH_USERS:
                complete = False
            for item in candidates[:MAX_AUTH_USERS]:
                if item.name.casefold() in {
                    "all users", "default", "default user", "public",
                }:
                    continue
                if item.is_dir() and not path_has_link_or_reparse(item):
                    rows.append(SSHLocalAccount(username=item.name, home=item))
        except OSError:
            pass
    else:
        try:
            import pwd

            discovered = sorted(pwd.getpwall(), key=lambda item: int(item.pw_uid))
            if len(discovered) > MAX_AUTH_USERS:
                complete = False
            for item in discovered[:MAX_AUTH_USERS]:
                rows.append(SSHLocalAccount(
                    username=str(item.pw_name),
                    home=Path(item.pw_dir),
                    uid=int(item.pw_uid),
                ))
        except (ImportError, OSError):
            complete = False

    normalized: dict[tuple[str, str], SSHLocalAccount] = {}
    for row in rows:
        username = str(row.username).strip()
        home = Path(row.home)
        uid = row.uid
        if (
            not username
            or len(username) > 256
            or any(character in username for character in ("\x00", "/", "\\"))
            or not home.is_absolute()
            or len(str(home)) > MAX_SSH_PATH_CHARS
            or (uid is not None and (type(uid) is not int or not 0 <= uid <= 2**63 - 1))
        ):
            complete = False
            continue
        identity = (username.casefold(), os.path.normcase(os.path.abspath(str(home))))
        normalized.setdefault(identity, SSHLocalAccount(username, home, uid))
        if len(normalized) >= MAX_AUTH_USERS:
            if len(rows) > len(normalized):
                complete = False
            break
    return tuple(normalized.values()), complete


def _per_user_source_path(
    value: str,
    *,
    account: SSHLocalAccount | None,
    environ: Mapping[str, str],
) -> tuple[str, Path | None, bool]:
    """Expand the bounded OpenSSH per-user token grammar.

    The returned boolean records whether plain relative-home semantics were
    used.  Unknown tokens, missing account data, and escaped relative paths are
    unresolved rather than converted into a false ``missing`` observation.
    """
    text = str(value or "").strip().strip('"')
    program_data = environ.get("ProgramData") or r"C:\ProgramData"
    text = re.sub(r"(?i)__PROGRAMDATA__", lambda _match: program_data, text)
    text = re.sub(r"(?i)%PROGRAMDATA%", lambda _match: program_data, text)
    if not text or len(text) > MAX_SSH_PATH_CHARS or "\x00" in text:
        return "unresolved", None, False
    if text.casefold() == "none":
        return "not-applicable", None, False
    if "$" in text or "~" in text:
        return "unresolved", None, False

    if "%" not in text:
        rendered = text
    else:
        expanded: list[str] = []
        expanded_length = 0
        index = 0
        while index < len(text):
            marker_index = text.find("%", index)
            if marker_index < 0:
                piece = text[index:]
                expanded.append(piece)
                expanded_length += len(piece)
                break
            if marker_index > index:
                piece = text[index:marker_index]
                expanded.append(piece)
                expanded_length += len(piece)
                if expanded_length > MAX_SSH_PATH_CHARS:
                    return "unresolved", None, False
                index = marker_index
            if index + 1 >= len(text):
                return "unresolved", None, False
            marker = text[index + 1]
            if marker == "%":
                piece = "%"
            elif marker in {"h", "u", "U"}:
                if account is None:
                    return "unresolved", None, False
                if marker == "h":
                    piece = str(account.home)
                elif marker == "u":
                    piece = account.username
                else:
                    if account.uid is None:
                        return "unresolved", None, False
                    piece = str(account.uid)
            else:
                return "unresolved", None, False
            index += 2
            expanded.append(piece)
            expanded_length += len(piece)
            if expanded_length > MAX_SSH_PATH_CHARS:
                return "unresolved", None, False
        rendered = "".join(expanded)
    if not rendered or len(rendered) > MAX_SSH_PATH_CHARS:
        return "unresolved", None, False
    candidate = Path(rendered)
    relative_home = not candidate.is_absolute()
    if relative_home:
        if account is None:
            return "unresolved", None, True
        candidate = account.home / candidate
    try:
        candidate = Path(os.path.abspath(str(candidate)))
    except OSError:
        return "unresolved", None, relative_home
    if relative_home and account is not None and not _lexically_within(account.home, candidate):
        return "unresolved", None, True
    return "resolved", candidate, relative_home


def observe_sshd_config_graph(
    root_path: Path | str,
    *,
    privacy_key: bytes,
    platform: str | None = None,
    environ: Mapping[str, str] | None = None,
    local_accounts: Iterable[SSHLocalAccount] | None = None,
    max_files: int = MAX_CONFIG_GRAPH_FILES,
    max_depth: int = MAX_CONFIG_GRAPH_DEPTH,
    max_total_bytes: int = MAX_CONFIG_GRAPH_BYTES,
) -> SSHConfigObservation:
    """Read one reparse-safe, root-confined Include graph and configured sources.

    The root parser remains conservative about effective Include precedence.
    Separately, the aggregate digest and source rows make every admitted file,
    configured local key authority, and unsupported command authority visible
    to the authenticated drift store without retaining paths or identities.
    """
    if not isinstance(privacy_key, bytes) or len(privacy_key) != 32:
        raise ValueError("SSH privacy key must contain exactly 32 bytes")
    if type(max_files) is not int or not 1 <= max_files <= MAX_CONFIG_GRAPH_FILES:
        raise ValueError("invalid SSH config graph file bound")
    if type(max_depth) is not int or not 0 <= max_depth <= MAX_CONFIG_GRAPH_DEPTH:
        raise ValueError("invalid SSH config graph depth bound")
    if type(max_total_bytes) is not int or not 1 <= max_total_bytes <= MAX_CONFIG_GRAPH_BYTES:
        raise ValueError("invalid SSH config graph byte bound")
    target = (platform or sys.platform).casefold()
    env = environ if environ is not None else os.environ
    root = Path(os.path.abspath(str(Path(root_path))))
    allowed_root = root.parent
    issues: list[str] = []
    sources: list[SSHConfiguredSourceEvidence] = []
    admitted: list[tuple[Path, bytes, ParsedSSHDConfig, os.stat_result]] = []
    seen: set[str] = set()
    total_bytes = 0

    def source_row(
        path: Path,
        kind: str,
        state: str,
        data: bytes | None = None,
        *,
        expected_windows_owner: str | None = None,
    ) -> None:
        custody = (
            _ssh_file_custody(
                path,
                target,
                expected_windows_owner=expected_windows_owner,
            )
            if state == "observed" else "unknown"
        )
        sources.append(SSHConfiguredSourceEvidence(
            source_token=_configured_source_token(
                privacy_key,
                kind=kind,
                identity=(os.path.normcase(str(path)), expected_windows_owner or "shared"),
            ),
            kind=kind,
            state=state,
            digest=hashlib.sha256(data).hexdigest() if data is not None else None,
            custody=custody,
        ))
        if custody == "unsafe":
            issues.append(f"ssh.{kind}.custody_unsafe")
        elif state == "observed" and custody == "unknown":
            issues.append(f"ssh.{kind}.custody_unknown")

    def include_matches(value: str, base: Path) -> tuple[Path, ...]:
        candidate = _static_ssh_path(value, base=base, environ=env)
        if candidate is None or not _lexically_within(allowed_root, candidate):
            issues.append("ssh.config.include_outside_allowed_root")
            sources.append(SSHConfiguredSourceEvidence(
                _configured_source_token(privacy_key, kind="include", identity=value),
                "include", "unsupported", None, "unknown",
            ))
            return ()
        if any(character in str(candidate.parent) for character in "*?["):
            issues.append("ssh.config.include_pattern_unsupported")
            return ()
        if any(character in candidate.name for character in "*?["):
            try:
                if path_has_link_or_reparse(candidate.parent):
                    raise OSError("unsafe include directory")
                matches: list[Path] = []
                for index, item in enumerate(candidate.parent.iterdir()):
                    if index >= MAX_CONFIG_DIRECTORY_ROWS:
                        issues.append("ssh.config.include_directory_bound_reached")
                        break
                    if fnmatch.fnmatchcase(item.name, candidate.name):
                        matches.append(item)
                        if len(matches) > max_files:
                            break
                rows = tuple(sorted(matches, key=lambda item: item.name.casefold()))
            except OSError:
                issues.append("ssh.config.include_unreadable_or_unsafe")
                return ()
            if len(rows) > max_files:
                issues.append("ssh.config.include_file_bound_reached")
                rows = rows[:max_files]
            if not rows:
                source_row(candidate, "include", "missing")
            return rows
        try:
            exists = os.path.lexists(candidate)
        except OSError:
            exists = False
        if not exists:
            source_row(candidate, "include", "missing")
            return ()
        return (candidate,)

    def visit(path: Path, depth: int, kind: str) -> None:
        nonlocal total_bytes
        if depth > max_depth:
            issues.append("ssh.config.include_depth_reached")
            return
        identity = os.path.normcase(os.path.abspath(str(path)))
        if identity in seen:
            issues.append("ssh.config.include_cycle_or_duplicate")
            return
        if len(seen) >= max_files:
            issues.append("ssh.config.include_file_bound_reached")
            return
        if not _lexically_within(allowed_root, path):
            issues.append("ssh.config.include_outside_allowed_root")
            return
        seen.add(identity)
        try:
            data = safe_read_bounded(path, max_bytes=min(MAX_CONFIG_BYTES, max_total_bytes))
            after = path.lstat()
            parsed = parse_sshd_config(data)
        except SSHConfigLimitError:
            source_row(path, kind, "unreadable")
            issues.append("ssh.config.bound_reached")
            return
        except (OSError, SSHSurfaceError):
            source_row(path, kind, "unreadable")
            issues.append("ssh.config.unreadable_or_unsafe")
            return
        if total_bytes + len(data) > max_total_bytes:
            source_row(path, kind, "unreadable")
            issues.append("ssh.config.include_byte_bound_reached")
            return
        total_bytes += len(data)
        source_row(path, kind, "observed", data)
        admitted.append((path, data, parsed, after))
        for directive in parsed.directives:
            if directive.keyword != "include":
                continue
            if len(directive.arguments) > MAX_CONFIG_GRAPH_FILES:
                issues.append("ssh.config.include_argument_bound_reached")
            for value in directive.arguments[:MAX_CONFIG_GRAPH_FILES]:
                for match in include_matches(value, path.parent):
                    visit(match, depth + 1, "include")

    visit(root, 0, "config")
    if not admitted or admitted[0][0] != root:
        raise SSHSurfaceError("sshd_config root was not safely admitted")

    aggregate_rows = []
    for path, data, _parsed, info in admitted:
        relative = os.path.normcase(str(path.relative_to(allowed_root)))
        aggregate_rows.append({
            "path": relative,
            "device": int(getattr(info, "st_dev", 0)),
            "inode": int(getattr(info, "st_ino", 0)),
            "size": len(data),
            "digest": hashlib.sha256(data).hexdigest(),
        })
    aggregate_digest = hashlib.sha256(_canonical_json(aggregate_rows)).hexdigest()

    configured_candidates: list[AuthorizedKeyCandidate] = []
    accounts, account_discovery_complete = _normalized_local_accounts(
        target, env, local_accounts
    )
    root_allow_users = admitted[0][2].option("AllowUsers")
    if root_allow_users.state == "explicit":
        admitted_names: set[str] = set()
        admission_exact = True
        for raw_name in root_allow_users.arguments:
            local_name = raw_name.split("@", 1)[0]
            if (
                not re.fullmatch(r"[A-Za-z0-9_.-]{1,256}", local_name)
                or any(marker in raw_name for marker in ("*", "?", "[", "]", "!"))
            ):
                admission_exact = False
                break
            admitted_names.add(local_name.casefold())
        if admission_exact and admitted_names:
            selected = tuple(
                account for account in accounts
                if account.username.casefold() in admitted_names
            )
            if {item.username.casefold() for item in selected} != admitted_names:
                account_discovery_complete = False
            accounts = selected
        else:
            account_discovery_complete = False
    elif root_allow_users.state == "ambiguous_include":
        account_discovery_complete = False
    if admitted[0][2].option("AllowGroups").state != "absent":
        # Group membership is deliberately not guessed from profile names.
        account_discovery_complete = False

    configured_values = 0
    configured_bound = False

    def reserve_configured_source() -> bool:
        nonlocal configured_values, configured_bound
        configured_values += 1
        if configured_values <= MAX_AUTH_FILES:
            return True
        if not configured_bound:
            issues.append("ssh.configured_sources.bound_reached")
        configured_bound = True
        return False

    def marker_source(
        *, kind: str, keyword: str, identity: object, state: str, custody: str = "unknown"
    ) -> None:
        sources.append(SSHConfiguredSourceEvidence(
            _configured_source_token(
                privacy_key, kind=kind, identity=(keyword, identity, state)
            ),
            kind,
            state,
            None,
            custody,
        ))

    def observe_configured_path(
        *,
        configured_path: Path,
        kind: str,
        owner: str,
        expected_windows_owner: str | None,
        candidate_root: Path,
    ) -> None:
        try:
            exists = os.path.lexists(configured_path)
        except OSError:
            exists = False
        if not exists:
            source_row(
                configured_path,
                kind,
                "missing",
                expected_windows_owner=expected_windows_owner,
            )
        else:
            try:
                file_data = safe_read_bounded(
                    configured_path, max_bytes=MAX_AUTH_FILE_BYTES
                )
            except OSError:
                source_row(
                    configured_path,
                    kind,
                    "unreadable",
                    expected_windows_owner=expected_windows_owner,
                )
                issues.append(f"ssh.{kind}.unreadable_or_unsafe")
            else:
                source_row(
                    configured_path,
                    kind,
                    "observed",
                    file_data,
                    expected_windows_owner=expected_windows_owner,
                )
        if kind in {"authorized_keys", "trusted_ca"}:
            configured_candidates.append(AuthorizedKeyCandidate(
                owner=owner,
                root=candidate_root,
                path=configured_path,
                expected_windows_owner=expected_windows_owner,
            ))

    for config_path, _data, parsed_file, _info in admitted:
        for directive in parsed_file.directives:
            keyword = directive.keyword
            if keyword not in {
                "authorizedkeyscommand", "authorizedprincipalscommand",
                "authorizedkeysfile", "trustedusercakeys", "authorizedprincipalsfile",
            }:
                continue
            if keyword in {"authorizedkeyscommand", "authorizedprincipalscommand"}:
                if not reserve_configured_source():
                    break
                kind = "key_command" if keyword == "authorizedkeyscommand" else "principals_command"
                digest = hashlib.sha256(
                    _canonical_json([keyword, *directive.arguments])
                ).hexdigest()
                sources.append(SSHConfiguredSourceEvidence(
                    _configured_source_token(
                        privacy_key, kind=kind, identity=(keyword, directive.arguments)
                    ),
                    kind,
                    "unsupported",
                    digest,
                    "not-applicable",
                ))
                issues.append(f"ssh.{kind}.unsupported")
                continue
            kind = {
                "authorizedkeysfile": "authorized_keys",
                "trustedusercakeys": "trusted_ca",
                "authorizedprincipalsfile": "principals",
            }[keyword]
            for value in directive.arguments[:MAX_AUTH_FILES]:
                if value.casefold() == "none":
                    if not reserve_configured_source():
                        break
                    marker_source(
                        kind=kind,
                        keyword=keyword,
                        identity="disabled",
                        state="not-applicable",
                        custody="not-applicable",
                    )
                    continue

                if keyword == "trustedusercakeys":
                    if not reserve_configured_source():
                        break
                    configured_path = _static_ssh_path(
                        value, base=config_path.parent, environ=env
                    )
                    if configured_path is None:
                        marker_source(
                            kind=kind, keyword=keyword, identity=value, state="unresolved"
                        )
                        issues.append(f"ssh.{kind}.dynamic_source_unresolved")
                        continue
                    observe_configured_path(
                        configured_path=configured_path,
                        kind=kind,
                        owner=f"configured-{kind}",
                        expected_windows_owner=None,
                        candidate_root=configured_path.parent,
                    )
                    continue

                # Absolute, account-independent values remain shared sources.
                static_state, static_path, _relative = _per_user_source_path(
                    value, account=None, environ=env
                )
                if static_state == "resolved" and static_path is not None:
                    if not reserve_configured_source():
                        break
                    observe_configured_path(
                        configured_path=static_path,
                        kind=kind,
                        owner=f"configured-{kind}",
                        expected_windows_owner=None,
                        candidate_root=static_path.parent,
                    )
                    if directive.scope != "global":
                        if reserve_configured_source():
                            marker_source(
                                kind=kind,
                                keyword=keyword,
                                identity=(value, "conditional"),
                                state="unresolved",
                            )
                            issues.append(
                                f"ssh.{kind}.conditional_application_unresolved"
                            )
                    continue

                if directive.scope != "global":
                    if not reserve_configured_source():
                        break
                    marker_source(
                        kind=kind,
                        keyword=keyword,
                        identity=(value, "conditional"),
                        state="unresolved",
                    )
                    issues.append(f"ssh.{kind}.conditional_application_unresolved")
                    continue

                if not accounts:
                    if not reserve_configured_source():
                        break
                    marker_source(
                        kind=kind,
                        keyword=keyword,
                        identity=(value, "accounts-unavailable"),
                        state="incomplete",
                    )
                    issues.append(f"ssh.{kind}.account_expansion_incomplete")
                    continue
                for account in accounts:
                    if not reserve_configured_source():
                        break
                    state, configured_path, relative_home = _per_user_source_path(
                        value, account=account, environ=env
                    )
                    if state != "resolved" or configured_path is None:
                        marker_source(
                            kind=kind,
                            keyword=keyword,
                            identity=(value, account.username),
                            state="unresolved",
                        )
                        issues.append(f"ssh.{kind}.dynamic_source_unresolved")
                        continue
                    observe_configured_path(
                        configured_path=configured_path,
                        kind=kind,
                        owner=account.username,
                        expected_windows_owner=(
                            account.username
                            if target.startswith("win") or target == "windows"
                            else None
                        ),
                        candidate_root=(account.home if relative_home else configured_path.parent),
                    )
                if not account_discovery_complete and not configured_bound:
                    if reserve_configured_source():
                        marker_source(
                            kind=kind,
                            keyword=keyword,
                            identity=(value, "account-set-incomplete"),
                            state="incomplete",
                        )
                        issues.append(f"ssh.{kind}.account_expansion_incomplete")
            if configured_bound:
                break
        if configured_bound:
            break

    source_unique = {item.source_token: item for item in sources}
    candidate_unique = {
        os.path.normcase(os.path.abspath(str(item.path))): item
        for item in configured_candidates
    }
    root_parsed = replace(admitted[0][2], digest=aggregate_digest)
    return SSHConfigObservation(
        parsed=root_parsed,
        aggregate_digest=aggregate_digest,
        sources=tuple(sorted(
            source_unique.values(), key=lambda item: item.source_token
        ))[:MAX_BASELINE_ITEMS],
        authorized_key_candidates=tuple(candidate_unique.values())[:MAX_AUTH_FILES],
        issues=tuple(dict.fromkeys(issues)),
        files_observed=len(admitted),
    )


def default_authorized_key_candidates(
    platform: str | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    max_users: int = MAX_AUTH_USERS,
) -> tuple[AuthorizedKeyCandidate, ...]:
    """Enumerate only conventional local authorized-key files, with hard caps."""
    if type(max_users) is not int or not 1 <= max_users <= MAX_AUTH_USERS:
        raise ValueError("invalid authorized-key user bound")
    target = (platform or sys.platform).casefold()
    env = environ if environ is not None else os.environ
    candidates: list[AuthorizedKeyCandidate] = []
    if target.startswith("win") or target == "windows":
        homes: list[tuple[str, Path]] = []
        profile = env.get("USERPROFILE")
        if profile:
            homes.append((env.get("USERNAME", "current-user"), Path(profile)))
        users_root = Path(env.get("SystemDrive", "C:")) / "Users"
        try:
            for item in sorted(users_root.iterdir(), key=lambda value: value.name.casefold()):
                if len(homes) >= max_users:
                    break
                if item.is_dir() and not path_has_link_or_reparse(item):
                    homes.append((item.name, item))
        except OSError:
            pass
        seen_homes: set[str] = set()
        for owner, home in homes:
            identity = os.path.normcase(os.path.abspath(str(home)))
            if identity in seen_homes or len(seen_homes) >= max_users:
                continue
            seen_homes.add(identity)
            candidates.append(AuthorizedKeyCandidate(
                owner=owner,
                root=home,
                path=home / ".ssh" / "authorized_keys",
                expected_windows_owner=owner,
            ))
        program_ssh = Path(env.get("ProgramData") or r"C:\ProgramData") / "ssh"
        candidates.append(AuthorizedKeyCandidate(
            owner="administrators",
            root=program_ssh,
            path=program_ssh / "administrators_authorized_keys",
        ))
        return tuple(candidates[:MAX_AUTH_FILES])

    try:
        import pwd
        users = sorted(pwd.getpwall(), key=lambda item: int(item.pw_uid))[:max_users]
    except (ImportError, OSError):
        users = []
    for item in users:
        try:
            home = Path(item.pw_dir)
            if not home.is_absolute():
                continue
            for filename in ("authorized_keys", "authorized_keys2"):
                candidates.append(AuthorizedKeyCandidate(
                    owner=str(item.pw_name),
                    root=home,
                    path=home / ".ssh" / filename,
                    expected_uid=int(item.pw_uid),
                ))
        except (AttributeError, TypeError, ValueError):
            continue
    return tuple(candidates[:MAX_AUTH_FILES])


_KEY_TYPE_RE = re.compile(
    r"^(?:"
    r"ssh-(?:rsa|dss|ed25519)(?:-cert-v01@openssh\.com)?|"
    r"ecdsa-sha2-nistp(?:256|384|521)(?:-cert-v01@openssh\.com)?|"
    r"sk-(?:ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com"
    r")$",
    re.IGNORECASE,
)


def _key_blob_matches_algorithm(blob: bytes, algorithm: str) -> bool:
    if len(blob) < 5:
        return False
    size = int.from_bytes(blob[:4], "big", signed=False)
    if size < 1 or size > 256 or 4 + size > len(blob):
        return False
    try:
        embedded = blob[4:4 + size].decode("ascii", "strict")
    except UnicodeDecodeError:
        return False
    return hmac.compare_digest(embedded.casefold(), algorithm.casefold())


def _parse_authorized_key_line(
    line: str,
    *,
    privacy_key: bytes,
    owner_token: str,
    path_token: str,
) -> AuthorizedKeyEntry | None:
    if not line.strip() or line.lstrip().startswith("#"):
        return None
    if "PRIVATE KEY" in line.upper() or line.lstrip().startswith("-----BEGIN"):
        raise SSHSurfaceError("private-key-material")
    tokens = _lex_openssh_line(line)
    algorithm_index = next(
        (index for index, token in enumerate(tokens) if _KEY_TYPE_RE.fullmatch(token)),
        None,
    )
    if algorithm_index is None or algorithm_index + 1 >= len(tokens):
        raise SSHSurfaceError("invalid-public-key-line")
    algorithm = tokens[algorithm_index].casefold()
    encoded = tokens[algorithm_index + 1]
    if not 8 <= len(encoded) <= ((MAX_KEY_BLOB_BYTES + 2) // 3) * 4 + 4:
        raise SSHSurfaceError("public-key-blob-bound")
    try:
        blob = base64.b64decode(encoded.encode("ascii"), validate=True)
    except (ValueError, UnicodeError, binascii.Error) as exc:
        raise SSHSurfaceError("invalid-public-key-blob") from exc
    if len(blob) > MAX_KEY_BLOB_BYTES or not _key_blob_matches_algorithm(blob, algorithm):
        raise SSHSurfaceError("public-key-algorithm-mismatch")
    fingerprint_b64 = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
    fingerprint = f"SHA256:{fingerprint_b64}"
    # Comments are intentionally excluded. Options are authenticated without
    # being retained, so a forced-command or forwarding restriction change is
    # visible as entry drift but its possibly sensitive text is never stored.
    option_text = " ".join(tokens[:algorithm_index])
    canonical = (
        option_text.encode("utf-8", "surrogatepass") + b"\x00"
        + algorithm.encode("ascii") + b"\x00" + blob
    )
    entry_digest = _purpose_token(
        privacy_key, b"authorized-key-entry", canonical, "entry"
    )
    options = option_text.casefold()
    restrictions = tuple(
        label for needle, label in (
            ("restrict", "restrict"),
            ("no-port-forwarding", "no-port-forwarding"),
            ("no-agent-forwarding", "no-agent-forwarding"),
            ("no-x11-forwarding", "no-x11-forwarding"),
            ("no-pty", "no-pty"),
            ("from=", "source-constrained"),
            ("command=", "forced-command"),
        ) if needle in options
    )
    return AuthorizedKeyEntry(
        fingerprint=fingerprint,
        entry_digest=entry_digest,
        algorithm=algorithm,
        owner_token=owner_token,
        path_token=path_token,
        restrictions=restrictions,
    )


def _lexically_within(root: Path, path: Path) -> bool:
    try:
        root_text = os.path.normcase(os.path.abspath(str(root)))
        path_text = os.path.normcase(os.path.abspath(str(path)))
        return os.path.commonpath((root_text, path_text)) == root_text
    except (OSError, ValueError):
        return False


def _unix_mode_issues(
    candidate: AuthorizedKeyCandidate,
    *,
    path_token: str,
) -> list[SSHInventoryIssue]:
    issues: list[SSHInventoryIssue] = []
    for code, path in (
        ("ssh.keys.home_mode_unsafe", candidate.root),
        ("ssh.keys.directory_mode_unsafe", candidate.path.parent),
        ("ssh.keys.file_mode_unsafe", candidate.path),
    ):
        try:
            info = path.lstat()
        except OSError:
            continue
        if stat.S_IMODE(info.st_mode) & 0o022:
            issues.append(SSHInventoryIssue(code, "high", path_token))
        if candidate.expected_uid is not None and int(info.st_uid) not in {
            int(candidate.expected_uid), 0
        }:
            issues.append(SSHInventoryIssue("ssh.keys.owner_mismatch", "high", path_token))
    return issues


def inventory_authorized_keys(
    candidates: Iterable[AuthorizedKeyCandidate],
    *,
    privacy_key: bytes,
    platform: str | None = None,
    windows_acl_verifier: Callable[[Path], bool | None] | None = None,
    max_users: int = MAX_AUTH_USERS,
    max_files: int = MAX_AUTH_FILES,
    max_lines: int = MAX_AUTH_LINES,
) -> AuthorizedKeyInventory:
    """Inventory public-key fingerprints only; never return key text or comments."""
    if not isinstance(privacy_key, bytes) or len(privacy_key) != 32:
        raise ValueError("SSH privacy key must contain exactly 32 bytes")
    if (
        type(max_users) is not int
        or type(max_files) is not int
        or not 1 <= max_users <= MAX_AUTH_USERS
        or not 1 <= max_files <= MAX_AUTH_FILES
    ):
        raise ValueError("invalid authorized-key inventory bounds")
    if type(max_lines) is not int or not 1 <= max_lines <= MAX_AUTH_LINES:
        raise ValueError("invalid authorized-key line bound")
    target = (platform or sys.platform).casefold()
    windows = target.startswith("win") or target == "windows"
    entries: list[AuthorizedKeyEntry] = []
    issues: list[SSHInventoryIssue] = []
    owners: set[str] = set()
    files_examined = 0
    lines_examined = 0
    dropped = 0
    seen_candidates: set[str] = set()
    for candidate_index, candidate in enumerate(candidates):
        if candidate_index >= max_files:
            dropped += 1
            break
        owner_token = _purpose_token(privacy_key, b"authorized-key-owner", candidate.owner, "owner")
        path_token = _purpose_token(
            privacy_key, b"authorized-key-path", os.path.normcase(str(candidate.path)), "path"
        )
        if owner_token not in owners and len(owners) >= max_users:
            dropped += 1
            continue
        owners.add(owner_token)
        identity = os.path.normcase(os.path.abspath(str(candidate.path)))
        if identity in seen_candidates:
            continue
        seen_candidates.add(identity)
        if not candidate.root.is_absolute() or not candidate.path.is_absolute() or not _lexically_within(
            candidate.root, candidate.path
        ):
            issues.append(SSHInventoryIssue("ssh.keys.path_escape_rejected", "high", path_token))
            continue
        try:
            exists = os.path.lexists(candidate.path)
        except OSError:
            exists = False
        if not exists:
            continue
        files_examined += 1
        if path_has_link_or_reparse(candidate.path):
            issues.append(SSHInventoryIssue("ssh.keys.link_reparse_rejected", "high", path_token))
            continue
        if windows:
            acl_state: bool | None = None
            if windows_acl_verifier is not None:
                try:
                    if windows_acl_verifier is verify_windows_ssh_acl:
                        acl_state = verify_windows_ssh_acl(
                            candidate.path,
                            expected_owner=candidate.expected_windows_owner,
                        )
                    else:
                        acl_state = windows_acl_verifier(candidate.path)
                except Exception:
                    acl_state = None
            if acl_state is True:
                pass
            elif acl_state is False:
                issues.append(SSHInventoryIssue("ssh.keys.windows_acl_unsafe", "high", path_token))
            else:
                issues.append(SSHInventoryIssue("ssh.keys.windows_acl_unknown", "medium", path_token))
        else:
            issues.extend(_unix_mode_issues(candidate, path_token=path_token))
        try:
            data = safe_read_bounded(candidate.path, max_bytes=MAX_AUTH_FILE_BYTES)
            text = data.decode("utf-8", "strict")
        except (OSError, UnicodeError):
            issues.append(SSHInventoryIssue("ssh.keys.file_unreadable", "high", path_token))
            continue
        for line in text.splitlines():
            if lines_examined >= max_lines:
                dropped += 1
                break
            lines_examined += 1
            if len(line) > MAX_CONFIG_LINE_CHARS:
                issues.append(SSHInventoryIssue("ssh.keys.line_oversized", "medium", path_token))
                dropped += 1
                continue
            try:
                entry = _parse_authorized_key_line(
                    line,
                    privacy_key=privacy_key,
                    owner_token=owner_token,
                    path_token=path_token,
                )
            except SSHSurfaceError as exc:
                code = (
                    "ssh.keys.private_material_ignored"
                    if str(exc) == "private-key-material"
                    else "ssh.keys.invalid_line"
                )
                issues.append(SSHInventoryIssue(code, "high" if "private" in code else "low", path_token))
                dropped += 1
                continue
            if entry is not None:
                entries.append(entry)
        if lines_examined >= max_lines:
            break
    unique: dict[tuple[str, str, str, str], AuthorizedKeyEntry] = {}
    for entry in entries:
        key = (entry.owner_token, entry.path_token, entry.fingerprint, entry.entry_digest)
        unique.setdefault(key, entry)
    sorted_entries = tuple(sorted(
        unique.values(),
        key=lambda item: (item.owner_token, item.path_token, item.fingerprint, item.entry_digest),
    ))
    if len(sorted_entries) > MAX_BASELINE_ITEMS:
        dropped += len(sorted_entries) - MAX_BASELINE_ITEMS
        sorted_entries = sorted_entries[:MAX_BASELINE_ITEMS]
    return AuthorizedKeyInventory(
        entries=sorted_entries,
        issues=tuple(issues[:MAX_BASELINE_ITEMS]),
        users_examined=len(owners),
        files_examined=files_examined,
        lines_examined=lines_examined,
        dropped=dropped,
    )


def _normalized_executable(value: object) -> str:
    text = str(value or "").strip().replace("\\", "/")
    # Service ImagePath may include arguments. Only parse a conservative quoted
    # or first-token executable; never execute or expand it.
    if text.startswith('"') and '"' in text[1:]:
        text = text[1:text.find('"', 1)]
    else:
        lowered = text.casefold()
        for suffix in ("/sshd.exe", "/sshd"):
            position = lowered.find(suffix)
            if position < 0:
                continue
            end = position + len(suffix)
            if end == len(text) or text[end].isspace():
                text = text[:end]
                break
        else:
            text = text.split(" ", 1)[0]
    text = text.strip().strip('"')
    return os.path.normcase(os.path.normpath(text)).replace("\\", "/")[:2048]


def _ssh_binary_name(executable: str) -> bool:
    return executable.rsplit("/", 1)[-1].casefold() in {"sshd", "sshd.exe"}


def _ssh_binary_role(executable: str, name: str = "") -> str:
    binary = executable.rsplit("/", 1)[-1].casefold()
    process_name = str(name or "").casefold()
    if binary in {"sshd", "sshd.exe"} or process_name in {"sshd", "sshd.exe"}:
        return "server"
    if binary in {"ssh", "ssh.exe"} or process_name in {"ssh", "ssh.exe"}:
        return "client"
    return ""


def _canonical_sshd_binaries(platform: str, environ: Mapping[str, str]) -> set[str]:
    if platform.startswith("win") or platform == "windows":
        root = str(Path(environ.get("SystemRoot") or r"C:\Windows") / "System32" / "OpenSSH" / "sshd.exe")
        return {_normalized_executable(root)}
    return {
        _normalized_executable("/usr/sbin/sshd"),
        _normalized_executable("/usr/local/sbin/sshd"),
    }


def _canonical_ssh_binaries(platform: str, environ: Mapping[str, str], role: str) -> set[str]:
    if role == "server":
        return _canonical_sshd_binaries(platform, environ)
    if platform.startswith("win") or platform == "windows":
        root = Path(environ.get("SystemRoot") or r"C:\Windows") / "System32" / "OpenSSH" / "ssh.exe"
        return {_normalized_executable(root)}
    return {_normalized_executable("/usr/bin/ssh"), _normalized_executable("/usr/local/bin/ssh")}


_SSH_FORWARDING_OPTION_LABELS = frozenset({
    "local-forward", "reverse-forward", "dynamic-forward", "tunnel-device",
    "stdio-forward", "proxy-jump",
})
_SSH_OPTION_COMPLETENESS_LABELS = frozenset({
    "client-config-uninspected", "proxy-command-uninspected", "option-parse-incomplete",
})


def _normalized_o_option(value: str) -> tuple[str | None, bool]:
    """Classify one bounded ``-o`` operand without retaining its value."""
    option = value.strip()
    if not option or len(option) > 2048 or "\x00" in option:
        return None, False
    if "=" in option:
        name, configured_value = option.split("=", 1)
    else:
        pieces = option.split(None, 1)
        if len(pieces) != 2:
            return None, False
        name, configured_value = pieces
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,63}", name):
        return None, False
    configured_value = configured_value.strip()
    normalized = name.casefold()
    labels = {
        "localforward": "local-forward",
        "remoteforward": "reverse-forward",
        "dynamicforward": "dynamic-forward",
        "proxyjump": "proxy-jump",
        "proxycommand": "proxy-command-uninspected",
    }
    if normalized in labels:
        return (labels[normalized], True) if configured_value else (None, False)
    if normalized == "tunnel":
        if configured_value.casefold() in {"no", "false", "off", "0"}:
            return None, True
        return ("tunnel-device", True) if configured_value else (None, False)
    return None, True


def _normalized_forwarding_flags(value: object) -> tuple[str, ...]:
    """Parse a strict bounded subset of the OpenSSH client option grammar."""
    if not isinstance(value, (list, tuple)):
        return ("option-parse-incomplete",)
    flags: set[str] = set()
    argv: list[str] = []
    total = 0
    if len(value) > 64:
        flags.add("option-parse-incomplete")
    for raw in value[:64]:
        try:
            argument = str(raw or "")
        except Exception:
            flags.add("option-parse-incomplete")
            break
        if len(argument) > 2048 or "\x00" in argument:
            flags.add("option-parse-incomplete")
            break
        total += len(argument)
        if total > 8192:
            flags.add("option-parse-incomplete")
            break
        argv.append(argument)
    if not argv:
        return tuple(sorted(flags))

    # psutil returns the executable as argv[0].  Do not interpret a destination
    # or a raw value after the first non-option as another option.
    index = 1 if not argv[0].startswith("-") else 0
    no_argument = set("46AaCfGgKkMNnqstTVvXxYy")
    argument_options = set("BbcDEeFIiJLlmOoPpQRSWw")
    forwarding = {
        "L": "local-forward",
        "R": "reverse-forward",
        "D": "dynamic-forward",
        "w": "tunnel-device",
        "W": "stdio-forward",
        "J": "proxy-jump",
    }
    while index < len(argv):
        argument = argv[index]
        if argument == "--":
            break
        if not argument.startswith("-") or argument == "-":
            break
        if argument.startswith("--"):
            flags.add("option-parse-incomplete")
            break
        cluster = argument[1:]
        position = 0
        while position < len(cluster):
            option = cluster[position]
            if option in no_argument:
                position += 1
                continue
            if option not in argument_options:
                flags.add("option-parse-incomplete")
                position = len(cluster)
                continue
            operand = cluster[position + 1:]
            if not operand:
                index += 1
                if index >= len(argv):
                    flags.add("option-parse-incomplete")
                    break
                operand = argv[index]
            if not operand:
                flags.add("option-parse-incomplete")
                break
            if option in forwarding:
                flags.add(forwarding[option])
            elif option == "F" and operand.casefold() != "none":
                flags.add("client-config-uninspected")
            elif option == "o":
                label, valid = _normalized_o_option(operand)
                if not valid:
                    flags.add("option-parse-incomplete")
                elif label is not None:
                    flags.add(label)
            # An argument-taking short option consumes the rest of its cluster.
            break
        index += 1
    return tuple(sorted(flags))


def _bounded_runtime_text(value: object, allowed: set[str], default: str) -> str:
    normalized = str(value or "").strip().casefold()
    return normalized if normalized in allowed else default


def _address_scope(address: str) -> str:
    normalized = str(address or "").strip().strip("[]")
    if normalized in {"", "*", "0.0.0.0", "::", "::0"}:
        return "wildcard"
    try:
        parsed = ipaddress.ip_address(normalized.split("%", 1)[0])
    except ValueError:
        return "unknown"
    if parsed.is_loopback:
        return "loopback"
    if parsed.is_link_local:
        return "link-local"
    return "interface"


def normalize_runtime_evidence(
    services: Iterable[Mapping[str, object]],
    listeners: Iterable[Mapping[str, object]],
    *,
    privacy_key: bytes,
    platform: str | None = None,
    environ: Mapping[str, str] | None = None,
    processes: Iterable[Mapping[str, object]] = (),
    connections: Iterable[Mapping[str, object]] = (),
) -> SSHRuntimeEvidence:
    """Normalize local runtime rows without retaining PIDs, paths, or endpoints."""
    if not isinstance(privacy_key, bytes) or len(privacy_key) != 32:
        raise ValueError("SSH privacy key must contain exactly 32 bytes")
    target = (platform or sys.platform).casefold()
    env = environ if environ is not None else os.environ
    canonical = _canonical_sshd_binaries(target, env)
    service_rows: list[SSHServiceEvidence] = []
    service_by_identity: dict[str, str] = {}
    issues: list[str] = []
    for index, raw in enumerate(services):
        if index >= MAX_RUNTIME_ROWS:
            issues.append("ssh.runtime.service_bound_reached")
            break
        if not isinstance(raw, Mapping):
            continue
        name = str(raw.get("name") or "")[:512]
        display = str(raw.get("display_name") or "")[:512]
        executable = _normalized_executable(raw.get("executable"))
        identity = str(raw.get("identity") or name or executable)[:1024]
        looks_ssh = (
            _ssh_binary_name(executable)
            or name.casefold() in {"sshd", "openssh", "opensshd"}
            or "openssh ssh server" in display.casefold()
        )
        if not looks_ssh:
            continue
        service_token = _purpose_token(
            privacy_key, b"ssh-service", f"{identity}\x00{executable}", "service"
        )
        executable_token = _purpose_token(
            privacy_key, b"ssh-executable", executable or "unknown", "binary"
        )
        conventional_name = name.casefold() in {"sshd", "openssh", "opensshd", "process:sshd"}
        evidence = SSHServiceEvidence(
            service_token=service_token,
            executable_token=executable_token,
            state=_bounded_runtime_text(
                raw.get("state"), {"running", "stopped", "paused", "starting", "unknown"}, "unknown"
            ),
            start_mode=_bounded_runtime_text(
                raw.get("start_mode"), {"auto", "automatic", "manual", "disabled", "boot", "unknown"}, "unknown"
            ),
            renamed=_ssh_binary_name(executable) and not conventional_name,
            nonstandard_binary=bool(executable) and executable not in canonical,
        )
        service_rows.append(evidence)
        service_by_identity[identity] = service_token

    listener_rows: list[SSHListenerEvidence] = []
    service_tokens = {item.service_token for item in service_rows}
    for index, raw in enumerate(listeners):
        if index >= MAX_RUNTIME_ROWS:
            issues.append("ssh.runtime.listener_bound_reached")
            break
        if not isinstance(raw, Mapping):
            continue
        try:
            port = int(raw.get("port", -1))
        except (TypeError, ValueError):
            continue
        if not 1 <= port <= 65535:
            continue
        identity = str(raw.get("service_identity") or "")[:1024]
        direct_token = str(raw.get("service_token") or "")
        service_token = service_by_identity.get(identity, direct_token)
        # A port belongs to this evidence set only when a recognized SSH
        # service/process supplied it. Port 22 alone is not proof of SSH.
        if service_token not in service_tokens:
            continue
        address = str(raw.get("address") or "")[:1024]
        bind_token = _purpose_token(privacy_key, b"ssh-listen-address", address, "bind")
        scope = _address_scope(address)
        listener_token = _purpose_token(
            privacy_key,
            b"ssh-listener",
            f"{service_token}\x00{bind_token}\x00{port}\x00{scope}",
            "listener",
        )
        listener_rows.append(SSHListenerEvidence(
            listener_token=listener_token,
            bind_token=bind_token,
            port=port,
            scope=scope,
            service_token=service_token,
        ))
    process_rows: list[SSHProcessEvidence] = []
    process_by_identity: dict[str, SSHProcessEvidence] = {}
    for index, raw in enumerate(processes):
        if index >= MAX_RUNTIME_ROWS:
            issues.append("ssh.runtime.process_bound_reached")
            break
        if not isinstance(raw, Mapping):
            continue
        executable = _normalized_executable(raw.get("executable"))
        name = str(raw.get("name") or "")[:256]
        role = _ssh_binary_role(executable, name)
        identity = str(raw.get("identity") or "")[:1024]
        if not role or not identity:
            continue
        process_token = _purpose_token(
            privacy_key,
            b"ssh-process-birth",
            f"{identity}\x00{executable}",
            "process",
        )
        forwarding_flags = (
            _normalized_forwarding_flags(raw.get("cmdline"))
            if role == "client" else ()
        )
        if "client-config-uninspected" in forwarding_flags:
            issues.append("ssh.runtime.client_config_uninspected")
        if "proxy-command-uninspected" in forwarding_flags:
            issues.append("ssh.runtime.proxy_command_uninspected")
        if "option-parse-incomplete" in forwarding_flags:
            issues.append("ssh.runtime.client_option_parse_incomplete")
        evidence = SSHProcessEvidence(
            process_token=process_token,
            executable_token=_purpose_token(
                privacy_key, b"ssh-executable", executable or "unknown", "binary"
            ),
            role=role,
            nonstandard_binary=(
                not executable
                or executable not in _canonical_ssh_binaries(target, env, role)
            ),
            forwarding_flags=forwarding_flags,
        )
        process_rows.append(evidence)
        process_by_identity[identity] = evidence

    connection_rows: list[SSHConnectionEvidence] = []
    allowed_states = {
        "listen", "established", "syn_sent", "syn_recv", "close_wait", "time_wait", "unknown"
    }
    for index, raw in enumerate(connections):
        if index >= MAX_RUNTIME_ROWS:
            issues.append("ssh.runtime.connection_bound_reached")
            break
        if not isinstance(raw, Mapping):
            continue
        process = process_by_identity.get(str(raw.get("process_identity") or "")[:1024])
        if process is None:
            continue
        local = str(raw.get("local") or "")[:1024]
        remote = str(raw.get("remote") or "")[:1024]
        state = str(raw.get("state") or "unknown").strip().casefold().replace("-", "_")
        state = state if state in allowed_states else "unknown"
        direction = "listener" if state == "listen" else (
            "outbound" if process.role == "client" else "inbound"
        )
        local_token = _purpose_token(
            privacy_key, b"ssh-local-endpoint", local or "unavailable", "endpoint"
        )
        remote_token = _purpose_token(
            privacy_key, b"ssh-remote-endpoint", remote or "unavailable", "endpoint"
        )
        connection_rows.append(SSHConnectionEvidence(
            connection_token=_purpose_token(
                privacy_key,
                b"ssh-connection",
                f"{process.process_token}\x00{local_token}\x00{remote_token}\x00{state}",
                "connection",
            ),
            local_token=local_token,
            remote_token=remote_token,
            state=state,
            direction=direction,
            process_token=process.process_token,
        ))
    services_unique = {item.service_token: item for item in service_rows}
    listeners_unique = {item.listener_token: item for item in listener_rows}
    processes_unique = {item.process_token: item for item in process_rows}
    connections_unique = {item.connection_token: item for item in connection_rows}
    return SSHRuntimeEvidence(
        services=tuple(sorted(services_unique.values(), key=lambda item: item.service_token)),
        listeners=tuple(sorted(listeners_unique.values(), key=lambda item: item.listener_token)),
        issues=tuple(dict.fromkeys(issues)),
        processes=tuple(sorted(processes_unique.values(), key=lambda item: item.process_token)),
        connections=tuple(sorted(connections_unique.values(), key=lambda item: item.connection_token)),
    )


def collect_local_ssh_runtime(
    *,
    privacy_key: bytes,
    platform: str | None = None,
    environ: Mapping[str, str] | None = None,
) -> SSHRuntimeEvidence:
    """Inspect local process/service tables only; make no network connection."""
    target = (platform or sys.platform).casefold()
    raw_services: list[dict[str, object]] = []
    raw_listeners: list[dict[str, object]] = []
    raw_processes: list[dict[str, object]] = []
    raw_connections: list[dict[str, object]] = []
    issues: list[str] = []
    pid_identity: dict[int, str] = {}
    try:
        import psutil
    except ImportError:
        return SSHRuntimeEvidence((), (), ("ssh.runtime.psutil_unavailable",))

    if target.startswith("win") or target == "windows":
        try:
            for index, service in enumerate(psutil.win_service_iter()):
                if index >= 8192:
                    issues.append("ssh.runtime.service_bound_reached")
                    break
                try:
                    value = service.as_dict()
                except Exception:
                    continue
                raw_services.append({
                    "name": value.get("name"),
                    "display_name": value.get("display_name"),
                    "executable": value.get("binpath"),
                    "state": value.get("status"),
                    "start_mode": value.get("start_type"),
                    "identity": value.get("name"),
                })
                try:
                    if str(value.get("status")).casefold() == "running":
                        pid = int(service.pid())
                        pid_identity[pid] = str(value.get("name") or "")
                except Exception:
                    pass
        except (AttributeError, OSError, RuntimeError):
            issues.append("ssh.runtime.windows_service_inventory_unavailable")
    try:
        for index, process in enumerate(
            psutil.process_iter(["pid", "name", "exe", "create_time"])
        ):
            if index >= 8192:
                issues.append("ssh.runtime.process_bound_reached")
                break
            ssh_candidate = False
            try:
                info = process.info
                executable = str(info.get("exe") or "")
                name = str(info.get("name") or "")
                normalized_executable = _normalized_executable(executable)
                role = _ssh_binary_role(normalized_executable, name)
                if not role:
                    continue
                ssh_candidate = True
                if not executable:
                    issues.append("ssh.runtime.process_metadata_partial")
                pid = int(info["pid"])
                created = float(info.get("create_time"))
                if not math.isfinite(created) or created <= 0:
                    raise ValueError("invalid process birth")
                process_identity = f"pid:{pid}:birth:{created:.6f}"
                command_line = None
                if role == "client":
                    try:
                        command_line = process.cmdline()
                    except Exception:
                        # psutil's eager ``as_dict`` path represented denied or
                        # raced command-line reads as unavailable.  Preserve
                        # that fail-visible contract while avoiding this costly
                        # query for every non-SSH process on the host.
                        command_line = None
                raw_processes.append({
                    "name": name,
                    "executable": executable,
                    "identity": process_identity,
                    "cmdline": tuple(command_line or ())[:64],
                })
                if role == "client" and not isinstance(command_line, (list, tuple)):
                    issues.append("ssh.runtime.client_arguments_unavailable")
                if role == "server":
                    service_identity = pid_identity.get(pid, process_identity)
                    if pid not in pid_identity:
                        raw_services.append({
                            "name": "process:sshd",
                            "display_name": "OpenSSH server process",
                            "executable": executable,
                            "state": "running",
                            "start_mode": "unknown",
                            "identity": service_identity,
                        })
                    pid_identity[pid] = service_identity
            except (KeyError, TypeError, ValueError, OSError, AttributeError):
                if ssh_candidate:
                    issues.append("ssh.runtime.process_metadata_partial")
                continue
    except (OSError, RuntimeError):
        issues.append("ssh.runtime.process_inventory_unavailable")

    # Build a bounded PID -> birth identity map from the normalized raw rows;
    # no PID or birth timestamp leaves this function.
    pid_process_identity: dict[int, str] = {}
    for raw in raw_processes:
        identity = str(raw["identity"])
        match = re.match(r"pid:(\d+):birth:", identity)
        if match:
            pid_process_identity[int(match.group(1))] = identity
    if (target.startswith("win") or target == "windows") and raw_processes:
        issues.append("ssh.runtime.signature_verification_unavailable")

    try:
        listen_status = str(getattr(psutil, "CONN_LISTEN", "LISTEN")).casefold()
        for index, conn in enumerate(psutil.net_connections(kind="tcp")):
            if index >= 4096:
                issues.append("ssh.runtime.connection_bound_reached")
                break
            pid = getattr(conn, "pid", None)
            if pid not in pid_process_identity:
                continue
            address = ""
            port = -1
            local = getattr(conn, "laddr", None)
            try:
                local_ip = str(getattr(local, "ip", local[0]))
                port = int(getattr(local, "port", local[1]))
                address = local_ip
                local_value = f"{local_ip}:{port}"
            except (TypeError, ValueError, IndexError, AttributeError):
                continue
            remote_value = ""
            remote = getattr(conn, "raddr", None)
            if remote:
                try:
                    remote_value = f"{getattr(remote, 'ip', remote[0])}:{int(getattr(remote, 'port', remote[1]))}"
                except (TypeError, ValueError, IndexError, AttributeError):
                    remote_value = "unavailable"
            status = str(getattr(conn, "status", "unknown") or "unknown").casefold()
            process_identity = pid_process_identity[int(pid)]
            raw_connections.append({
                "local": local_value,
                "remote": remote_value,
                "state": status,
                "process_identity": process_identity,
            })
            if status != listen_status:
                continue
            service_identity = pid_identity.get(int(pid))
            if service_identity:
                raw_listeners.append({
                    "address": address,
                    "port": port,
                    "service_identity": service_identity,
                })
    except (OSError, RuntimeError, PermissionError):
        issues.append("ssh.runtime.connection_inventory_unavailable")
    normalized = normalize_runtime_evidence(
        raw_services,
        raw_listeners,
        privacy_key=privacy_key,
        platform=target,
        environ=environ,
        processes=raw_processes,
        connections=raw_connections,
    )
    return SSHRuntimeEvidence(
        normalized.services,
        normalized.listeners,
        tuple(dict.fromkeys((*issues, *normalized.issues))),
        normalized.processes,
        normalized.connections,
    )


def _default_host_key_candidates(platform: str, environ: Mapping[str, str]) -> tuple[Path, ...]:
    if platform.startswith("win") or platform == "windows":
        root = Path(environ.get("ProgramData") or r"C:\ProgramData") / "ssh"
    else:
        root = Path("/etc/ssh")
    names = (
        "ssh_host_ed25519_key",
        "ssh_host_ecdsa_key",
        "ssh_host_rsa_key",
        "ssh_host_dsa_key",
    )
    return tuple(root / name for name in names)


def inventory_host_keys(
    parsed: ParsedSSHDConfig | None,
    *,
    privacy_key: bytes,
    platform: str | None = None,
    environ: Mapping[str, str] | None = None,
    windows_acl_verifier: Callable[[Path], bool | None] | None = None,
) -> tuple[tuple[dict[str, str], ...], tuple[str, ...]]:
    """Hash bounded host-key files; retain neither paths nor private key bytes."""
    target = (platform or sys.platform).casefold()
    windows = target.startswith("win") or target == "windows"
    env = environ if environ is not None else os.environ
    candidates: list[Path] = []
    issues: list[str] = []
    if parsed is not None:
        for directive in parsed.global_directives("HostKey")[:MAX_HOST_KEYS]:
            if directive.arguments:
                path = Path(directive.arguments[0])
                if path.is_absolute():
                    candidates.append(path)
                else:
                    issues.append("ssh.host_keys.non_absolute_path_rejected")
    if not candidates:
        candidates.extend(_default_host_key_candidates(target, env))
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for path in candidates[:MAX_HOST_KEYS]:
        path_token = _purpose_token(
            privacy_key, b"ssh-host-key-path", os.path.normcase(str(path)), "hostkey"
        )
        if path_token in seen:
            continue
        seen.add(path_token)
        try:
            if not path.exists():
                continue
            data = safe_read_bounded(path, max_bytes=MAX_AUTH_FILE_BYTES)
        except OSError:
            issues.append("ssh.host_keys.unreadable_or_unsafe")
            continue
        if windows:
            verifier = windows_acl_verifier or verify_windows_ssh_acl
            try:
                acl_state = verifier(path)
            except Exception:
                acl_state = None
            if acl_state is False:
                issues.append("ssh.host_keys.windows_acl_unsafe")
            elif acl_state is not True:
                issues.append("ssh.host_keys.windows_acl_unknown")
        out.append({"path_token": path_token, "digest": hashlib.sha256(data).hexdigest()})
    return tuple(sorted(out, key=lambda item: item["path_token"])), tuple(issues)


def build_ssh_snapshot(
    *,
    config_digest: str | None,
    config_state: str,
    inventory: AuthorizedKeyInventory,
    host_keys: Sequence[Mapping[str, str]],
    runtime: SSHRuntimeEvidence,
    configured_sources: Sequence[SSHConfiguredSourceEvidence] = (),
    coverage: Iterable[str] = (),
) -> dict[str, object]:
    """Build the only schema accepted by the authenticated drift store."""
    digest = config_digest if isinstance(config_digest, str) and _HEX64.fullmatch(config_digest) else None
    state = config_state if config_state in {
        "observed", "missing", "ambiguous", "unreadable", "unsafe"
    } else "unreadable"
    return {
        "config_digest": digest,
        "config_state": state,
        "authorized_keys": [item.as_dict() for item in inventory.entries[:MAX_BASELINE_ITEMS]],
        "host_keys": [
            {"path_token": str(item.get("path_token", "")), "digest": str(item.get("digest", ""))}
            for item in host_keys[:MAX_HOST_KEYS]
        ],
        "services": [item.as_dict() for item in runtime.services[:MAX_RUNTIME_ROWS]],
        "listeners": [item.as_dict() for item in runtime.listeners[:MAX_RUNTIME_ROWS]],
        "configured_sources": [
            item.as_dict() for item in configured_sources[:MAX_BASELINE_ITEMS]
        ],
        "processes": [item.as_dict() for item in runtime.processes[:MAX_RUNTIME_ROWS]],
        "connections": [item.as_dict() for item in runtime.connections[:MAX_RUNTIME_ROWS]],
        "coverage": sorted({str(item) for item in coverage})[:128],
    }


_SNAPSHOT_FIELDS = {
    "config_digest", "config_state", "authorized_keys", "host_keys", "services", "listeners",
    "configured_sources", "processes", "connections", "coverage",
}
_LEGACY_SNAPSHOT_FIELDS = {
    "config_digest", "config_state", "authorized_keys", "host_keys", "services", "listeners"
}
_KEY_FIELDS = {
    "fingerprint", "entry_digest", "algorithm", "owner_token", "path_token", "restrictions"
}
_HOST_KEY_FIELDS = {"path_token", "digest"}
_SERVICE_FIELDS = {
    "service_token", "executable_token", "state", "start_mode", "renamed", "nonstandard_binary"
}
_LISTENER_FIELDS = {"listener_token", "bind_token", "port", "scope", "service_token"}
_CONFIGURED_SOURCE_FIELDS = {"source_token", "kind", "state", "digest", "custody"}
_PROCESS_FIELDS = {
    "process_token", "executable_token", "role", "nonstandard_binary", "forwarding_flags"
}
_CONNECTION_FIELDS = {
    "connection_token", "local_token", "remote_token", "state", "direction", "process_token"
}


def _valid_token(value: object, prefixes: set[str]) -> bool:
    if not isinstance(value, str) or not _TOKEN.fullmatch(value):
        return False
    return value.split(":", 1)[0] in prefixes


def _validate_snapshot(value: object) -> dict[str, object]:
    if isinstance(value, dict) and set(value) == _LEGACY_SNAPSHOT_FIELDS:
        value = {
            **value,
            "configured_sources": [],
            "processes": [],
            "connections": [],
            "coverage": ["ssh.baseline.legacy_v1_coverage_unknown"],
        }
    if not isinstance(value, dict) or set(value) != _SNAPSHOT_FIELDS:
        raise SSHBaselineIntegrityError("SSH snapshot schema is invalid")
    config_digest = value["config_digest"]
    if config_digest is not None and (
        not isinstance(config_digest, str) or not _HEX64.fullmatch(config_digest)
    ):
        raise SSHBaselineIntegrityError("SSH config digest is invalid")
    config_state = value["config_state"]
    if config_state not in {"observed", "missing", "ambiguous", "unreadable", "unsafe"}:
        raise SSHBaselineIntegrityError("SSH config state is invalid")

    keys = value["authorized_keys"]
    if not isinstance(keys, list) or len(keys) > MAX_BASELINE_ITEMS:
        raise SSHBaselineIntegrityError("SSH authorized-key bound is invalid")
    clean_keys: list[dict[str, object]] = []
    for item in keys:
        if not isinstance(item, dict) or set(item) != _KEY_FIELDS:
            raise SSHBaselineIntegrityError("SSH authorized-key schema is invalid")
        fingerprint = item["fingerprint"]
        algorithm = item["algorithm"]
        restrictions = item["restrictions"]
        if (
            not isinstance(fingerprint, str)
            or not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{32,64}", fingerprint)
            or not isinstance(algorithm, str)
            or not _KEY_TYPE_RE.fullmatch(algorithm)
            or not _valid_token(item["entry_digest"], {"entry"})
            or not _valid_token(item["owner_token"], {"owner"})
            or not _valid_token(item["path_token"], {"path"})
            or not isinstance(restrictions, list)
            or len(restrictions) > 16
            or any(not isinstance(entry, str) or len(entry) > 32 for entry in restrictions)
        ):
            raise SSHBaselineIntegrityError("SSH authorized-key value is invalid")
        clean_keys.append({
            "fingerprint": fingerprint,
            "entry_digest": item["entry_digest"],
            "algorithm": algorithm.casefold(),
            "owner_token": item["owner_token"],
            "path_token": item["path_token"],
            "restrictions": list(restrictions),
        })

    host_keys = value["host_keys"]
    if not isinstance(host_keys, list) or len(host_keys) > MAX_HOST_KEYS:
        raise SSHBaselineIntegrityError("SSH host-key bound is invalid")
    clean_host_keys: list[dict[str, str]] = []
    for item in host_keys:
        if (
            not isinstance(item, dict)
            or set(item) != _HOST_KEY_FIELDS
            or not _valid_token(item["path_token"], {"hostkey"})
            or not isinstance(item["digest"], str)
            or not _HEX64.fullmatch(item["digest"])
        ):
            raise SSHBaselineIntegrityError("SSH host-key value is invalid")
        clean_host_keys.append({"path_token": item["path_token"], "digest": item["digest"]})

    services = value["services"]
    if not isinstance(services, list) or len(services) > MAX_RUNTIME_ROWS:
        raise SSHBaselineIntegrityError("SSH service bound is invalid")
    clean_services: list[dict[str, object]] = []
    for item in services:
        if not isinstance(item, dict) or set(item) != _SERVICE_FIELDS:
            raise SSHBaselineIntegrityError("SSH service schema is invalid")
        if (
            not _valid_token(item["service_token"], {"service"})
            or not _valid_token(item["executable_token"], {"binary"})
            or item["state"] not in {"running", "stopped", "paused", "starting", "unknown"}
            or item["start_mode"] not in {"auto", "automatic", "manual", "disabled", "boot", "unknown"}
            or type(item["renamed"]) is not bool
            or type(item["nonstandard_binary"]) is not bool
        ):
            raise SSHBaselineIntegrityError("SSH service value is invalid")
        clean_services.append(dict(item))

    listeners = value["listeners"]
    if not isinstance(listeners, list) or len(listeners) > MAX_RUNTIME_ROWS:
        raise SSHBaselineIntegrityError("SSH listener bound is invalid")
    clean_listeners: list[dict[str, object]] = []
    for item in listeners:
        if not isinstance(item, dict) or set(item) != _LISTENER_FIELDS:
            raise SSHBaselineIntegrityError("SSH listener schema is invalid")
        if (
            not _valid_token(item["listener_token"], {"listener"})
            or not _valid_token(item["bind_token"], {"bind"})
            or not _valid_token(item["service_token"], {"service"})
            or type(item["port"]) is not int
            or not 1 <= item["port"] <= 65535
            or item["scope"] not in {"wildcard", "loopback", "link-local", "interface", "unknown"}
        ):
            raise SSHBaselineIntegrityError("SSH listener value is invalid")
        clean_listeners.append(dict(item))

    configured_sources = value["configured_sources"]
    if not isinstance(configured_sources, list) or len(configured_sources) > MAX_BASELINE_ITEMS:
        raise SSHBaselineIntegrityError("SSH configured-source bound is invalid")
    clean_sources: list[dict[str, object]] = []
    for item in configured_sources:
        if not isinstance(item, dict) or set(item) != _CONFIGURED_SOURCE_FIELDS:
            raise SSHBaselineIntegrityError("SSH configured-source schema is invalid")
        digest = item["digest"]
        if (
            not _valid_token(item["source_token"], {"sourcefile"})
            or item["kind"] not in {
                "config", "include", "authorized_keys", "trusted_ca", "principals",
                "key_command", "principals_command",
            }
            or item["state"] not in {
                "observed", "missing", "unreadable", "unresolved", "incomplete",
                "unsupported", "disabled", "not-applicable",
            }
            or (digest is not None and (not isinstance(digest, str) or not _HEX64.fullmatch(digest)))
            or item["custody"] not in {"verified", "unsafe", "unknown", "not-applicable"}
        ):
            raise SSHBaselineIntegrityError("SSH configured-source value is invalid")
        clean_sources.append(dict(item))

    processes = value["processes"]
    if not isinstance(processes, list) or len(processes) > MAX_RUNTIME_ROWS:
        raise SSHBaselineIntegrityError("SSH process bound is invalid")
    clean_processes: list[dict[str, object]] = []
    forwarding_labels = set(
        _SSH_FORWARDING_OPTION_LABELS | _SSH_OPTION_COMPLETENESS_LABELS
    )
    for item in processes:
        flags = item.get("forwarding_flags") if isinstance(item, dict) else None
        if (
            not isinstance(item, dict)
            or set(item) != _PROCESS_FIELDS
            or not _valid_token(item["process_token"], {"process"})
            or not _valid_token(item["executable_token"], {"binary"})
            or item["role"] not in {"server", "client"}
            or type(item["nonstandard_binary"]) is not bool
            or not isinstance(flags, list)
            or len(flags) > len(forwarding_labels)
            or any(flag not in forwarding_labels for flag in flags)
        ):
            raise SSHBaselineIntegrityError("SSH process value is invalid")
        clean_processes.append({**item, "forwarding_flags": sorted(set(flags))})

    connections = value["connections"]
    if not isinstance(connections, list) or len(connections) > MAX_RUNTIME_ROWS:
        raise SSHBaselineIntegrityError("SSH connection bound is invalid")
    clean_connections: list[dict[str, object]] = []
    process_tokens = {str(item["process_token"]) for item in clean_processes}
    for item in connections:
        if (
            not isinstance(item, dict)
            or set(item) != _CONNECTION_FIELDS
            or not _valid_token(item["connection_token"], {"connection"})
            or not _valid_token(item["local_token"], {"endpoint"})
            or not _valid_token(item["remote_token"], {"endpoint"})
            or item["process_token"] not in process_tokens
            or item["state"] not in {
                "listen", "established", "syn_sent", "syn_recv", "close_wait", "time_wait", "unknown"
            }
            or item["direction"] not in {"listener", "inbound", "outbound", "unknown"}
        ):
            raise SSHBaselineIntegrityError("SSH connection value is invalid")
        clean_connections.append(dict(item))

    coverage = value["coverage"]
    if (
        not isinstance(coverage, list)
        or len(coverage) > 128
        or any(
            not isinstance(item, str)
            or not re.fullmatch(r"ssh\.[a-z0-9_.-]{1,95}", item)
            for item in coverage
        )
    ):
        raise SSHBaselineIntegrityError("SSH coverage schema is invalid")
    return {
        "config_digest": config_digest,
        "config_state": config_state,
        "authorized_keys": sorted(
            clean_keys,
            key=lambda item: (
                str(item["owner_token"]), str(item["path_token"]),
                str(item["fingerprint"]), str(item["entry_digest"]),
            ),
        ),
        "host_keys": sorted(clean_host_keys, key=lambda item: item["path_token"]),
        "services": sorted(clean_services, key=lambda item: str(item["service_token"])),
        "listeners": sorted(clean_listeners, key=lambda item: str(item["listener_token"])),
        "configured_sources": sorted(
            clean_sources, key=lambda item: str(item["source_token"])
        ),
        "processes": sorted(
            clean_processes, key=lambda item: str(item["process_token"])
        ),
        "connections": sorted(
            clean_connections, key=lambda item: str(item["connection_token"])
        ),
        "coverage": sorted(set(coverage)),
    }


def _map_rows(rows: Sequence[Mapping[str, object]], keys: Sequence[str]) -> dict[str, Mapping[str, object]]:
    out: dict[str, Mapping[str, object]] = {}
    for row in rows:
        identity = "\x00".join(str(row.get(key, "")) for key in keys)
        out[identity] = row
    return out


def compare_ssh_snapshots(
    baseline: Mapping[str, object],
    current: Mapping[str, object],
) -> dict[str, object]:
    """Return bounded, identity-minimized drift; list ordering has no meaning."""
    before = _validate_snapshot(dict(baseline))
    after = _validate_snapshot(dict(current))
    changes: dict[str, object] = {}
    if before["config_digest"] != after["config_digest"] or before["config_state"] != after["config_state"]:
        changes["config"] = {
            "changed": before["config_digest"] != after["config_digest"],
            "before_state": before["config_state"],
            "after_state": after["config_state"],
            "before_digest": before["config_digest"],
            "after_digest": after["config_digest"],
        }

    old_keys = _map_rows(before["authorized_keys"], ("owner_token", "path_token", "fingerprint"))  # type: ignore[arg-type]
    new_keys = _map_rows(after["authorized_keys"], ("owner_token", "path_token", "fingerprint"))  # type: ignore[arg-type]
    added_key_ids = sorted(set(new_keys) - set(old_keys))
    removed_key_ids = sorted(set(old_keys) - set(new_keys))
    modified_key_ids = sorted(
        identity for identity in set(old_keys) & set(new_keys)
        if old_keys[identity].get("entry_digest") != new_keys[identity].get("entry_digest")
    )
    if added_key_ids:
        changes["keys_added"] = [new_keys[item]["fingerprint"] for item in added_key_ids]
    if removed_key_ids:
        changes["keys_removed"] = [old_keys[item]["fingerprint"] for item in removed_key_ids]
    if modified_key_ids:
        changes["keys_modified"] = [new_keys[item]["fingerprint"] for item in modified_key_ids]

    def row_drift(
        field: str,
        identity_keys: tuple[str, ...],
        public_id: str,
    ) -> None:
        old = _map_rows(before[field], identity_keys)  # type: ignore[arg-type]
        new = _map_rows(after[field], identity_keys)  # type: ignore[arg-type]
        added = sorted(set(new) - set(old))
        removed = sorted(set(old) - set(new))
        modified = sorted(
            identity for identity in set(old) & set(new)
            if _canonical_json(old[identity]) != _canonical_json(new[identity])
        )
        if added:
            changes[f"{field}_added"] = [new[item][public_id] for item in added]
        if removed:
            changes[f"{field}_removed"] = [old[item][public_id] for item in removed]
        if modified:
            changes[f"{field}_modified"] = [new[item][public_id] for item in modified]

    row_drift("host_keys", ("path_token",), "path_token")
    row_drift("services", ("service_token",), "service_token")
    row_drift("listeners", ("listener_token",), "listener_token")
    row_drift("configured_sources", ("source_token",), "source_token")
    row_drift("processes", ("process_token",), "process_token")
    row_drift("connections", ("connection_token",), "connection_token")
    if before["coverage"] != after["coverage"]:
        changes["coverage"] = {
            "before": list(before["coverage"]),
            "after": list(after["coverage"]),
        }
    return changes


class SSHBaselineStore:
    """HMAC-authenticated provisional/trusted SSH surface baseline."""

    def __init__(
        self,
        path: Path | str,
        *,
        data_root: Path | str | None = None,
        master_key: bytes | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.path = Path(path)
        self._data_root = Path(data_root) if data_root is not None else self.path.parent
        self._keys = load_ssh_purpose_keys(self._data_root, master_key=master_key)
        self._clock = clock

    @property
    def authentication_available(self) -> bool:
        return self._keys is not None

    def _signature(self, body: Mapping[str, object]) -> str:
        if self._keys is None:
            raise SSHBaselineIntegrityError("SSH baseline HMAC authority is unavailable")
        return hmac.new(self._keys.baseline_key, _canonical_json(body), hashlib.sha256).hexdigest()

    def _load(self) -> tuple[dict[str, object], dict[str, object]] | None:
        if not self.path.exists():
            return None
        if self._keys is None:
            raise SSHBaselineIntegrityError("SSH baseline HMAC authority is unavailable")
        if path_has_link_or_reparse(self.path):
            raise SSHBaselineIntegrityError("SSH baseline path is link/reparse-backed")
        try:
            raw = safe_read_bounded(self.path, max_bytes=MAX_BASELINE_BYTES)
            value = json.loads(
                raw.decode("utf-8", "strict"),
                object_pairs_hook=_strict_object,
                parse_constant=lambda item: (_ for _ in ()).throw(
                    SSHBaselineIntegrityError(f"invalid baseline constant: {item}")
                ),
            )
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise SSHBaselineIntegrityError("SSH baseline is unreadable or malformed") from exc
        if not isinstance(value, dict) or set(value) != {"body", "hmac_sha256"}:
            raise SSHBaselineIntegrityError("SSH baseline wrapper is invalid")
        body = value["body"]
        signature = value["hmac_sha256"]
        if (
            not isinstance(body, dict)
            or set(body) != {"schema", "trusted", "captured_at", "snapshot"}
            or type(body["schema"]) is not int
            or body["schema"] not in {_LEGACY_BASELINE_SCHEMA, _BASELINE_SCHEMA}
            or type(body["trusted"]) is not bool
            or not isinstance(body["captured_at"], (int, float))
            or isinstance(body["captured_at"], bool)
            or not math.isfinite(float(body["captured_at"]))
            or not isinstance(signature, str)
            or not _HEX64.fullmatch(signature)
            or not hmac.compare_digest(signature, self._signature(body))
        ):
            raise SSHBaselineIntegrityError("SSH baseline failed authentication")
        snapshot = _validate_snapshot(body["snapshot"])
        clean_body = {
            "schema": int(body["schema"]),
            "trusted": body["trusted"],
            "captured_at": float(body["captured_at"]),
            "snapshot": snapshot,
        }
        return clean_body, snapshot

    def _write(self, snapshot: Mapping[str, object], *, trusted: bool) -> None:
        if self._keys is None:
            raise SSHBaselineIntegrityError("SSH baseline HMAC authority is unavailable")
        clean = _validate_snapshot(dict(snapshot))
        captured = float(self._clock())
        if not math.isfinite(captured):
            raise ValueError("SSH baseline clock is invalid")
        body: dict[str, object] = {
            "schema": _BASELINE_SCHEMA,
            "trusted": bool(trusted),
            "captured_at": captured,
            "snapshot": clean,
        }
        wrapper = {"body": body, "hmac_sha256": self._signature(body)}
        encoded = _canonical_json(wrapper)
        if len(encoded) > MAX_BASELINE_BYTES:
            raise SSHBaselineIntegrityError("SSH baseline exceeds storage bound")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if path_has_link_or_reparse(self.path.parent) or (
            self.path.exists() and path_has_link_or_reparse(self.path)
        ):
            raise SSHBaselineIntegrityError("SSH baseline destination is link/reparse-backed")
        temporary = self.path.with_name(
            f".{self.path.name}.tmp-{os.getpid()}-{secrets.token_hex(6)}"
        )
        fd = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
            try:
                self.path.chmod(0o600)
            except OSError:
                pass
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass

    def observe(
        self,
        snapshot: Mapping[str, object],
        *,
        initialize_provisional: bool = True,
    ) -> SSHBaselineComparison:
        """Compare evidence, optionally recording an explicitly untrusted first view."""
        current = _validate_snapshot(dict(snapshot))
        if self._keys is None:
            return SSHBaselineComparison(
                "unknown", False, "purpose-separated bus key unavailable", {}
            )
        try:
            loaded = self._load()
        except SSHBaselineIntegrityError as exc:
            return SSHBaselineComparison("tampered", False, str(exc), {})
        if loaded is None:
            if initialize_provisional:
                try:
                    self._write(current, trusted=False)
                except (OSError, SSHBaselineIntegrityError) as exc:
                    return SSHBaselineComparison("unknown", False, f"baseline could not be recorded: {exc}", {})
            return SSHBaselineComparison(
                "unknown", False,
                "first observation recorded as provisional; operator trust has not been established",
                {},
            )
        body, previous = loaded
        changes = compare_ssh_snapshots(previous, current)
        trusted = bool(body["trusted"])
        if changes:
            return SSHBaselineComparison(
                "drift", trusted,
                "SSH surface differs from the authenticated baseline",
                changes,
            )
        return SSHBaselineComparison(
            "stable" if trusted else "unknown",
            trusted,
            "authenticated trusted baseline is stable" if trusted else "provisional baseline is stable but untrusted",
            {},
        )

    def establish_trusted(self, snapshot: Mapping[str, object]) -> None:
        """Explicit operator/API action; the observe-only module never calls this."""
        self._write(snapshot, trusted=True)


_SSH_SOURCE_RE = re.compile(
    r"\bfrom\s+(?P<source>[^\s]+)(?:\s+port\s+\d+)?",
    re.IGNORECASE,
)
_FAILED_RE = re.compile(
    r"\bFailed\s+(?:password|publickey|keyboard-interactive|none)\s+for\s+"
    r"(?:(?:invalid\s+user)\s+)?(?P<account>[^\s]+)\s+from\s+(?P<source>[^\s]+)",
    re.IGNORECASE,
)
_ACCEPTED_RE = re.compile(
    r"\bAccepted\s+(?P<method>password|publickey|keyboard-interactive|hostbased)\s+"
    r"for\s+(?P<account>[^\s]+)\s+from\s+(?P<source>[^\s]+)",
    re.IGNORECASE,
)
_INVALID_RE = re.compile(
    r"\bInvalid\s+user\s+(?P<account>[^\s]+)\s+from\s+(?P<source>[^\s]+)",
    re.IGNORECASE,
)
_FORWARD_SIGNAL_RE = re.compile(
    r"(?:direct-tcpip|forwarded-tcpip|tcp forwarding|port forwarding|"
    r"forwarding request|request to connect|Allocated port|Tunnel forwarding|"
    r"tun(?:nel)?\s+request|channel\s+\d+:\s+open)",
    re.IGNORECASE,
)


def _normalize_source(value: str) -> str:
    source = value.strip().strip("[]").rstrip(".,;")[:512]
    # Normalize actual IP addresses so equivalent compressed IPv6 forms share
    # one token. Hostnames stay opaque and are never returned.
    zone = ""
    candidate = source
    if "%" in candidate:
        candidate, zone = candidate.split("%", 1)
    try:
        normalized = ipaddress.ip_address(candidate).compressed
        return f"{normalized}%{zone.casefold()}" if zone else normalized
    except ValueError:
        return source.casefold()


def analyze_openssh_logs(
    lines: Iterable[str],
    *,
    privacy_key: bytes,
    known_source_tokens: Iterable[str] = (),
    max_lines: int = MAX_LOG_LINES,
    max_bytes: int = MAX_LOG_BYTES,
    max_evidence: int = MAX_LOG_EVIDENCE,
) -> SSHLogAnalysis:
    """Analyze bounded log text and emit only purpose-tokenized identities.

    The returned structure never carries a raw source address, hostname,
    account name, or original log line. Callers may safely persist its tokens.
    """
    if not isinstance(privacy_key, bytes) or len(privacy_key) != 32:
        raise ValueError("SSH privacy key must contain exactly 32 bytes")
    if (
        type(max_lines) is not int
        or type(max_bytes) is not int
        or not 1 <= max_lines <= MAX_LOG_LINES
        or not 1 <= max_bytes <= MAX_LOG_BYTES
    ):
        raise ValueError("invalid SSH log analysis bounds")
    if type(max_evidence) is not int or not 1 <= max_evidence <= MAX_LOG_EVIDENCE:
        raise ValueError("invalid SSH log evidence bound")
    known: set[str] = set()
    for index, item in enumerate(known_source_tokens):
        if index >= 4096:
            break
        if isinstance(item, str) and _valid_token(item, {"source"}):
            known.add(item)
    counts: dict[tuple[str, str, str], int] = {}
    observed: set[str] = set()
    lines_examined = 0
    bytes_examined = 0
    dropped_lines = 0
    candidates_seen = 0
    for raw in lines:
        candidates_seen += 1
        if candidates_seen > max_lines:
            dropped_lines += 1
            break
        if not isinstance(raw, str):
            dropped_lines += 1
            continue
        if len(raw) > MAX_LOG_LINE_CHARS:
            dropped_lines += 1
            continue
        encoded_size = len(raw.encode("utf-8", "replace"))
        if encoded_size > MAX_LOG_LINE_CHARS * 4:
            dropped_lines += 1
            continue
        if bytes_examined + encoded_size > max_bytes:
            dropped_lines += 1
            break
        lines_examined += 1
        bytes_examined += encoded_size
        line = raw[:MAX_LOG_LINE_CHARS]
        kind = ""
        source = ""
        account = ""
        failed = _FAILED_RE.search(line)
        accepted = _ACCEPTED_RE.search(line)
        invalid = _INVALID_RE.search(line)
        if failed:
            kind = "authentication_failure"
            source = failed.group("source")
            account = failed.group("account")
        elif accepted:
            method = accepted.group("method").casefold()
            kind = "successful_password_auth" if method in {
                "password", "keyboard-interactive"
            } else "successful_key_auth"
            source = accepted.group("source")
            account = accepted.group("account")
        elif invalid:
            kind = "authentication_failure"
            source = invalid.group("source")
            account = invalid.group("account")
        elif _FORWARD_SIGNAL_RE.search(line):
            kind = "forwarding_or_tunnel_signal"
            source_match = _SSH_SOURCE_RE.search(line)
            source = source_match.group("source") if source_match else "source-unavailable"
        else:
            continue
        source_token = _purpose_token(
            privacy_key, b"ssh-auth-source", _normalize_source(source), "source"
        )
        account_token = (
            _purpose_token(privacy_key, b"ssh-auth-account", account.casefold(), "account")
            if account else ""
        )
        observed.add(source_token)
        identity = (kind, source_token, account_token)
        counts[identity] = min(1_000_000_000, counts.get(identity, 0) + 1)

    priority = {
        "successful_password_auth": 0,
        "forwarding_or_tunnel_signal": 1,
        "authentication_failure": 2,
        "successful_key_auth": 3,
    }
    rows: list[SSHLogEvidence] = []
    for (kind, source_token, account_token), count in sorted(
        counts.items(),
        key=lambda item: (
            priority.get(item[0][0], 99), item[0][1], item[0][2]
        ),
    ):
        severity = {
            "successful_password_auth": "high",
            "forwarding_or_tunnel_signal": "high",
            "authentication_failure": "medium" if count >= 5 else "low",
            "successful_key_auth": "info",
        }.get(kind, "low")
        rows.append(SSHLogEvidence(
            kind=kind,
            severity=severity,
            source_token=source_token,
            account_token=account_token,
            count=count,
            new_source=source_token not in known,
        ))
    dropped_evidence = max(0, len(rows) - max_evidence)
    return SSHLogAnalysis(
        evidence=tuple(rows[:max_evidence]),
        observed_source_tokens=tuple(sorted(observed)[:4096]),
        lines_examined=lines_examined,
        bytes_examined=bytes_examined,
        dropped_lines=dropped_lines,
        dropped_evidence=dropped_evidence,
    )


WINDOWS_OPENSSH_CHANNELS: tuple[tuple[str, tuple[int, ...]], ...] = (
    ("OpenSSH/Operational", (1, 2, 3, 4)),
    ("OpenSSH/Admin", (1, 2, 3, 4)),
)
_WINDOWS_EVENT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def _windows_event_uint(node: object, label: str) -> int:
    text = str(getattr(node, "text", "") or "").strip()
    if not text or len(text) > 20 or not text.isdecimal():
        raise ValueError(f"invalid Windows OpenSSH {label}")
    value = int(text)
    if value < 0 or value > 2**63 - 1:
        raise ValueError(f"invalid Windows OpenSSH {label}")
    return value


def windows_event_record_id(xml: str) -> int:
    """Extract a bounded record cursor without retaining any event payload."""
    if not isinstance(xml, str) or len(xml.encode("utf-8", "replace")) > MAX_LOG_BYTES:
        raise ValueError("Windows OpenSSH event exceeds the admission bound")
    try:
        root = SafeET.fromstring(xml)
    except Exception as exc:
        raise ValueError("Windows OpenSSH event XML is malformed") from exc
    system = root.find(f"{_WINDOWS_EVENT_NS}System")
    record = system.find(f"{_WINDOWS_EVENT_NS}EventRecordID") if system is not None else None
    if record is None:
        raise ValueError("Windows OpenSSH event has no record ID")
    return _windows_event_uint(record, "record ID")


def parse_windows_openssh_event(xml: str, *, expected_channel: str) -> WindowsOpenSSHEvent:
    """Admit one fixed-provider event and return only its bounded log payload."""
    expected = str(expected_channel or "")
    allowed = dict(WINDOWS_OPENSSH_CHANNELS)
    if expected not in allowed:
        raise ValueError("unsupported Windows OpenSSH channel")
    if not isinstance(xml, str) or len(xml.encode("utf-8", "replace")) > MAX_LOG_BYTES:
        raise ValueError("Windows OpenSSH event exceeds the admission bound")
    try:
        root = SafeET.fromstring(xml)
    except Exception as exc:
        raise ValueError("Windows OpenSSH event XML is malformed") from exc
    system = root.find(f"{_WINDOWS_EVENT_NS}System")
    if system is None:
        raise ValueError("Windows OpenSSH event has no System section")
    provider = system.find(f"{_WINDOWS_EVENT_NS}Provider")
    channel = system.find(f"{_WINDOWS_EVENT_NS}Channel")
    event = system.find(f"{_WINDOWS_EVENT_NS}EventID")
    record = system.find(f"{_WINDOWS_EVENT_NS}EventRecordID")
    provider_name = str(provider.attrib.get("Name", "") if provider is not None else "")
    channel_name = str(channel.text or "" if channel is not None else "")
    if provider_name.casefold() != "openssh" or channel_name.casefold() != expected.casefold():
        raise ValueError("Windows OpenSSH provider or channel mismatch")
    if event is None or record is None:
        raise ValueError("Windows OpenSSH event identity is incomplete")
    event_id = _windows_event_uint(event, "event ID")
    if event_id not in allowed[expected]:
        raise ValueError("Windows OpenSSH event ID is not admitted")
    record_id = _windows_event_uint(record, "record ID")
    parts: list[str] = []
    total = 0
    event_data = root.find(f"{_WINDOWS_EVENT_NS}EventData")
    if event_data is not None:
        for index, node in enumerate(list(event_data)):
            if index >= 16:
                raise ValueError("Windows OpenSSH event field bound reached")
            name = str(node.attrib.get("Name", "")).casefold()
            if name not in {"payload", "message"}:
                continue
            value = str(node.text or "").replace("\x00", "")
            value = "".join(
                character if character in "\t\r\n" or ord(character) >= 32 else " "
                for character in value
            )
            encoded = value.encode("utf-8", "replace")
            if total + len(encoded) > MAX_LOG_LINE_CHARS:
                raise ValueError("Windows OpenSSH payload bound reached")
            total += len(encoded)
            if value:
                parts.append(value)
    return WindowsOpenSSHEvent(
        channel=expected,
        event_id=event_id,
        record_id=record_id,
        message=" ".join(parts)[:MAX_LOG_LINE_CHARS],
    )


def open_windows_openssh_event_source(channel: str):
    """Open only a compile-time OpenSSH channel with its fixed event-ID set."""
    allowed = dict(WINDOWS_OPENSSH_CHANNELS)
    if channel not in allowed:
        raise ValueError("unsupported Windows OpenSSH channel")
    from angerona.core.windows_event_log import WindowsEventLogSource

    return WindowsEventLogSource(channel, allowed[channel])


def canonical_openssh_log_candidates(
    platform: str | None = None,
    *,
    environ: Mapping[str, str] | None = None,
) -> tuple[Path, ...]:
    """Return conventional local text logs; journal/event-channel ingestion is separate."""
    target = (platform or sys.platform).casefold()
    env = environ if environ is not None else os.environ
    if target.startswith("win") or target == "windows":
        root = Path(env.get("ProgramData") or r"C:\ProgramData") / "ssh" / "logs"
        return (root / "sshd.log", root / "openssh.log")
    if target in {"darwin", "mac", "macos", "osx"}:
        return (Path("/var/log/system.log"), Path("/var/log/auth.log"))
    return (Path("/var/log/auth.log"), Path("/var/log/secure"))
