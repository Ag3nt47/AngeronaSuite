"""Bounded, authenticated temporal tradecraft correlation.

The correlator intentionally recognizes actor-neutral defensive signals rather
than attempting attribution.  It retains only purpose-keyed pseudonyms and
fixed signal kinds; raw accounts, addresses, paths, commands, and event detail
payloads never enter its state file.  Its output is evidence for an operator,
not response authority.

Restart state is canonical JSON protected by an HMAC derived from Angerona's
per-install key.  Missing, unauthenticated, non-monotonic, and overflowed
history remain explicit because an incomplete sequence must never be reported
as a clean host.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import time
from typing import Any, Final, Iterable, Mapping

from angerona.core.eventbus import Event


SCHEMA: Final = "angerona.temporal-tradecraft.v1"
MAX_STATE_BYTES: Final = 256 * 1024
MAX_SIGNALS: Final = 512
MAX_MATCHES: Final = 128
MAX_REASONS: Final = 16
MAX_WINDOW_SECONDS: Final = 6 * 60 * 60
MAX_EVENT_SKEW_SECONDS: Final = 5 * 60
_REPARSE_POINT: Final = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[a-z][a-z0-9_-]{0,15}:v1:[0-9a-f]{32}$")
_STATE_FIELDS = frozenset({
    "schema", "revision", "window_seconds", "signals", "matches", "continuity",
})
_CONTINUITY_FIELDS = frozenset({
    "missing_since", "missing_reasons", "blind_sources", "overflow_at", "dropped",
})
_SIGNAL_FIELDS = frozenset({
    "kind", "observed_at", "evidence_digest", "source_token", "evidence_grade",
    "attestation",
})

_KINDS = frozenset({
    "ssh_key_change",
    "ssh_session",
    "ssh_tunnel",
    "network_path_change",
    "log_clear",
})
_EVIDENCE_GRADES = frozenset(
    {
        "broker-provenanced",
        "schema-admitted-local",
        "unprovenanced",
        # Read-only migration support for state written before producer
        # provenance was separated from EventBus storage integrity.
        "authenticated-bus",
        "local-unarmed",
    }
)

_PATH_CODES = frozenset({
    "network.path_added",
    "network.interface_epoch_changed",
    "network.wireless_identity_drift",
    "network.dns_drift",
    "network.dhcp_drift",
    "network.default_route_drift",
    "network.gateway_identity_drift",
    "network.profile_category_drift",
})
_SESSION_CODES = frozenset({
    "ssh.logs.successful_key_auth",
    "ssh.logs.successful_password_auth",
})
_TUNNEL_CODES = frozenset({
    "ssh.logs.forwarding_or_tunnel_signal",
    "ssh.runtime.client_forwarding_process",
})
_LOG_CLEAR_CLASSES = frozenset({"audit-log-cleared", "event-log-cleared"})


class TemporalTradecraftError(RuntimeError):
    """Temporal evidence or authenticated state failed admission."""


@dataclass(frozen=True)
class TemporalPattern:
    pattern_id: str
    steps: tuple[str, ...]
    severity: str
    summary: str


PATTERNS: Final = (
    TemporalPattern(
        "temporal.ssh_key_session_tunnel",
        ("ssh_key_change", "ssh_session", "ssh_tunnel"),
        "High",
        "SSH key drift was followed by a valid session and tunnel behavior.",
    ),
    TemporalPattern(
        "temporal.ssh_session_path_log_clear",
        ("ssh_session", "network_path_change", "log_clear"),
        "Critical",
        "An SSH session preceded first-hop path drift and audit-log clearing.",
    ),
    TemporalPattern(
        "temporal.ssh_key_session_tunnel_path_log_clear",
        (
            "ssh_key_change",
            "ssh_session",
            "ssh_tunnel",
            "network_path_change",
            "log_clear",
        ),
        "Critical",
        "SSH persistence, access, tunneling, path drift, and log clearing formed an ordered campaign.",
    ),
)


@dataclass(frozen=True)
class TemporalSignal:
    kind: str
    observed_at: float
    evidence_digest: str
    source_token: str
    evidence_grade: str
    attestation: str

    def as_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "observed_at": self.observed_at,
            "evidence_digest": self.evidence_digest,
            "source_token": self.source_token,
            "evidence_grade": self.evidence_grade,
            "attestation": self.attestation,
        }


@dataclass(frozen=True)
class TemporalFinding:
    pattern_id: str
    severity: str
    summary: str
    started_at: float
    ended_at: float
    signal_kinds: tuple[str, ...]
    evidence_digests: tuple[str, ...]
    evidence_grade: str
    response_authorized: bool = False


@dataclass(frozen=True)
class TemporalAssessment:
    state: str
    reason: str
    findings: tuple[TemporalFinding, ...]
    missing_steps: tuple[str, ...]
    retained_signals: int
    dropped_signals: int
    persistence_status: str
    response_authorized: bool = False


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if not isinstance(key, str) or key in result:
            raise TemporalTradecraftError("temporal state contains a duplicate JSON field")
        result[key] = value
    return result


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise TemporalTradecraftError("temporal state is not canonical JSON") from exc


def _token(key: bytes, namespace: bytes, value: object, prefix: str) -> str:
    material = str(value).encode("utf-8", "surrogatepass")[:4096]
    digest = hmac.new(key, namespace + b"\0" + material, hashlib.sha256).hexdigest()
    return f"{prefix}:v1:{digest[:32]}"


def _digest(key: bytes, namespace: bytes, value: object) -> str:
    return hmac.new(key, namespace + b"\0" + _canonical(value), hashlib.sha256).hexdigest()


def derive_temporal_keys(master_key: bytes) -> tuple[bytes, bytes]:
    """Derive state-authentication and privacy keys from a 32-byte master."""
    if not isinstance(master_key, bytes) or len(master_key) != 32:
        raise ValueError("temporal master key must contain exactly 32 bytes")
    return (
        hmac.new(master_key, b"angerona/temporal-state/v1", hashlib.sha256).digest(),
        hmac.new(master_key, b"angerona/temporal-privacy/v1", hashlib.sha256).digest(),
    )


def load_temporal_keys(
    data_root: str | Path,
    *,
    master_key: bytes | None = None,
) -> tuple[bytes, bytes] | None:
    """Load but never create/rotate the installation key, then domain-separate it."""
    value = master_key
    if value is None:
        try:
            from angerona.core.ssh_surface import safe_read_bounded

            encoded = safe_read_bounded(Path(data_root) / "bus.key", max_bytes=256)
            value = bytes.fromhex(encoded.decode("ascii", "strict").strip())
        except (OSError, UnicodeError, ValueError):
            return None
    if not isinstance(value, bytes) or len(value) != 32:
        return None
    return derive_temporal_keys(value)


def _is_reparse(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        int(getattr(info, "st_file_attributes", 0)) & _REPARSE_POINT
    )


def _reject_reparse_components(path: Path) -> None:
    absolute = Path(os.path.abspath(os.fspath(path)))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        info = current.lstat()
        if _is_reparse(info):
            raise OSError("temporal state path is link/reparse-backed")


def _safe_state_read(path: Path) -> bytes:
    _reject_reparse_components(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or _is_reparse(before):
        raise OSError("temporal state is not a safe regular file")
    if before.st_size > MAX_STATE_BYTES:
        raise OSError("temporal state exceeds its size bound")
    if _is_reparse(path.parent.lstat()):
        raise OSError("temporal state parent is link/reparse-backed")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(os.fspath(path), flags)
    try:
        opened = os.fstat(descriptor)
        identity = lambda info: (
            getattr(info, "st_dev", None),
            getattr(info, "st_ino", None),
            stat.S_IFMT(info.st_mode),
            info.st_size,
            getattr(info, "st_mtime_ns", None),
        )
        if _is_reparse(opened) or identity(opened) != identity(before):
            raise OSError("temporal state changed while opening")
        chunks: list[bytes] = []
        remaining = MAX_STATE_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    finally:
        os.close(descriptor)
    payload = b"".join(chunks)
    if len(payload) > MAX_STATE_BYTES:
        raise OSError("temporal state exceeds its size bound")
    after = path.lstat()
    if _is_reparse(after) or (
        before.st_size,
        getattr(before, "st_mtime_ns", None),
        getattr(before, "st_ctime_ns", None),
    ) != (
        after.st_size,
        getattr(after, "st_mtime_ns", None),
        getattr(after, "st_ctime_ns", None),
    ):
        raise OSError("temporal state changed during read")
    _reject_reparse_components(path)
    return payload


def _secure_state_write(path: Path, payload: bytes) -> None:
    if len(payload) > MAX_STATE_BYTES:
        raise OSError("temporal state exceeds its size bound")
    path.parent.mkdir(parents=True, exist_ok=True)
    _reject_reparse_components(path.parent)
    if _is_reparse(path.parent.lstat()) or (path.exists() and _is_reparse(path.lstat())):
        raise OSError("temporal state destination is link/reparse-backed")
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}-{secrets.token_hex(6)}")
    descriptor = os.open(os.fspath(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or _is_reparse(info):
            raise OSError("temporal state destination changed file type")
        _reject_reparse_components(path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def _classify_event(event: Event) -> str | None:
    details = event.details if isinstance(event.details, dict) else {}
    code = str(
        details.get("finding_code") or details.get("finding_type") or ""
    )[:128]
    classification = str(details.get("classification") or "")[:128].casefold()
    if event.module == "SSH Surface / Key / Tunnel Guard" and code == "ssh.baseline.drift":
        changes = details.get("changes")
        if isinstance(changes, dict) and any(
            bool(changes.get(field)) for field in ("keys_added", "keys_modified")
        ):
            return "ssh_key_change"
    if event.module == "SSH Surface / Key / Tunnel Guard" and code in _SESSION_CODES:
        return "ssh_session"
    if event.module == "SSH Surface / Key / Tunnel Guard" and code in _TUNNEL_CODES:
        return "ssh_tunnel"
    if event.module == "Zero-Trust Network Path Monitor" and code in _PATH_CODES:
        return "network_path_change"
    if event.module == "Audit Log Integrity Guard" and classification in _LOG_CLEAR_CLASSES:
        return "log_clear"
    return None


class TemporalTradecraftEngine:
    """Fixed-memory temporal automaton with authenticated restart state."""

    def __init__(
        self,
        state_path: str | Path,
        *,
        state_key: bytes,
        privacy_key: bytes,
        window_seconds: int = 3600,
        max_signals: int = MAX_SIGNALS,
        persistence_enabled: bool = True,
        clock=time.time,
    ) -> None:
        if not isinstance(state_key, bytes) or len(state_key) < 32:
            raise ValueError("temporal state key must contain at least 32 bytes")
        if not isinstance(privacy_key, bytes) or len(privacy_key) < 32:
            raise ValueError("temporal privacy key must contain at least 32 bytes")
        if not 60 <= int(window_seconds) <= MAX_WINDOW_SECONDS:
            raise ValueError("temporal window must be between 60 and 21600 seconds")
        self.path = Path(os.path.abspath(os.fspath(state_path)))
        self._state_key = bytes(state_key)
        self._privacy_key = bytes(privacy_key)
        self.window_seconds = int(window_seconds)
        self.max_signals = max(16, min(int(max_signals), MAX_SIGNALS))
        self._clock = clock
        self._persistence_enabled = bool(persistence_enabled)
        self._signals: deque[TemporalSignal] = deque()
        self._matches: deque[str] = deque(maxlen=MAX_MATCHES)
        self._revision = 0
        self._missing_since: float | None = None
        self._missing_reasons: deque[str] = deque(maxlen=MAX_REASONS)
        self._blind_sources: set[str] = set()
        self._overflow_at: float | None = None
        self._dropped = 0
        self.persistence_status = "missing"
        self._persistence_locked = False
        if self._persistence_enabled:
            self._load()
        else:
            self.persistence_status = "unavailable"
            self._persistence_locked = True
            self._blind_sources.add(
                _token(self._privacy_key, b"temporal-blind", "state-store", "sensor")
            )

    def _signal_payload(self, signal: TemporalSignal) -> dict[str, object]:
        payload = signal.as_dict()
        payload.pop("attestation")
        return payload

    def _attest_signal(self, payload: Mapping[str, object]) -> str:
        return hmac.new(
            self._state_key,
            b"angerona/temporal-signal/v1\0" + _canonical(payload),
            hashlib.sha256,
        ).hexdigest()

    def _document(self) -> dict[str, object]:
        return {
            "schema": SCHEMA,
            "revision": self._revision,
            "window_seconds": self.window_seconds,
            "signals": [item.as_dict() for item in self._signals],
            "matches": list(self._matches),
            "continuity": {
                "missing_since": self._missing_since,
                "missing_reasons": list(self._missing_reasons),
                "blind_sources": sorted(self._blind_sources),
                "overflow_at": self._overflow_at,
                "dropped": self._dropped,
            },
        }

    def _save(self) -> bool:
        if self._persistence_locked:
            return False
        self._revision += 1
        document = self._document()
        envelope = {
            "document": document,
            "hmac_sha256": hmac.new(
                self._state_key,
                b"angerona/temporal-state/v1\0" + _canonical(document),
                hashlib.sha256,
            ).hexdigest(),
        }
        try:
            _secure_state_write(self.path, _canonical(envelope))
        except OSError:
            self.persistence_status = "unavailable"
            self._persistence_locked = True
            self._blind_sources.add(
                _token(self._privacy_key, b"temporal-blind", "state-store", "sensor")
            )
            return False
        self.persistence_status = "authenticated"
        return True

    def _load(self) -> None:
        try:
            raw = _safe_state_read(self.path)
        except FileNotFoundError:
            self._missing_since = float(self._clock())
            self._missing_reasons.append("no-authenticated-restart-history")
            self.persistence_status = "missing"
            return
        except OSError:
            self.persistence_status = "untrusted"
            self._persistence_locked = True
            self._blind_sources.add(
                _token(self._privacy_key, b"temporal-blind", "state-store", "sensor")
            )
            return
        try:
            envelope = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
            if not isinstance(envelope, dict) or frozenset(envelope) != {
                "document", "hmac_sha256"
            }:
                raise TemporalTradecraftError("temporal state envelope is invalid")
            document = envelope["document"]
            signature = envelope["hmac_sha256"]
            if not isinstance(document, dict) or not isinstance(signature, str):
                raise TemporalTradecraftError("temporal state envelope is invalid")
            expected = hmac.new(
                self._state_key,
                b"angerona/temporal-state/v1\0" + _canonical(document),
                hashlib.sha256,
            ).hexdigest()
            if not _HEX_64.fullmatch(signature) or not hmac.compare_digest(signature, expected):
                raise TemporalTradecraftError("temporal state authentication failed")
            self._admit_document(document)
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            RecursionError,
            TemporalTradecraftError,
        ):
            self.persistence_status = "untrusted"
            self._persistence_locked = True
            self._signals.clear()
            self._matches.clear()
            self._blind_sources.add(
                _token(self._privacy_key, b"temporal-blind", "state-store", "sensor")
            )
            return
        self.persistence_status = "authenticated"
        self._prune(float(self._clock()))

    def _admit_document(self, document: Mapping[str, object]) -> None:
        if frozenset(document) != _STATE_FIELDS or document.get("schema") != SCHEMA:
            raise TemporalTradecraftError("temporal state schema is invalid")
        revision = document.get("revision")
        stored_window = document.get("window_seconds")
        if type(revision) is not int or revision < 0:
            raise TemporalTradecraftError("temporal state revision is invalid")
        if type(stored_window) is not int or stored_window != self.window_seconds:
            raise TemporalTradecraftError("temporal state window is invalid")
        rows = document.get("signals")
        matches = document.get("matches")
        continuity = document.get("continuity")
        if not isinstance(rows, list) or len(rows) > self.max_signals:
            raise TemporalTradecraftError("temporal signal count is invalid")
        if not isinstance(matches, list) or len(matches) > MAX_MATCHES:
            raise TemporalTradecraftError("temporal match count is invalid")
        if not isinstance(continuity, dict) or frozenset(continuity) != _CONTINUITY_FIELDS:
            raise TemporalTradecraftError("temporal continuity state is invalid")
        admitted: list[TemporalSignal] = []
        prior = float("-inf")
        for row in rows:
            if not isinstance(row, dict) or frozenset(row) != _SIGNAL_FIELDS:
                raise TemporalTradecraftError("temporal signal schema is invalid")
            kind = row.get("kind")
            observed_at = row.get("observed_at")
            evidence_digest = row.get("evidence_digest")
            source_token = row.get("source_token")
            grade = row.get("evidence_grade")
            attestation = row.get("attestation")
            if (
                kind not in _KINDS
                or type(observed_at) not in (int, float)
                or not math.isfinite(float(observed_at))
                or not _HEX_64.fullmatch(str(evidence_digest))
                or not _TOKEN.fullmatch(str(source_token))
                or grade not in _EVIDENCE_GRADES
                or not _HEX_64.fullmatch(str(attestation))
                or float(observed_at) < prior
            ):
                raise TemporalTradecraftError("temporal signal value is invalid")
            signal = TemporalSignal(
                str(kind),
                float(observed_at),
                str(evidence_digest),
                str(source_token),
                str(grade),
                str(attestation),
            )
            if not hmac.compare_digest(signal.attestation, self._attest_signal(self._signal_payload(signal))):
                raise TemporalTradecraftError("temporal signal authentication failed")
            prior = signal.observed_at
            admitted.append(signal)
        if any(not isinstance(item, str) or len(item) > 160 for item in matches):
            raise TemporalTradecraftError("temporal match identity is invalid")
        missing_since = continuity.get("missing_since")
        overflow_at = continuity.get("overflow_at")
        if missing_since is not None and type(missing_since) not in (int, float):
            raise TemporalTradecraftError("temporal missing timestamp is invalid")
        if overflow_at is not None and type(overflow_at) not in (int, float):
            raise TemporalTradecraftError("temporal overflow timestamp is invalid")
        reasons = continuity.get("missing_reasons")
        blind = continuity.get("blind_sources")
        dropped = continuity.get("dropped")
        if (
            not isinstance(reasons, list)
            or len(reasons) > MAX_REASONS
            or any(not isinstance(item, str) or not item or len(item) > 96 for item in reasons)
            or not isinstance(blind, list)
            or len(blind) > MAX_REASONS
            or any(not isinstance(item, str) or not _TOKEN.fullmatch(item) for item in blind)
            or type(dropped) is not int
            or dropped < 0
        ):
            raise TemporalTradecraftError("temporal continuity values are invalid")
        self._revision = revision
        self._signals = deque(admitted)
        self._matches = deque(matches, maxlen=MAX_MATCHES)
        self._missing_since = None if missing_since is None else float(missing_since)
        self._missing_reasons = deque(reasons, maxlen=MAX_REASONS)
        self._blind_sources = set(blind)
        self._overflow_at = None if overflow_at is None else float(overflow_at)
        self._dropped = dropped

    def _prune(self, now: float) -> None:
        cutoff = now - self.window_seconds
        while self._signals and self._signals[0].observed_at < cutoff:
            self._signals.popleft()
        if self._overflow_at is not None and self._overflow_at < cutoff:
            self._overflow_at = None
        if self._missing_since is not None and self._missing_since < cutoff:
            self._missing_since = None
            self._missing_reasons.clear()

    def _continuity_state(self) -> tuple[str, str]:
        if self.persistence_status in {"untrusted", "unavailable"}:
            return "blind", "authenticated temporal restart state is unavailable"
        if self._blind_sources:
            return "blind", "one or more admitted sensor sources are blind or unauthenticated"
        if self._overflow_at is not None:
            return "overflow", "bounded temporal evidence capacity was exceeded"
        if self._missing_since is not None:
            return "missing", "; ".join(self._missing_reasons) or "temporal history is incomplete"
        return "observing", "bounded temporal evidence is continuous within the current window"

    def _missing_steps(self) -> tuple[str, ...]:
        best: tuple[str, ...] = ()
        kinds = [item.kind for item in self._signals]
        for pattern in PATTERNS:
            position = 0
            for kind in kinds:
                if position < len(pattern.steps) and kind == pattern.steps[position]:
                    position += 1
            remaining = pattern.steps[position:]
            if position and (not best or len(remaining) < len(best)):
                best = remaining
        return best

    def _assessment(
        self,
        *,
        findings: Iterable[TemporalFinding] = (),
        fallback_state: str = "observing",
        fallback_reason: str = "no complete temporal tradecraft sequence",
    ) -> TemporalAssessment:
        found = tuple(findings)
        state, reason = self._continuity_state()
        if state == "observing":
            state = "match" if found else fallback_state
            reason = "one or more ordered patterns completed" if found else fallback_reason
        return TemporalAssessment(
            state=state,
            reason=reason,
            findings=found,
            missing_steps=self._missing_steps(),
            retained_signals=len(self._signals),
            dropped_signals=self._dropped,
            persistence_status=self.persistence_status,
            response_authorized=False,
        )

    def classify(self, event: Event) -> str | None:
        return _classify_event(event)

    def observe_event(
        self,
        event: Event,
        *,
        integrity_verified: bool,
        evidence_grade: str = "unprovenanced",
    ) -> TemporalAssessment:
        try:
            signal = self.prepare_event(
                event,
                integrity_verified=integrity_verified,
                evidence_grade=evidence_grade,
            )
        except TemporalTradecraftError as exc:
            if str(exc) == "event-authentication-failed":
                return self.mark_blind(event.module, reason=str(exc))
            return self.mark_missing(str(exc))
        if signal is None:
            return self._assessment()
        return self.observe(signal)

    def prepare_event(
        self,
        event: Event,
        *,
        integrity_verified: bool,
        evidence_grade: str = "unprovenanced",
    ) -> TemporalSignal | None:
        """Tokenize one fixed-schema event for a raw-free bounded work queue."""
        kind = _classify_event(event)
        if kind is None:
            return None
        now = float(self._clock())
        stamp = float(event.ts)
        if (
            not math.isfinite(now)
            or not math.isfinite(stamp)
            or stamp > now + MAX_EVENT_SKEW_SECONDS
            or stamp < now - MAX_WINDOW_SECONDS
        ):
            raise TemporalTradecraftError("stale-or-future-temporal-evidence")
        if not integrity_verified:
            raise TemporalTradecraftError("event-authentication-failed")
        if evidence_grade not in _EVIDENCE_GRADES:
            raise TemporalTradecraftError("event-provenance-grade-invalid")
        details = event.details if isinstance(event.details, dict) else {}
        code = str(
            details.get("finding_code") or details.get("finding_type") or ""
        )[:128]
        classification = str(details.get("classification") or "")[:128]
        # Hash any already-tokenized correlation hints again.  This deliberately
        # never stores or emits the supplied values, even if a producer violated
        # its own privacy contract and mislabeled a raw identifier as a token.
        correlation_hints = []
        for key in (
            "account_token", "source_token", "subject_token", "process_token",
            "listener_token", "path_token", "interface_token",
        ):
            value = details.get(key)
            if isinstance(value, (str, int)):
                correlation_hints.append(_token(
                    self._privacy_key, b"temporal-hint", f"{key}:{value}", "hint"
                ))
        evidence_digest = _digest(
            self._privacy_key,
            b"temporal-evidence",
            {
                "module_token": _token(
                    self._privacy_key, b"temporal-module", event.module, "source"
                ),
                "kind": kind,
                "code": code,
                "classification": classification,
                "observed_at": stamp,
                "event_auth": event.hmac_sig[:64] if event.hmac_sig else "unarmed",
                "hints": sorted(correlation_hints),
            },
        )
        source_token = _token(
            self._privacy_key, b"temporal-module", event.module, "source"
        )
        grade = evidence_grade
        payload = {
            "kind": kind,
            "observed_at": stamp,
            "evidence_digest": evidence_digest,
            "source_token": source_token,
            "evidence_grade": grade,
        }
        return TemporalSignal(
            kind=kind,
            observed_at=stamp,
            evidence_digest=evidence_digest,
            source_token=source_token,
            evidence_grade=grade,
            attestation=self._attest_signal(payload),
        )

    def observe(self, signal: TemporalSignal) -> TemporalAssessment:
        now = float(self._clock())
        if signal.kind not in _KINDS:
            raise TemporalTradecraftError("temporal signal kind is not admitted")
        if not hmac.compare_digest(signal.attestation, self._attest_signal(self._signal_payload(signal))):
            return self.mark_blind(signal.source_token, reason="signal-authentication-failed")
        if (
            not math.isfinite(now)
            or not math.isfinite(signal.observed_at)
            or signal.observed_at > now + MAX_EVENT_SKEW_SECONDS
            or signal.observed_at < now - MAX_WINDOW_SECONDS
        ):
            return self.mark_missing("stale-or-future-temporal-evidence", now=now)
        if any(item.evidence_digest == signal.evidence_digest for item in self._signals):
            return self._assessment(fallback_reason="duplicate temporal evidence was ignored")
        if self._signals and signal.observed_at < self._signals[-1].observed_at:
            return self.mark_missing("non-monotonic-temporal-evidence", now=now)
        self._signals.append(signal)
        if len(self._signals) > self.max_signals:
            self._signals.popleft()
            self._dropped += 1
            self._overflow_at = now
        self._prune(now)
        findings: list[TemporalFinding] = []
        for pattern in PATTERNS:
            selected: list[TemporalSignal] = []
            position = 0
            for item in self._signals:
                if position < len(pattern.steps) and item.kind == pattern.steps[position]:
                    selected.append(item)
                    position += 1
            if position != len(pattern.steps):
                continue
            match_id = pattern.pattern_id + ":" + selected[-1].evidence_digest
            if match_id in self._matches:
                continue
            self._matches.append(match_id)
            if all(item.evidence_grade == "broker-provenanced" for item in selected):
                grade = "broker-provenanced"
            elif all(
                item.evidence_grade in {"broker-provenanced", "schema-admitted-local"}
                for item in selected
            ):
                grade = "schema-admitted-local"
            else:
                grade = "unprovenanced"
            severity = pattern.severity if grade == "broker-provenanced" else "Medium"
            findings.append(TemporalFinding(
                pattern_id=pattern.pattern_id,
                severity=severity,
                summary=pattern.summary,
                started_at=selected[0].observed_at,
                ended_at=selected[-1].observed_at,
                signal_kinds=tuple(item.kind for item in selected),
                evidence_digests=tuple(item.evidence_digest for item in selected),
                evidence_grade=grade,
                response_authorized=False,
            ))
        self._save()
        return self._assessment(findings=findings)

    def mark_missing(self, reason: str, *, now: float | None = None) -> TemporalAssessment:
        cleaned = str(reason).strip()[:96] or "unspecified-evidence-gap"
        current = float(self._clock()) if now is None else float(now)
        before = (self._missing_since, tuple(self._missing_reasons))
        self._missing_since = current if self._missing_since is None else self._missing_since
        if cleaned not in self._missing_reasons:
            self._missing_reasons.append(cleaned)
        if before != (self._missing_since, tuple(self._missing_reasons)):
            self._save()
        return self._assessment()

    def mark_blind(self, source: object, *, reason: str = "sensor-blind") -> TemporalAssessment:
        source_text = str(source)
        token = source_text if _TOKEN.fullmatch(source_text) else _token(
            self._privacy_key, b"temporal-blind", source_text, "sensor"
        )
        before = (frozenset(self._blind_sources), tuple(self._missing_reasons))
        self._blind_sources.add(token)
        cleaned = str(reason).strip()[:96]
        if cleaned and cleaned not in self._missing_reasons:
            self._missing_reasons.append(cleaned)
        if before != (frozenset(self._blind_sources), tuple(self._missing_reasons)):
            self._save()
        return self._assessment()

    def mark_recovered(self, source: object) -> TemporalAssessment:
        source_text = str(source)
        token = source_text if _TOKEN.fullmatch(source_text) else _token(
            self._privacy_key, b"temporal-blind", source_text, "sensor"
        )
        changed = token in self._blind_sources
        self._blind_sources.discard(token)
        if changed:
            self._save()
        return self._assessment(fallback_reason="sensor recovery recorded; prior gaps remain explicit")

    def mark_overflow(self, dropped: int = 1) -> TemporalAssessment:
        self._dropped += max(1, int(dropped))
        self._overflow_at = float(self._clock())
        self._save()
        return self._assessment()

    def note_restart_gap(self) -> TemporalAssessment:
        return self.mark_missing("module-restart-observation-gap")

    def tick(self) -> TemporalAssessment:
        """Advance only time-based bounds; never manufacture source evidence."""
        before = (
            len(self._signals), self._missing_since, self._overflow_at,
            tuple(self._missing_reasons),
        )
        self._prune(float(self._clock()))
        after = (
            len(self._signals), self._missing_since, self._overflow_at,
            tuple(self._missing_reasons),
        )
        if after != before:
            self._save()
        return self._assessment()

    @property
    def retained_signals(self) -> tuple[TemporalSignal, ...]:
        return tuple(self._signals)


__all__ = [
    "MAX_SIGNALS",
    "MAX_WINDOW_SECONDS",
    "PATTERNS",
    "TemporalAssessment",
    "TemporalFinding",
    "TemporalPattern",
    "TemporalSignal",
    "TemporalTradecraftEngine",
    "TemporalTradecraftError",
    "derive_temporal_keys",
    "load_temporal_keys",
]
