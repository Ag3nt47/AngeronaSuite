"""Privacy-minimized identity and session transition analytics.

This module consumes structured evidence supplied by other sensors.  It does
not read browser databases, authentication tokens, credentials, or cloud APIs.
Raw identifiers exist only in the caller-owned input object long enough to be
purpose-keyed; retained state and findings contain pseudonyms exclusively.
"""
from __future__ import annotations

from collections import OrderedDict, deque
from dataclasses import dataclass
import hashlib
import hmac
import math
from pathlib import Path
import re
import time
from typing import Final, Mapping


SCHEMA: Final = "angerona.identity-session-evidence.v1"
MAX_EVENTS: Final = 4096
MAX_WINDOW_SECONDS: Final = 60 * 60
MAX_EVENT_SKEW_SECONDS: Final = 5 * 60
MAX_ASSOCIATIONS: Final = 4096
_KINDS = frozenset({
    "logon_session",
    "session_end",
    "device_code_flow",
    "new_device",
    "browser_token_store_access",
    "rmm_session",
    "privilege_change",
})
_OUTCOMES = frozenset({"attempt", "success", "denied", "unknown"})
_SECRET_SHAPE = re.compile(
    r"(?i)^(?:bearer\s+|eyJ[a-z0-9_-]{8,}\.|(?:sk|gh[pousr]_)[a-z0-9_-]{8,}|"
    r"[a-z0-9+/]{40,}={0,2}$)|(?:password|passwd|secret|access[_ -]?token|"
    r"refresh[_ -]?token|authorization)\s*[:=]"
)
_PSEUDONYM = re.compile(r"^[a-z][a-z0-9_-]{0,15}:v1:[0-9a-f]{32}$")


class IdentitySessionError(ValueError):
    """Supplied identity/session evidence violated the admission contract."""


def _bounded_ref(value: object, label: str, *, required: bool = False) -> str:
    if value is None:
        text = ""
    elif isinstance(value, (str, int)) and not isinstance(value, bool):
        text = str(value)
    else:
        raise IdentitySessionError(f"{label} must be a bounded identifier")
    if text != text.strip() or len(text) > 320 or any(ord(char) < 32 for char in text):
        raise IdentitySessionError(f"{label} must be a bounded identifier")
    if required and not text:
        raise IdentitySessionError(f"{label} is required")
    if text and _SECRET_SHAPE.search(text):
        raise IdentitySessionError(f"{label} resembles secret or token material")
    return text


def _pseudonym(key: bytes, namespace: bytes, value: str, prefix: str) -> str:
    if not value:
        return ""
    digest = hmac.new(
        key,
        namespace + b"\0" + value.casefold().encode("utf-8", "surrogatepass"),
        hashlib.sha256,
    ).hexdigest()
    return f"{prefix}:v1:{digest[:32]}"


def derive_identity_session_key(master_key: bytes) -> bytes:
    if not isinstance(master_key, bytes) or len(master_key) != 32:
        raise ValueError("identity-session master key must contain exactly 32 bytes")
    return hmac.new(
        master_key,
        b"angerona/identity-session-privacy/v1",
        hashlib.sha256,
    ).digest()


def load_identity_session_key(
    data_root: str | Path,
    *,
    master_key: bytes | None = None,
) -> bytes | None:
    """Load but never create/rotate the installation key."""
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
    return derive_identity_session_key(value)


@dataclass(frozen=True)
class IdentitySessionEvidence:
    """Caller-supplied metadata only; no secret/token value field exists."""

    timestamp: float
    kind: str
    principal_ref: str = ""
    luid: str = ""
    session_ref: str = ""
    device_ref: str = ""
    source_ref: str = ""
    process_ref: str = ""
    outcome: str = "unknown"
    privileged: bool = False
    remote: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.timestamp) not in (int, float)
            or not math.isfinite(float(self.timestamp))
        ):
            raise IdentitySessionError("timestamp is invalid")
        if self.kind not in _KINDS:
            raise IdentitySessionError("identity/session evidence kind is unsupported")
        if self.outcome not in _OUTCOMES:
            raise IdentitySessionError("identity/session outcome is unsupported")
        if type(self.privileged) is not bool or type(self.remote) is not bool:
            raise IdentitySessionError("identity/session flags must be booleans")
        principal = _bounded_ref(self.principal_ref, "principal_ref")
        luid = _bounded_ref(self.luid, "luid")
        session = _bounded_ref(self.session_ref, "session_ref")
        device = _bounded_ref(self.device_ref, "device_ref")
        source = _bounded_ref(self.source_ref, "source_ref")
        process = _bounded_ref(self.process_ref, "process_ref")
        if self.kind in {
            "logon_session", "device_code_flow", "new_device", "privilege_change"
        } and not principal:
            raise IdentitySessionError("principal_ref is required for this evidence kind")
        if self.kind in {"logon_session", "session_end"} and not (luid or session):
            raise IdentitySessionError("logon/session evidence requires a LUID or session reference")
        if self.kind == "new_device" and not device:
            raise IdentitySessionError("new-device evidence requires a device reference")
        if self.kind == "browser_token_store_access" and not process:
            raise IdentitySessionError("browser-store evidence requires a process reference")
        if self.kind == "rmm_session" and not (session or source or process):
            raise IdentitySessionError("RMM evidence requires a session, source, or process reference")


@dataclass(frozen=True)
class TokenizedSessionEvent:
    timestamp: float
    kind: str
    principal_token: str
    luid_token: str
    session_token: str
    device_token: str
    source_token: str
    process_token: str
    outcome: str
    privileged: bool
    remote: bool
    evidence_grade: str
    event_digest: str


@dataclass(frozen=True)
class IdentitySessionFinding:
    rule_id: str
    severity: str
    reason: str
    principal_token: str
    session_token: str
    device_token: str
    evidence_count: int
    evidence_grade: str
    response_authorized: bool = False


@dataclass(frozen=True)
class IdentitySessionAssessment:
    state: str
    reason: str
    findings: tuple[IdentitySessionFinding, ...]
    retained_events: int
    dropped_events: int
    raw_values_retained: bool = False
    response_authorized: bool = False


def evidence_from_mapping(value: Mapping[str, object]) -> IdentitySessionEvidence:
    """Strictly admit a structured producer envelope."""
    allowed = frozenset({
        "schema", "timestamp", "kind", "principal_ref", "luid", "session_ref",
        "device_ref", "source_ref", "process_ref", "outcome", "privileged", "remote",
    })
    if not isinstance(value, Mapping) or not frozenset(value).issubset(allowed):
        raise IdentitySessionError("identity/session evidence schema has unknown fields")
    if value.get("schema") != SCHEMA:
        raise IdentitySessionError("identity/session evidence schema is unsupported")
    if "timestamp" not in value or "kind" not in value:
        raise IdentitySessionError("identity/session evidence is missing required fields")
    return IdentitySessionEvidence(
        timestamp=value["timestamp"],  # type: ignore[arg-type]
        kind=value["kind"],  # type: ignore[arg-type]
        principal_ref=value.get("principal_ref", ""),  # type: ignore[arg-type]
        luid=value.get("luid", ""),  # type: ignore[arg-type]
        session_ref=value.get("session_ref", ""),  # type: ignore[arg-type]
        device_ref=value.get("device_ref", ""),  # type: ignore[arg-type]
        source_ref=value.get("source_ref", ""),  # type: ignore[arg-type]
        process_ref=value.get("process_ref", ""),  # type: ignore[arg-type]
        outcome=value.get("outcome", "unknown"),  # type: ignore[arg-type]
        privileged=value.get("privileged", False),  # type: ignore[arg-type]
        remote=value.get("remote", False),  # type: ignore[arg-type]
    )


class IdentitySessionAnalytics:
    """Fixed-memory transition analytics over tokenized supplied evidence."""

    def __init__(
        self,
        privacy_key: bytes,
        *,
        window_seconds: int = 15 * 60,
        max_events: int = MAX_EVENTS,
        clock=time.time,
    ) -> None:
        if not isinstance(privacy_key, bytes) or len(privacy_key) < 32:
            raise ValueError("identity-session privacy key must contain at least 32 bytes")
        if not 60 <= int(window_seconds) <= MAX_WINDOW_SECONDS:
            raise ValueError("identity-session window must be between 60 and 3600 seconds")
        self._key = bytes(privacy_key)
        self.window_seconds = int(window_seconds)
        self.max_events = max(32, min(int(max_events), MAX_EVENTS))
        self._clock = clock
        self._events: deque[TokenizedSessionEvent] = deque()
        # The deque remains the authoritative ordered evidence window.  This
        # companion index only avoids a second linear walk for replay checks;
        # every capacity/time eviction removes the same digest immediately.
        self._event_digests: set[str] = set()
        self._luid_owners: OrderedDict[str, tuple[str, str, float]] = OrderedDict()
        self._session_owners: OrderedDict[str, tuple[str, str, float]] = OrderedDict()
        self._known_devices: OrderedDict[str, None] = OrderedDict()
        self._dropped = 0
        self._coverage_state = "observing"
        self._coverage_reason = "supplied identity/session evidence is admitted"

    def tokenize(
        self,
        evidence: IdentitySessionEvidence,
        *,
        evidence_grade: str = "unprovenanced",
    ) -> TokenizedSessionEvent:
        if evidence_grade not in {
            "broker-provenanced",
            "schema-admitted-local",
            "unprovenanced",
            # Migration-only grades from the pre-provenance implementation.
            "authenticated-bus",
            "local-unarmed",
        }:
            raise IdentitySessionError("identity/session evidence grade is unsupported")
        tokens = {
            "principal_token": _pseudonym(
                self._key, b"identity-principal", evidence.principal_ref, "principal"
            ),
            "luid_token": _pseudonym(self._key, b"identity-luid", evidence.luid, "luid"),
            "session_token": _pseudonym(
                self._key, b"identity-session", evidence.session_ref, "session"
            ),
            "device_token": _pseudonym(
                self._key, b"identity-device", evidence.device_ref, "device"
            ),
            "source_token": _pseudonym(
                self._key, b"identity-source", evidence.source_ref, "source"
            ),
            "process_token": _pseudonym(
                self._key, b"identity-process", evidence.process_ref, "process"
            ),
        }
        canonical = "|".join((
            evidence.kind,
            f"{float(evidence.timestamp):.6f}",
            *tokens.values(),
            evidence.outcome,
            "1" if evidence.privileged else "0",
            "1" if evidence.remote else "0",
            evidence_grade,
        ))
        event_digest = hmac.new(
            self._key,
            b"angerona/identity-session-event/v1\0" + canonical.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return TokenizedSessionEvent(
            timestamp=float(evidence.timestamp),
            kind=evidence.kind,
            outcome=evidence.outcome,
            privileged=evidence.privileged,
            remote=evidence.remote,
            evidence_grade=evidence_grade,
            event_digest=event_digest,
            **tokens,
        )

    @staticmethod
    def _related(first: TokenizedSessionEvent, second: TokenizedSessionEvent) -> bool:
        pairs = (
            (first.principal_token, second.principal_token),
            (first.luid_token, second.luid_token),
            (first.session_token, second.session_token),
            (first.device_token, second.device_token),
        )
        return any(left and right and hmac.compare_digest(left, right) for left, right in pairs)

    @staticmethod
    def _grade(rows: tuple[TokenizedSessionEvent, ...]) -> str:
        if rows and all(item.evidence_grade == "broker-provenanced" for item in rows):
            return "broker-provenanced"
        if rows and all(
            item.evidence_grade in {"broker-provenanced", "schema-admitted-local"}
            for item in rows
        ):
            return "schema-admitted-local"
        return "unprovenanced"

    @staticmethod
    def _finding(
        rule_id: str,
        severity: str,
        reason: str,
        rows: tuple[TokenizedSessionEvent, ...],
    ) -> IdentitySessionFinding:
        last = rows[-1]
        grade = IdentitySessionAnalytics._grade(rows)
        return IdentitySessionFinding(
            rule_id=rule_id,
            severity=severity if grade == "broker-provenanced" else "Medium",
            reason=reason,
            principal_token=last.principal_token,
            session_token=last.session_token or last.luid_token,
            device_token=last.device_token,
            evidence_count=len(rows),
            evidence_grade=grade,
            response_authorized=False,
        )

    def _bounded_association(
        self,
        store: OrderedDict[str, tuple[str, str, float]],
        key: str,
        owner: tuple[str, str],
        observed_at: float,
    ) -> tuple[str, str] | None:
        if not key:
            return None
        retained = store.get(key)
        previous = None
        if retained is not None and retained[2] >= observed_at - self.window_seconds:
            previous = retained[:2]
        store[key] = (*owner, observed_at)
        store.move_to_end(key)
        while len(store) > MAX_ASSOCIATIONS:
            store.popitem(last=False)
        return previous

    def observe(
        self,
        evidence: IdentitySessionEvidence | TokenizedSessionEvent,
        *,
        evidence_grade: str = "unprovenanced",
    ) -> IdentitySessionAssessment:
        row = (
            evidence
            if isinstance(evidence, TokenizedSessionEvent)
            else self.tokenize(evidence, evidence_grade=evidence_grade)
        )
        now = float(self._clock())
        if (
            not math.isfinite(now)
            or not math.isfinite(row.timestamp)
            or row.timestamp > now + MAX_EVENT_SKEW_SECONDS
            or row.timestamp < now - MAX_WINDOW_SECONDS
        ):
            return self.mark_coverage("missing", "stale-or-future identity/session evidence")
        if row.event_digest in self._event_digests:
            return self._assessment((), "duplicate tokenized evidence was ignored")
        self._events.append(row)
        self._event_digests.add(row.event_digest)
        if len(self._events) > self.max_events:
            evicted = self._events.popleft()
            self._event_digests.discard(evicted.event_digest)
            self._dropped += 1
            self._coverage_state = "overflow"
            self._coverage_reason = "identity/session evidence capacity was exceeded"
        cutoff = now - self.window_seconds
        while self._events and self._events[0].timestamp < cutoff:
            evicted = self._events.popleft()
            self._event_digests.discard(evicted.event_digest)

        findings: list[IdentitySessionFinding] = []
        owner = (row.principal_token, row.device_token)
        if row.kind == "session_end":
            if row.luid_token:
                self._luid_owners.pop(row.luid_token, None)
            if row.session_token:
                self._session_owners.pop(row.session_token, None)
            previous_luid = None
            previous_session = None
        else:
            previous_luid = self._bounded_association(
                self._luid_owners, row.luid_token, owner, row.timestamp
            )
            previous_session = self._bounded_association(
                self._session_owners, row.session_token, owner, row.timestamp
            )
        for rule_id, previous in (
            ("identity_session.luid_rebinding", previous_luid),
            ("identity_session.session_rebinding", previous_session),
        ):
            if previous is not None and previous != owner and any(owner) and any(previous):
                findings.append(self._finding(
                    rule_id,
                    "Critical",
                    "A live logon/session reference was rebound to a different principal or device.",
                    (row,),
                ))

        prior = tuple(
            item for item in self._events
            if item is not row and self._related(item, row)
        )
        effective = row.outcome in {"success", "unknown"}
        if row.kind == "new_device" and effective:
            known = row.device_token in self._known_devices
            self._known_devices[row.device_token] = None
            self._known_devices.move_to_end(row.device_token)
            while len(self._known_devices) > MAX_ASSOCIATIONS:
                self._known_devices.popitem(last=False)
            if not known:
                findings.append(self._finding(
                    "identity_session.new_device_enrollment",
                    "High" if row.privileged else "Medium",
                    "A newly observed device was enrolled for this principal.",
                    (row,),
                ))
            device_code = next(
                (
                    item for item in reversed(prior)
                    if item.kind == "device_code_flow" and item.outcome != "denied"
                ),
                None,
            )
            if device_code is not None:
                findings.append(self._finding(
                    "identity_session.device_code_new_device",
                    "Critical",
                    "A device-code flow was followed by new-device enrollment.",
                    (device_code, row),
                ))
        if effective and row.kind in {
            "logon_session", "new_device", "rmm_session", "privilege_change"
        }:
            browser = next(
                (
                    item for item in reversed(prior)
                    if item.kind == "browser_token_store_access"
                    and item.outcome != "denied"
                ),
                None,
            )
            if browser is not None:
                findings.append(self._finding(
                    "identity_session.browser_store_transition",
                    "Critical" if row.privileged else "High",
                    "Browser credential-store access preceded an identity/session transition.",
                    (browser, row),
                ))
        if row.kind == "privilege_change" and effective:
            rmm = next(
                (
                    item for item in reversed(prior)
                    if item.kind == "rmm_session" and item.outcome != "denied"
                ),
                None,
            )
            if rmm is not None:
                findings.append(self._finding(
                    "identity_session.rmm_privilege_transition",
                    "Critical",
                    "An RMM session preceded a privilege transition.",
                    (rmm, row),
                ))
            if row.remote:
                findings.append(self._finding(
                    "identity_session.remote_privilege_transition",
                    "High",
                    "A supplied remote-session signal included a privilege transition.",
                    (row,),
                ))
        if row.kind == "device_code_flow" and row.privileged:
            findings.append(self._finding(
                "identity_session.privileged_device_code_flow",
                "High",
                "A privileged principal entered a device-code authentication flow.",
                (row,),
            ))
        return self._assessment(tuple(findings), "identity/session transition admitted")

    def mark_coverage(self, state: str, reason: str) -> IdentitySessionAssessment:
        if state not in {"observing", "missing", "blind", "overflow"}:
            raise IdentitySessionError("identity/session coverage state is unsupported")
        self._coverage_state = state
        self._coverage_reason = str(reason).strip()[:160] or "coverage state changed"
        return self._assessment((), self._coverage_reason)

    def _assessment(
        self,
        findings: tuple[IdentitySessionFinding, ...],
        reason: str,
    ) -> IdentitySessionAssessment:
        state = self._coverage_state
        rendered_reason = self._coverage_reason if state != "observing" else reason
        if state == "observing" and findings:
            state = "finding"
            rendered_reason = "one or more identity/session transition rules matched"
        return IdentitySessionAssessment(
            state=state,
            reason=rendered_reason,
            findings=findings,
            retained_events=len(self._events),
            dropped_events=self._dropped,
            raw_values_retained=False,
            response_authorized=False,
        )

    @property
    def retained_events(self) -> tuple[TokenizedSessionEvent, ...]:
        return tuple(self._events)


__all__ = [
    "IdentitySessionAnalytics",
    "IdentitySessionAssessment",
    "IdentitySessionError",
    "IdentitySessionEvidence",
    "IdentitySessionFinding",
    "MAX_EVENTS",
    "SCHEMA",
    "TokenizedSessionEvent",
    "derive_identity_session_key",
    "evidence_from_mapping",
    "load_identity_session_key",
]
