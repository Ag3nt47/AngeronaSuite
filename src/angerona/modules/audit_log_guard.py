"""Windows audit-log continuity and tamper guard.

The guard watches explicit clearing/policy/service events and independently
anchors each channel generation.  It is observation-only: fixtures and live
code never clear a log or change audit policy.
"""
from __future__ import annotations

import hmac
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Protocol

from angerona.core.event_log_integrity import (
    AuditEventRejected,
    AuditIntegrityRecord,
    AuthenticatedEventLogCheckpoint,
    ChannelCheckpoint,
    assess_continuity,
    audit_event_selectors,
    parse_audit_integrity_xml,
)
from angerona.core.independent_high_water import IndependentHighWater
from angerona.core.module_base import BaseModule, Severity
from angerona.core.windows_event_log import WindowsEventLogSource, _record_id_from_xml


class EventSource(Protocol):
    def oldest_record_id(self) -> int: ...
    def newest_record_id(self) -> int: ...
    def record_anchor(self, record_id: int) -> str: ...
    def read_after(self, record_id: int, limit: int) -> list[str]: ...
    def close(self) -> None: ...


_CHANNELS: tuple[tuple[str, tuple[int, ...]], ...] = (
    ("Security", (1100, 1102, 1104, 1108, 4612, 4719, 4902, 4906, 4907, 4912)),
    ("System", (104,)),
    ("Microsoft-Windows-Sysmon/Operational", (4, 16, 255)),
)
_BATCH = 128
_POLL_SECONDS = 4.0
_SEVERITY = {
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


@dataclass(frozen=True)
class _PendingTransition:
    channel: str
    source: EventSource
    guard_record_id: int
    guard_anchor: str
    terminal_record_id: int
    terminal_anchor: str
    reached_observed_terminal: bool
    records: tuple[AuditIntegrityRecord, ...]
    rejected_reason_codes: tuple[str, ...]


class AuditLogIntegrityGuard(BaseModule):
    CODE = "ALIG"
    NAME = "Audit Log Integrity Guard"
    name = "Audit Log Integrity Guard"
    description = (
        "Detects Windows log clearing, audit-policy drift, service impairment, "
        "retention gaps, record reuse, and authenticated cursor tampering."
    )
    category = "Telemetry"
    version = "1.0.0"
    supported_platforms = frozenset({"windows"})
    capability_mode = "observe"
    platform_requirements = ("Windows Event Log read access",)

    def __init__(
        self,
        *,
        sources: Mapping[str, EventSource] | None = None,
        data_root: Path | None = None,
        checkpoint_key: bytes | None = None,
        high_water: IndependentHighWater | None = None,
    ) -> None:
        super().__init__()
        if checkpoint_key is not None and (
            not isinstance(checkpoint_key, bytes) or len(checkpoint_key) != 32
        ):
            raise ValueError("audit-log checkpoint key must contain 32 bytes")
        self._provided_sources = dict(sources or {})
        self._sources: dict[str, EventSource] = {}
        self._owns_sources: set[str] = set()
        self._data_root = Path(data_root) if data_root is not None else None
        self._checkpoint_key = checkpoint_key
        self._high_water = high_water
        self._checkpoint_store: AuthenticatedEventLogCheckpoint | None = None
        self._checkpoints: dict[str, ChannelCheckpoint] | None = None
        self._checkpoint_status = "missing"
        self._coverage_complete = False
        self._blind_reported: set[str] = set()
        self._events_seen = 0
        self._gaps_seen = 0
        self._freshness_reported = ""

    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    @property
    def _checkpoint_path(self) -> Path:
        if self._data_root is None:
            from angerona.core.data_paths import data_dir

            root = data_dir()
        else:
            root = self._data_root
        return root / "sensor-cursors" / "audit-log-integrity.json"

    @property
    def _checkpoint(self) -> AuthenticatedEventLogCheckpoint:
        if self._checkpoint_store is None:
            self._checkpoint_store = AuthenticatedEventLogCheckpoint(
                self._checkpoint_path,
                authority_key=self._checkpoint_key,
                high_water=self._high_water,
            )
        return self._checkpoint_store

    def _source(self, channel: str, event_ids: tuple[int, ...]) -> EventSource:
        if channel in self._sources:
            return self._sources[channel]
        source = self._provided_sources.get(channel)
        if source is None:
            source = WindowsEventLogSource(
                channel,
                event_ids,
                providers_by_event=audit_event_selectors(channel),
            )
            self._owns_sources.add(channel)
        self._sources[channel] = source
        return source

    def _emit_health(self, message: str, state: str, *, channel: str, **details) -> None:
        self.emit(
            message,
            Severity.HIGH,
            source_channel=channel,
            sensor_state=state,
            telemetry_quality="untrusted" if state == "untrusted" else "gap",
            response_authorized=False,
            response_authority="observe-only",
            mitre_tags=["T1070.001", "T1562.002"],
            **details,
        )

    def _emit_record(self, record) -> None:
        severity = _SEVERITY.get(record.severity, Severity.MEDIUM)
        self.emit(
            f"Audit integrity signal: {record.reason}",
            severity,
            source_channel=record.channel,
            provider=record.provider,
            event_id=record.event_id,
            record_id=record.record_id,
            created_at=record.created_at,
            classification=record.classification,
            admitted_fields=dict(record.fields),
            raw_event_omitted=True,
            response_authorized=False,
            response_authority="observe-only",
            state_grade_tradecraft_pattern=True,
            attribution="not-assessed",
            mitre_tags=["T1070.001", "T1562.002"],
        )
        self._events_seen += 1

    def _load_checkpoint(self) -> None:
        if self._checkpoints is not None:
            return
        self._checkpoints, self._checkpoint_status = self._checkpoint.load()
        self._coverage_complete = self._checkpoint.coverage_complete
        self._report_freshness()
        if self._checkpoint_status == "first-enrollment":
            self.set_health(55, "audit-log retained-evidence enrollment is in progress")
            self.emit(
                "Audit-log integrity coverage enrollment started with bounded retained-evidence replay",
                Severity.INFO,
                schema="angerona.audit-log-coverage.v1",
                sensor_state="provisional",
                replay_batch_size=_BATCH,
                replay_scope="oldest-retained-to-stable-terminal",
                coverage_complete=False,
                raw_event_omitted=True,
                response_authorized=False,
                response_authority="observe-only",
            )
        if self._checkpoint_status == "untrusted":
            self.set_health(25, "audit-log continuity checkpoint is untrusted")
            self._emit_health(
                "Audit-log continuity checkpoint authentication failed",
                "untrusted",
                channel="all",
                replay_retained_evidence=True,
            )

    def _report_freshness(self) -> None:
        freshness = self._checkpoint.freshness_status
        if freshness == self._freshness_reported:
            return
        self._freshness_reported = freshness
        if self._checkpoint.independent_freshness_verified:
            return
        self.set_health(45, "audit-log state has no independently verified freshness")
        self.emit(
            "Audit-log checkpoint local authenticity is separate from independent freshness",
            Severity.MEDIUM,
            schema="angerona.state-high-water.v1",
            state_domain="audit-log-continuity",
            freshness_status=freshness,
            independently_fresh=False,
            raw_event_omitted=True,
            response_authorized=False,
            response_authority="observe-only",
        )

    @staticmethod
    def _transition_stable(transition: _PendingTransition) -> bool:
        if transition.guard_record_id > 0:
            current_guard = transition.source.record_anchor(transition.guard_record_id)
            if not current_guard or not hmac.compare_digest(
                transition.guard_anchor, current_guard
            ):
                return False
        if transition.terminal_record_id > 0:
            current_terminal = transition.source.record_anchor(
                transition.terminal_record_id
            )
            if not current_terminal or not hmac.compare_digest(
                transition.terminal_anchor, current_terminal
            ):
                return False
        return True

    def _poll_channel(
        self, channel: str, event_ids: tuple[int, ...]
    ) -> _PendingTransition | None:
        assert self._checkpoints is not None
        try:
            source = self._source(channel, event_ids)
            oldest = max(0, int(source.oldest_record_id()))
            newest = max(0, int(source.newest_record_id()))
            if oldest > newest:
                oldest = 0
            checkpoint = self._checkpoints.get(channel)
            retained_anchor = ""
            if checkpoint is not None and checkpoint.record_id > 0:
                retained_anchor = source.record_anchor(checkpoint.record_id)
            if self._checkpoint_status in {"untrusted", "provisional"} or (
                self._checkpoint_status == "authenticated" and checkpoint is None
            ):
                channel_status = "untrusted"
            elif self._checkpoint_status == "first-enrollment":
                channel_status = "first-enrollment"
            else:
                channel_status = "authenticated"
            assessment = assess_continuity(
                checkpoint,
                oldest=oldest,
                newest=newest,
                retained_anchor=retained_anchor,
                checkpoint_status=channel_status,
            )
            if assessment.state in {"gap", "untrusted"}:
                self._gaps_seen += 1
                self.set_health(35, f"{channel} continuity {assessment.state}")
                self._emit_health(
                    f"{channel} event-log continuity {assessment.state}: {assessment.reason}",
                    assessment.state,
                    channel=channel,
                    missing_record_start=assessment.missing_start,
                    missing_record_end=assessment.missing_end,
                    oldest_retained_record=oldest,
                    newest_record=newest,
                    replay_from_record=assessment.resume_after + 1 if oldest else 0,
                )

            resume_after = assessment.resume_after
            guard_record_id = oldest if oldest > 0 else 0
            admission_anchor = source.record_anchor(guard_record_id) if guard_record_id else ""
            if assessment.state == "live" and resume_after > 0:
                guard_record_id = resume_after
                admission_anchor = source.record_anchor(resume_after)
                if not hmac.compare_digest(retained_anchor, admission_anchor):
                    self._gaps_seen += 1
                    self._emit_health(
                        f"{channel} changed before the event query",
                        "gap",
                        channel=channel,
                        gap_reason="pre-query-anchor-change",
                    )
                    return None
            if guard_record_id > 0 and not admission_anchor:
                self._gaps_seen += 1
                self._emit_health(
                    f"{channel} admission record vanished before the event query",
                    "gap",
                    channel=channel,
                    gap_reason="admission-record-missing",
                )
                return None

            rows = source.read_after(resume_after, _BATCH)
            if admission_anchor:
                post_query_anchor = source.record_anchor(guard_record_id)
                if not hmac.compare_digest(admission_anchor, post_query_anchor):
                    self._gaps_seen += 1
                    self._emit_health(
                        f"{channel} changed during the event query",
                        "gap",
                        channel=channel,
                        gap_reason="mid-query-anchor-change",
                    )
                    return None

            latest = resume_after
            staged_records: list[AuditIntegrityRecord] = []
            rejected: set[str] = set()
            for xml in rows:
                try:
                    record = parse_audit_integrity_xml(xml, channel)
                    latest = max(latest, record.record_id)
                    staged_records.append(record)
                except (TypeError, ValueError) as exc:
                    try:
                        latest = max(latest, _record_id_from_xml(str(xml)))
                    except (TypeError, ValueError):
                        pass
                    rejected.add(
                        exc.reason_code
                        if isinstance(exc, AuditEventRejected)
                        else "schema-rejected"
                    )
            if len(rows) < _BATCH:
                latest = max(latest, newest)
            terminal_anchor = source.record_anchor(latest) if latest > 0 else ""
            if latest > 0 and not terminal_anchor:
                self._gaps_seen += 1
                self._emit_health(
                    f"{channel} terminal record vanished before checkpoint",
                    "gap",
                    channel=channel,
                    gap_reason="terminal-record-missing",
                )
                return None
            transition = _PendingTransition(
                channel=channel,
                source=source,
                guard_record_id=guard_record_id,
                guard_anchor=admission_anchor,
                terminal_record_id=latest,
                terminal_anchor=terminal_anchor,
                reached_observed_terminal=len(rows) < _BATCH and latest >= newest,
                records=tuple(staged_records),
                rejected_reason_codes=tuple(sorted(rejected)),
            )
            if not self._transition_stable(transition):
                self._gaps_seen += 1
                self._emit_health(
                    f"{channel} changed before the transition could be staged",
                    "gap",
                    channel=channel,
                    gap_reason="late-generation-change",
                    staged_records_discarded=len(staged_records),
                )
                return None
            return transition
        except Exception as exc:
            self.set_health(20, f"{channel} event-log evidence is blind")
            if channel not in self._blind_reported:
                self._blind_reported.add(channel)
                self.emit(
                    f"{channel} audit-log evidence unavailable: {type(exc).__name__}",
                    Severity.HIGH,
                    source_channel=channel,
                    sensor_state="blind",
                    error_class=type(exc).__name__,
                    response_authorized=False,
                    response_authority="observe-only",
                )
            return None

    def poll_once(self) -> int:
        before = self._events_seen
        self._load_checkpoint()
        assert self._checkpoints is not None
        prior_checkpoints = dict(self._checkpoints)
        pending: list[_PendingTransition] = []
        for channel, event_ids in _CHANNELS:
            transition = self._poll_channel(channel, event_ids)
            if transition is not None:
                pending.append(transition)
        accepted: list[_PendingTransition] = []
        for transition in pending:
            # Revalidate immediately before the authenticated CAS.  Records are
            # still staged and will be discarded if either generation anchor
            # changed since the query/parse phase.
            if not self._transition_stable(transition):
                self._gaps_seen += 1
                self._emit_health(
                    f"{transition.channel} changed before checkpoint commit",
                    "gap",
                    channel=transition.channel,
                    gap_reason="pre-commit-generation-change",
                    staged_records_discarded=len(transition.records),
                )
                continue
            self._checkpoints[transition.channel] = ChannelCheckpoint(
                transition.terminal_record_id, transition.terminal_anchor
            )
            accepted.append(transition)
        if not accepted:
            return 0
        coverage_complete = (
            len(accepted) == len(_CHANNELS)
            and all(item.reached_observed_terminal for item in accepted)
            and len(self._checkpoints) == len(_CHANNELS)
        )
        was_complete = self._coverage_complete
        checkpoint_changed = (
            self._checkpoint_status != "authenticated"
            or self._checkpoints != prior_checkpoints
            or coverage_complete != was_complete
        )
        checkpoint_committed = (
            self._checkpoint.save(
                self._checkpoints, coverage_complete=coverage_complete
            )
            if checkpoint_changed
            else self._checkpoint.verify_unchanged()
        )
        if not checkpoint_committed:
            self._checkpoints = prior_checkpoints
            self.set_health(20, "audit-log continuity checkpoint could not be authenticated")
            self._emit_health(
                "Audit-log continuity checkpoint could not be authenticated",
                "untrusted",
                channel="all",
            )
            self._report_freshness()
        else:
            self._checkpoint_status = "authenticated"
            self._coverage_complete = coverage_complete
            self._report_freshness()
            publishable: list[_PendingTransition] = []
            post_commit_changed = False
            for transition in accepted:
                if self._transition_stable(transition):
                    publishable.append(transition)
                    continue
                post_commit_changed = True
                self._gaps_seen += 1
                prior = prior_checkpoints.get(transition.channel)
                if prior is None:
                    self._checkpoints.pop(transition.channel, None)
                else:
                    self._checkpoints[transition.channel] = prior
                self._emit_health(
                    f"{transition.channel} changed before staged evidence publication",
                    "gap",
                    channel=transition.channel,
                    gap_reason="post-commit-generation-change",
                    staged_records_discarded=len(transition.records),
                )
            if post_commit_changed:
                coverage_complete = False
                self._coverage_complete = False
                if not self._checkpoint.save(
                    self._checkpoints, coverage_complete=False
                ):
                    self.set_health(20, "audit-log race recovery checkpoint failed closed")
                    self._emit_health(
                        "Audit-log race recovery checkpoint could not be authenticated",
                        "untrusted",
                        channel="all",
                    )
            for transition in publishable:
                for record in transition.records:
                    self._emit_record(record)
                for reason_code in transition.rejected_reason_codes:
                    self.set_health(60, f"{transition.channel} contains rejected event evidence")
                    self.emit(
                        f"{transition.channel} audit-integrity record was rejected by fixed schema",
                        Severity.MEDIUM,
                        source_channel=transition.channel,
                        sensor_state="degraded",
                        rejection_reason=reason_code,
                        raw_event_omitted=True,
                        response_authorized=False,
                        response_authority="observe-only",
                    )
                self._blind_reported.discard(transition.channel)
            if coverage_complete and not was_complete:
                self.emit(
                    "Audit-log retained-evidence enrollment reached stable terminal anchors",
                    Severity.INFO,
                    schema="angerona.audit-log-coverage.v1",
                    sensor_state="authenticated",
                    coverage_complete=True,
                    raw_event_omitted=True,
                    response_authorized=False,
                    response_authority="observe-only",
                )
            if not self._blind_reported and self.health >= 35:
                self.set_health(
                    (
                        100
                        if coverage_complete
                        and self._gaps_seen == 0
                        and self._checkpoint.independent_freshness_verified
                        else 75
                        if coverage_complete and self._gaps_seen == 0
                        else 70
                    ),
                    f"{len(self._checkpoints)} channels anchored; "
                    f"{self._events_seen} integrity event(s) observed; "
                    f"coverage {'complete' if coverage_complete else 'provisional'}",
                )
        return self._events_seen - before

    def run(self) -> None:
        try:
            while not self.stopping:
                self.poll_once()
                self.sleep(_POLL_SECONDS)
        finally:
            for channel in list(self._owns_sources):
                source = self._sources.get(channel)
                if source is not None:
                    try:
                        source.close()
                    except Exception:
                        pass

    def self_test(self) -> tuple[bool, str]:
        fixture = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
          <System><Provider Name='Microsoft-Windows-Eventlog'/><EventID>104</EventID>
          <TimeCreated SystemTime='2020-01-01T00:00:00Z'/><EventRecordID>9</EventRecordID>
          <Channel>System</Channel></System>
          <EventData><Data Name='Channel'>Security</Data>
          <Data Name='SubjectUserName'>operator</Data></EventData></Event>"""
        try:
            record = parse_audit_integrity_xml(fixture, "System")
            ok = (
                record.classification == "event-log-cleared"
                and record.fields == {"affected_channel": "[REDACTED]"}
            )
            return (
                ok,
                "strict clear-event parser and privacy boundary verified"
                if ok else "clear-event fixture semantics changed",
            )
        except Exception as exc:
            return False, str(exc)


def register() -> AuditLogIntegrityGuard:
    return AuditLogIntegrityGuard()


__all__ = ["AuditLogIntegrityGuard", "register"]
