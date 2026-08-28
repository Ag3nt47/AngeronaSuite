"""Observe-only SSH Surface / Key / Tunnel Guard.

The module performs bounded local inspection. It never probes a listener,
guesses a password, intercepts a session, edits sshd_config, or removes a key.
Findings describe advanced intrusion tradecraft without attributing an actor.
"""
from __future__ import annotations

import json
import os
import secrets
import stat
import sys
import threading
import time
from collections import deque
from itertools import islice
from pathlib import Path
from typing import Callable, Iterable, Mapping, Sequence

from angerona.core.eventbus import Event, Severity
from angerona.core.module_base import BaseModule
from angerona.core.sensor_provenance import (
    SensorProvenanceBroker,
    SensorProvenanceError,
)
from angerona.core.ssh_surface import (
    MAX_LOG_BYTES,
    MAX_LOG_LINES,
    MAX_WINDOWS_EVENT_ROWS,
    WINDOWS_OPENSSH_CHANNELS,
    AuthorizedKeyCandidate,
    SSHBaselineComparison,
    SSHBaselineStore,
    SSHConfigObservation,
    SSHConfigLimitError,
    SSHLogEvidence,
    SSHRuntimeEvidence,
    SSHSurfaceError,
    analyze_openssh_logs,
    build_ssh_snapshot,
    canonical_openssh_log_candidates,
    canonical_sshd_config_candidates,
    collect_local_ssh_runtime,
    default_authorized_key_candidates,
    evaluate_sshd_posture,
    inventory_authorized_keys,
    inventory_host_keys,
    load_ssh_purpose_keys,
    observe_sshd_config_graph,
    open_windows_openssh_event_source,
    parse_sshd_config,
    parse_windows_openssh_event,
    path_has_link_or_reparse,
    verify_windows_ssh_acl,
    windows_event_record_id,
)


SUPPORTED_PLATFORMS = ("windows", "macos", "linux")

_SEVERITY = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}
_MAX_LOG_READ_BYTES = 256 * 1024
_WINDOWS_EVENT_RETRY_BASE_SECONDS = 5.0
_WINDOWS_EVENT_RETRY_MAX_SECONDS = 300.0
_WINDOWS_EVENT_QUERY_FAILURE_LIMIT = 3
_FORWARDING_ACTIVITY_LABELS = frozenset({
    "local-forward", "reverse-forward", "dynamic-forward", "tunnel-device",
    "stdio-forward", "proxy-jump",
})
_BROKER_EVENT_TYPE = "angerona.ssh-log-input.v1"
_BROKER_PRODUCER_LABEL = "OpenSSH Auth Event Collector"
_BROKER_EVENT_FIELDS = frozenset({"channel", "provider", "rendered_message"})
_BROKER_CHANNELS = frozenset(channel for channel, _query in WINDOWS_OPENSSH_CHANNELS)


def _valid_broker_ssh_event(document: Mapping[str, object]) -> bool:
    """Validate the complete consumer schema before broker continuity advances."""

    return bool(
        isinstance(document, Mapping)
        and frozenset(document) == _BROKER_EVENT_FIELDS
        and isinstance(document.get("channel"), str)
        and document.get("channel") in _BROKER_CHANNELS
        and document.get("provider") == "OpenSSH"
        and isinstance(document.get("rendered_message"), str)
        and document["rendered_message"]
        and len(document["rendered_message"]) <= 8192
    )


class _BoundedLogTail:
    """In-memory, non-persistent cursor for conventional text auth logs."""

    def __init__(self) -> None:
        self._identity: tuple[int, int] | None = None
        self._offset = 0

    def read(self, path: Path) -> tuple[tuple[str, ...], str | None]:
        if path_has_link_or_reparse(path):
            return (), "ssh.logs.link_reparse_rejected"
        try:
            before = path.lstat()
        except FileNotFoundError:
            return (), None
        except OSError:
            return (), "ssh.logs.unreadable"
        if not stat.S_ISREG(before.st_mode):
            return (), "ssh.logs.non_regular_rejected"
        identity = (int(getattr(before, "st_dev", 0)), int(getattr(before, "st_ino", 0)))
        issue = None
        initial_partial = False
        if self._identity != identity:
            self._identity = identity
            self._offset = max(0, before.st_size - _MAX_LOG_READ_BYTES)
            initial_partial = self._offset > 0
        elif before.st_size < self._offset:
            self._offset = max(0, before.st_size - _MAX_LOG_READ_BYTES)
            initial_partial = self._offset > 0
            issue = "ssh.logs.truncated_or_rotated"
        start_offset = self._offset
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(str(path), flags)
            try:
                opened = os.fstat(fd)
                opened_identity = (
                    int(getattr(opened, "st_dev", 0)), int(getattr(opened, "st_ino", 0))
                )
                if opened_identity != identity or not stat.S_ISREG(opened.st_mode):
                    return (), "ssh.logs.changed_during_read"
                os.lseek(fd, self._offset, os.SEEK_SET)
                data = os.read(fd, _MAX_LOG_READ_BYTES + 1)
                if len(data) > _MAX_LOG_READ_BYTES:
                    data = data[:_MAX_LOG_READ_BYTES]
                    issue = "ssh.logs.read_bound_reached"
            finally:
                os.close(fd)
        except OSError:
            return (), "ssh.logs.unreadable"
        if not data:
            return (), issue
        prefix = 0
        if initial_partial:
            # Initial tail can begin in the middle of a record. Discard only
            # that fragment; no unbounded backward search is attempted.
            split = data.find(b"\n")
            if split < 0:
                self._offset = start_offset + len(data)
                return (), "ssh.logs.oversized_record_dropped"
            prefix = split + 1
        payload = data[prefix:]
        consumed = len(data)
        if payload and not payload.endswith((b"\n", b"\r")):
            split = payload.rfind(b"\n")
            if split < 0:
                # Leave a bounded incomplete record on disk for the next poll;
                # no raw identity-bearing fragment is retained in memory.
                if len(data) >= _MAX_LOG_READ_BYTES:
                    self._offset = start_offset + len(data)
                    return (), "ssh.logs.oversized_record_dropped"
                self._offset = start_offset + prefix
                return (), issue
            payload = payload[:split + 1]
            consumed = prefix + split + 1
        self._offset = start_offset + consumed
        lines = payload.decode("utf-8", "replace").splitlines()[:MAX_LOG_LINES]
        return tuple(lines), issue


class SSHSurfaceGuardModule(BaseModule):
    CODE = "SSHG"
    NAME = "SSH Surface / Key / Tunnel Guard"
    name = "SSH Surface / Key / Tunnel Guard"
    description = (
        "Read-only OpenSSH posture, authorized-key fingerprint, host-key, service, "
        "listener, authentication, and tunnel-drift monitoring with authenticated baselines."
    )
    category = "Zero Trust"
    version = "1.1.0"
    supported_platforms = SUPPORTED_PLATFORMS
    capability_mode = "observe"
    platform_requirements = (
        "Local OpenSSH files and logs when present",
        "psutil for local service/process/listener evidence",
        "Angerona bus.key for authenticated persistent drift state",
    )

    def __init__(
        self,
        *,
        data_root: Path | str | None = None,
        master_key: bytes | None = None,
        config_paths: Sequence[Path | str] | None = None,
        key_candidates: Iterable[AuthorizedKeyCandidate] | None = None,
        runtime_collector: Callable[..., SSHRuntimeEvidence] | None = None,
        windows_event_source_factory: Callable[[str], object] | None = None,
        provenance_broker: SensorProvenanceBroker | None = None,
        monotonic_clock: Callable[[], float] | None = None,
        interval_seconds: float = 30.0,
        platform: str | None = None,
    ) -> None:
        super().__init__()
        if master_key is not None and (
            not isinstance(master_key, bytes) or len(master_key) != 32
        ):
            raise ValueError("SSH guard key override must contain exactly 32 bytes")
        self._data_root_override = Path(data_root) if data_root is not None else None
        self._data_root: Path | None = self._data_root_override
        self._master_key = master_key
        self._config_paths = tuple(Path(item) for item in config_paths) if config_paths else None
        self._key_candidates = tuple(key_candidates) if key_candidates is not None else None
        self._runtime_collector = runtime_collector or collect_local_ssh_runtime
        self._windows_event_source_factory = (
            windows_event_source_factory or open_windows_openssh_event_source
        )
        self._provenance_broker = provenance_broker
        self._monotonic_clock = monotonic_clock or time.monotonic
        self._platform = (platform or sys.platform).casefold()
        self._interval = max(5.0, min(300.0, float(interval_seconds)))
        self._purpose_keys = None
        self._ephemeral_privacy_key = secrets.token_bytes(32)
        self._baseline: SSHBaselineStore | None = None
        self._last_finding_codes: set[str] = set()
        self._last_log_issue_codes: set[str] = set()
        self._last_baseline_marker = ""
        self._known_source_tokens: set[str] = set()
        self._log_tails: dict[Path, _BoundedLogTail] = {}
        self._windows_event_sources: dict[str, object] = {}
        self._windows_event_cursors: dict[str, int] = {}
        self._windows_event_failures: dict[str, int] = {}
        self._windows_event_query_failures: dict[str, int] = {}
        self._windows_event_next_retry: dict[str, float] = {}
        self._windows_event_last_failure: dict[str, str] = {}
        self._windows_event_ever_opened: set[str] = set()
        self._windows_history_bounded: set[str] = set()
        self._log_source_states: dict[str, str] = {}
        self._queued_log_evidence: deque[SSHLogEvidence] = deque(maxlen=256)
        self._evidence_lock = threading.RLock()
        self._live_ingest_enabled = threading.Event()

    def bind_manager(self, manager) -> None:
        if self._data_root_override is None:
            config = getattr(manager, "config", None)
            value = getattr(config, "data_dir", None)
            if value is not None:
                self._data_root = Path(value)

    def _root(self) -> Path:
        if self._data_root is not None:
            return self._data_root
        from angerona.core.data_paths import data_dir
        self._data_root = data_dir()
        return self._data_root

    def _ensure_security_state(self) -> bytes:
        if self._purpose_keys is None:
            self._purpose_keys = load_ssh_purpose_keys(
                self._root(), master_key=self._master_key
            )
        if self._baseline is None:
            self._baseline = SSHBaselineStore(
                self._root() / "shared_logs" / "ssh_surface_baseline.json",
                data_root=self._root(),
                master_key=self._master_key,
            )
        return (
            self._purpose_keys.privacy_key
            if self._purpose_keys is not None
            else self._ephemeral_privacy_key
        )

    @staticmethod
    def _base_details(**extra: object) -> dict[str, object]:
        details: dict[str, object] = {
            "response_authorized": False,
            "capability_mode": "observe",
            "read_only": True,
            "actor_attribution": "none",
            "tradecraft_context": (
                "Advanced and state-grade intrusion tradecraft defense; evidence alone "
                "does not identify an actor."
            ),
        }
        details.update(extra)
        return details

    def _emit_observation(
        self,
        message: str,
        severity: Severity,
        **details: object,
    ) -> None:
        self.emit(message, severity, **self._base_details(**details))

    def _on_bus_event(self, event: Event) -> None:
        """Consume only broker-authenticated, fixed-schema OpenSSH evidence.

        EventBus authentication protects stored bytes, not the identity of the
        process that supplied them.  The live path therefore fails closed
        unless the privileged provenance broker authenticates the producer,
        schema, sequence, and loss-free continuity.  Canonical local log and
        Windows Event Log collectors do not pass through this adapter.
        """
        if (
            not self._live_ingest_enabled.is_set()
            or self.stopping
            or event.module == self.name
        ):
            return
        details = event.details if isinstance(event.details, dict) else {}
        envelope = details.get("sensor_provenance_envelope")
        if envelope is None or self._provenance_broker is None:
            return
        try:
            accepted = self._provenance_broker.ingest(
                envelope,
                expected_label=_BROKER_PRODUCER_LABEL,
                expected_event_type=_BROKER_EVENT_TYPE,
                event_validator=_valid_broker_ssh_event,
            )
        except SensorProvenanceError:
            return
        document = accepted.event
        if (
            accepted.coverage_state != "ready"
            or not isinstance(document, Mapping)
        ):
            return
        rendered = str(document["rendered_message"])
        privacy_key = self._ensure_security_state()
        analysis = analyze_openssh_logs(
            (rendered,),
            privacy_key=privacy_key,
            known_source_tokens=self._known_source_tokens,
            max_lines=1,
            max_bytes=min(MAX_LOG_BYTES, 8192),
        )
        with self._evidence_lock:
            self._known_source_tokens.update(analysis.observed_source_tokens)
            if len(self._known_source_tokens) > 4096:
                self._known_source_tokens = set(sorted(self._known_source_tokens)[-4096:])
            self._queued_log_evidence.extend(analysis.evidence)

    def _config_observation(
        self, privacy_key: bytes
    ) -> tuple[SSHConfigObservation | None, str, list[str]]:
        candidates = self._config_paths or canonical_sshd_config_candidates(self._platform)
        existing: list[Path] = []
        for path in candidates[:8]:
            try:
                if path.exists():
                    existing.append(path)
            except OSError:
                continue
        if not existing:
            return None, "missing", ["ssh.config.canonical_not_observed"]
        issues: list[str] = []
        observation = None
        for path in existing:
            try:
                observation = observe_sshd_config_graph(
                    path,
                    privacy_key=privacy_key,
                    platform=self._platform,
                )
                break
            except SSHConfigLimitError:
                issues.append("ssh.config.bound_reached")
            except (OSError, SSHSurfaceError):
                issues.append("ssh.config.unreadable_or_unsafe")
        if observation is None:
            return None, "unsafe" if issues else "unreadable", issues
        issues.extend(observation.issues)
        if len(existing) > 1:
            issues.append("ssh.config.multiple_canonical_files")
        parsed = observation.parsed
        state = "ambiguous" if parsed.errors or parsed.include_lines or len(existing) > 1 else "observed"
        return observation, state, list(dict.fromkeys(issues))

    @staticmethod
    def _windows_channel_code(channel: str) -> str:
        return "operational" if channel.casefold().endswith("/operational") else "admin"

    @staticmethod
    def _windows_retry_delay(channel: str, failures: int) -> float:
        exponent = min(6, max(0, int(failures) - 1))
        base = min(
            _WINDOWS_EVENT_RETRY_MAX_SECONDS,
            _WINDOWS_EVENT_RETRY_BASE_SECONDS * (2**exponent),
        )
        # Stable bounded jitter avoids synchronized reopen storms without
        # retaining an exception string or other source identity.
        bucket = sum(channel.encode("utf-8", "ignore")) + max(1, failures) * 17
        factor = 0.9 + (bucket % 21) / 100.0
        return min(_WINDOWS_EVENT_RETRY_MAX_SECONDS, base * factor)

    @staticmethod
    def _close_windows_source(source: object | None) -> None:
        if source is None:
            return
        try:
            source.close()
        except Exception:
            pass

    def _schedule_windows_reopen(
        self,
        channel: str,
        *,
        now: float,
        failure: str,
    ) -> None:
        failures = min(16, self._windows_event_failures.get(channel, 0) + 1)
        self._windows_event_failures[channel] = failures
        self._windows_event_next_retry[channel] = now + self._windows_retry_delay(
            channel, failures
        )
        self._windows_event_last_failure[channel] = failure

    def _collect_windows_event_lines(self) -> tuple[list[str], list[str]]:
        if not (self._platform.startswith("win") or self._platform == "windows"):
            return [], []
        lines: list[str] = []
        issues: list[str] = []
        for channel, _event_ids in WINDOWS_OPENSSH_CHANNELS:
            code = self._windows_channel_code(channel)
            now = float(self._monotonic_clock())
            opened_after_failure = False
            source = self._windows_event_sources.get(channel)
            if source is None:
                next_retry = self._windows_event_next_retry.get(channel, 0.0)
                if now < next_retry:
                    self._log_source_states[code] = "retry-backoff"
                    issues.append(f"ssh.logs.windows_{code}_retry_backoff")
                    continue
                provisional: object | None = None
                had_failure = channel in self._windows_event_last_failure
                try:
                    provisional = self._windows_event_source_factory(channel)
                    newest = max(0, int(provisional.newest_record_id()))
                    oldest = max(0, int(provisional.oldest_record_id()))
                    source = provisional
                    self._windows_event_sources[channel] = provisional
                    initial_cursor = max(0, newest - MAX_WINDOWS_EVENT_ROWS)
                    self._windows_event_cursors[channel] = initial_cursor
                    if oldest and initial_cursor > max(0, oldest - 1):
                        self._windows_history_bounded.add(channel)
                    if had_failure or channel in self._windows_event_ever_opened:
                        # A new handle cannot prove that records retained during
                        # the blind interval cover the complete interval.
                        self._windows_history_bounded.add(channel)
                        opened_after_failure = True
                    self._windows_event_ever_opened.add(channel)
                    self._windows_event_failures[channel] = 0
                    self._windows_event_next_retry.pop(channel, None)
                    self._log_source_states[code] = (
                        "available-tail"
                        if channel in self._windows_history_bounded else "available"
                    )
                except Exception:
                    self._close_windows_source(provisional)
                    self._windows_event_sources.pop(channel, None)
                    self._windows_event_cursors.pop(channel, None)
                    self._schedule_windows_reopen(
                        channel, now=now, failure="open-failed"
                    )
                    self._log_source_states[code] = "retry-backoff"
                    issues.append(f"ssh.logs.windows_{code}_open_failed")
                    continue
            if source is None:
                self._log_source_states[code] = "retry-backoff"
                issues.append(f"ssh.logs.windows_{code}_retry_backoff")
                continue
            if channel in self._windows_history_bounded:
                issues.append(f"ssh.logs.windows_{code}_history_bounded")
            cursor = self._windows_event_cursors.get(channel, 0)
            try:
                prior_query_failures = self._windows_event_query_failures.get(channel, 0)
                newest = max(0, int(source.newest_record_id()))
                if newest < cursor:
                    oldest = max(0, int(source.oldest_record_id()))
                    cursor = max(0, oldest - 1)
                    self._windows_history_bounded.add(channel)
                    issues.append(f"ssh.logs.windows_{code}_cursor_regressed")
                rows = list(islice(
                    source.read_after(cursor, MAX_WINDOWS_EVENT_ROWS),
                    MAX_WINDOWS_EVENT_ROWS + 1,
                ))
                if len(rows) > MAX_WINDOWS_EVENT_ROWS:
                    rows = rows[:MAX_WINDOWS_EVENT_ROWS]
                    issues.append(f"ssh.logs.windows_{code}_bound_reached")
                admitted_cursor = cursor
                for xml in rows:
                    try:
                        admitted_cursor = max(admitted_cursor, windows_event_record_id(xml))
                        event = parse_windows_openssh_event(
                            xml, expected_channel=channel
                        )
                    except (TypeError, ValueError):
                        issues.append(f"ssh.logs.windows_{code}_event_rejected")
                        continue
                    if event.message:
                        lines.append(event.message)
                if not rows and newest > cursor:
                    self._windows_history_bounded.add(channel)
                    issues.append(f"ssh.logs.windows_{code}_query_gap_unresolved")
                    self._windows_event_cursors[channel] = cursor
                else:
                    self._windows_event_cursors[channel] = admitted_cursor
                self._windows_event_query_failures[channel] = 0
                if opened_after_failure or prior_query_failures:
                    self._windows_event_last_failure.pop(channel, None)
                    if channel in self._windows_history_bounded:
                        issues.append(
                            f"ssh.logs.windows_{code}_recovered_history_bounded"
                        )
                        self._log_source_states[code] = "recovered-tail"
                    else:
                        issues.append(f"ssh.logs.windows_{code}_recovered")
                        self._log_source_states[code] = "recovered"
                else:
                    self._log_source_states[code] = (
                        "available-tail"
                        if channel in self._windows_history_bounded else "available"
                    )
            except Exception:
                failures = min(
                    _WINDOWS_EVENT_QUERY_FAILURE_LIMIT,
                    self._windows_event_query_failures.get(channel, 0) + 1,
                )
                self._windows_event_query_failures[channel] = failures
                self._windows_event_last_failure[channel] = "query-failed"
                if failures >= _WINDOWS_EVENT_QUERY_FAILURE_LIMIT:
                    self._close_windows_source(source)
                    self._windows_event_sources.pop(channel, None)
                    self._windows_event_cursors.pop(channel, None)
                    self._windows_history_bounded.add(channel)
                    self._schedule_windows_reopen(
                        channel, now=now, failure="query-failed"
                    )
                    self._log_source_states[code] = "retry-backoff"
                    issues.append(f"ssh.logs.windows_{code}_source_reopen_scheduled")
                else:
                    self._log_source_states[code] = "degraded"
                issues.append(f"ssh.logs.windows_{code}_query_failed")
        return lines[:MAX_WINDOWS_EVENT_ROWS], list(dict.fromkeys(issues))

    def _collect_log_evidence(self, privacy_key: bytes) -> tuple[list[SSHLogEvidence], list[str]]:
        rows: list[SSHLogEvidence] = []
        issues: list[str] = []
        self._log_source_states.setdefault("text", "not-configured")
        windows_lines, windows_issues = self._collect_windows_event_lines()
        issues.extend(windows_issues)
        if windows_lines:
            analysis = analyze_openssh_logs(
                windows_lines,
                privacy_key=privacy_key,
                known_source_tokens=self._known_source_tokens,
                max_lines=min(MAX_LOG_LINES, len(windows_lines)),
                max_bytes=MAX_LOG_BYTES,
            )
            self._known_source_tokens.update(analysis.observed_source_tokens)
            rows.extend(analysis.evidence)
            if analysis.dropped_lines or analysis.dropped_evidence:
                issues.append("ssh.logs.windows_analysis_bound_reached")
        for path in canonical_openssh_log_candidates(self._platform)[:4]:
            cursor = self._log_tails.setdefault(path, _BoundedLogTail())
            lines, issue = cursor.read(path)
            if issue:
                issues.append(issue)
            if not lines:
                continue
            self._log_source_states["text"] = "available"
            analysis = analyze_openssh_logs(
                lines,
                privacy_key=privacy_key,
                known_source_tokens=self._known_source_tokens,
                max_lines=MAX_LOG_LINES,
                max_bytes=MAX_LOG_BYTES,
            )
            self._known_source_tokens.update(analysis.observed_source_tokens)
            rows.extend(analysis.evidence)
            if analysis.dropped_lines or analysis.dropped_evidence:
                issues.append("ssh.logs.analysis_bound_reached")
        with self._evidence_lock:
            rows.extend(self._queued_log_evidence)
            self._queued_log_evidence.clear()
        if len(self._known_source_tokens) > 4096:
            self._known_source_tokens = set(sorted(self._known_source_tokens)[-4096:])
        return rows[:256], list(dict.fromkeys(issues))

    @staticmethod
    def _runtime_source_states(runtime: SSHRuntimeEvidence) -> dict[str, str]:
        issue_set = set(runtime.issues)
        psutil_missing = "ssh.runtime.psutil_unavailable" in issue_set
        return {
            "runtime-connections": (
                "unavailable"
                if psutil_missing
                or "ssh.runtime.connection_inventory_unavailable" in issue_set
                else "available"
            ),
            "runtime-processes": (
                "unavailable"
                if psutil_missing
                or "ssh.runtime.process_inventory_unavailable" in issue_set
                else (
                    "partial"
                    if {
                        "ssh.runtime.process_metadata_partial",
                        "ssh.runtime.client_arguments_unavailable",
                    } & issue_set
                    else "available"
                )
            ),
            "runtime-services": (
                "unavailable"
                if psutil_missing
                or "ssh.runtime.windows_service_inventory_unavailable" in issue_set
                else "available"
            ),
            "runtime-signatures": (
                "unavailable"
                if "ssh.runtime.signature_verification_unavailable" in issue_set
                else "not-required"
            ),
        }

    def _emit_baseline(self, comparison: SSHBaselineComparison) -> None:
        marker = json.dumps(
            {
                "status": comparison.status,
                "trusted": comparison.baseline_trusted,
                "reason": comparison.reason,
                "changes": comparison.changes,
            },
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        if marker == self._last_baseline_marker:
            return
        self._last_baseline_marker = marker
        if comparison.status == "tampered":
            self._emit_observation(
                "SSH drift baseline failed authentication; evidence remains untrusted.",
                Severity.CRITICAL,
                finding_code="ssh.baseline.authentication_failed",
                baseline_status="tampered",
                baseline_trusted=False,
            )
        elif comparison.status == "drift":
            self._emit_observation(
                "SSH configuration, key, runtime, evidence-source, or coverage drift detected.",
                Severity.HIGH,
                finding_code="ssh.baseline.drift",
                baseline_status="drift",
                baseline_trusted=comparison.baseline_trusted,
                changes=dict(comparison.changes),
            )
        elif comparison.status == "unknown":
            self._emit_observation(
                "SSH baseline trust is unknown; no observed state has been auto-trusted.",
                Severity.MEDIUM,
                finding_code="ssh.baseline.unknown",
                baseline_status="unknown",
                baseline_trusted=False,
            )

    def observe_once(self) -> dict[str, object]:
        privacy_key = self._ensure_security_state()
        config_observation, config_state, collection_issues = self._config_observation(
            privacy_key
        )
        parsed = config_observation.parsed if config_observation is not None else None
        posture = evaluate_sshd_posture(parsed, platform=self._platform) if parsed is not None else ()
        candidates = list(
            self._key_candidates or default_authorized_key_candidates(self._platform)
        )
        if config_observation is not None:
            candidates.extend(config_observation.authorized_key_candidates)
        inventory = inventory_authorized_keys(
            candidates,
            privacy_key=privacy_key,
            platform=self._platform,
            windows_acl_verifier=(
                verify_windows_ssh_acl
                if self._platform.startswith("win") or self._platform == "windows"
                else None
            ),
        )
        host_keys, host_key_issues = inventory_host_keys(
            parsed,
            privacy_key=privacy_key,
            platform=self._platform,
            windows_acl_verifier=(
                verify_windows_ssh_acl
                if self._platform.startswith("win") or self._platform == "windows"
                else None
            ),
        )
        try:
            runtime = self._runtime_collector(
                privacy_key=privacy_key,
                platform=self._platform,
            )
        except Exception:
            runtime = SSHRuntimeEvidence((), (), ("ssh.runtime.collector_failed",))
        if runtime.services and not host_keys:
            host_key_issues = (*host_key_issues, "ssh.host_keys.none_observed")
        log_rows, log_issues = self._collect_log_evidence(privacy_key)
        coverage = tuple(dict.fromkeys((
            *collection_issues,
            *(item.code for item in inventory.issues),
            *host_key_issues,
            *runtime.issues,
            *log_issues,
        )))
        snapshot = build_ssh_snapshot(
            config_digest=(
                config_observation.aggregate_digest
                if config_observation is not None else None
            ),
            config_state=config_state,
            inventory=inventory,
            host_keys=host_keys,
            runtime=runtime,
            configured_sources=(
                config_observation.sources if config_observation is not None else ()
            ),
            coverage=coverage,
        )
        assert self._baseline is not None
        comparison = self._baseline.observe(snapshot)

        current_codes = {item.code for item in posture}
        for item in posture:
            if item.code in self._last_finding_codes:
                continue
            self._emit_observation(
                item.summary,
                _SEVERITY.get(item.severity, Severity.MEDIUM),
                finding_code=item.code,
                setting=item.setting,
                posture_state=item.state,
                recommendation=item.recommendation,
            )
        for issue in inventory.issues:
            current_codes.add(issue.code)
            if issue.code not in self._last_finding_codes:
                self._emit_observation(
                    "SSH authorized-key custody or parsing requires review.",
                    _SEVERITY.get(issue.severity, Severity.MEDIUM),
                    finding_code=issue.code,
                    subject_token=issue.subject_token,
                )
        for issue in (*collection_issues, *host_key_issues, *runtime.issues):
            current_codes.add(issue)
            if issue not in self._last_finding_codes:
                self._emit_observation(
                    "SSH observation coverage is incomplete or ambiguous.",
                    Severity.MEDIUM,
                    finding_code=issue,
                )
        for service in runtime.services:
            if service.renamed or service.nonstandard_binary:
                code = (
                    "ssh.runtime.renamed_service"
                    if service.renamed else "ssh.runtime.nonstandard_binary"
                )
                current_codes.add(code)
                if code not in self._last_finding_codes:
                    self._emit_observation(
                        "SSH service identity or binary location differs from the canonical host posture.",
                        Severity.HIGH,
                        finding_code=code,
                        service_token=service.service_token,
                        executable_token=service.executable_token,
                    )
        for listener in runtime.listeners:
            code = ""
            severity = Severity.LOW
            if listener.port != 22:
                code = "ssh.runtime.nonstandard_listener"
                severity = Severity.MEDIUM
            elif listener.scope == "wildcard":
                code = "ssh.runtime.wildcard_listener"
            if code:
                current_codes.add(code)
                if code not in self._last_finding_codes:
                    self._emit_observation(
                        "SSH listener exposure requires zero-trust network policy review.",
                        severity,
                        finding_code=code,
                        listener_token=listener.listener_token,
                        port=listener.port,
                        scope=listener.scope,
                    )
        for process in runtime.processes:
            if process.nonstandard_binary:
                code = "ssh.runtime.nonstandard_process_binary"
                current_codes.add(code)
                if code not in self._last_finding_codes:
                    self._emit_observation(
                        "SSH process executable location differs from the canonical host posture.",
                        Severity.HIGH,
                        finding_code=code,
                        process_token=process.process_token,
                        executable_token=process.executable_token,
                        process_role=process.role,
                    )
            active_forwarding = tuple(
                flag for flag in process.forwarding_flags
                if flag in _FORWARDING_ACTIVITY_LABELS
            )
            if process.role == "client" and active_forwarding:
                code = "ssh.runtime.client_forwarding_process"
                current_codes.add(code)
                if code not in self._last_finding_codes:
                    self._emit_observation(
                        "A local SSH client process uses forwarding or tunnel options.",
                        Severity.HIGH,
                        finding_code=code,
                        process_token=process.process_token,
                        forwarding_flags=list(active_forwarding),
                    )
        self._last_finding_codes = current_codes
        self._emit_baseline(comparison)

        for row in log_rows:
            message = {
                "authentication_failure": "SSH authentication failures observed.",
                "successful_password_auth": "Successful SSH password authentication observed.",
                "successful_key_auth": "Successful SSH key authentication from a newly observed source.",
                "forwarding_or_tunnel_signal": "SSH forwarding or tunnel activity observed.",
            }.get(row.kind, "SSH authentication activity observed.")
            if row.kind == "successful_key_auth" and not row.new_source:
                continue
            self._emit_observation(
                message,
                _SEVERITY.get(row.severity, Severity.MEDIUM),
                finding_code=f"ssh.logs.{row.kind}",
                source_token=row.source_token,
                account_token=row.account_token,
                count=row.count,
                new_source=row.new_source,
            )
        for issue in log_issues:
            if issue in self._last_log_issue_codes:
                continue
            recovered = "_recovered" in issue
            self._emit_observation(
                (
                    "SSH log source recovered; any unobserved interval remains explicit."
                    if recovered
                    else "SSH log observation boundary changed or reached a safety limit."
                ),
                Severity.INFO if recovered else Severity.MEDIUM,
                finding_code=issue,
            )
        self._last_log_issue_codes = set(log_issues)

        ssh_present = bool(
            parsed
            or runtime.services
            or runtime.listeners
            or runtime.processes
            or runtime.connections
            or inventory.entries
        )
        if comparison.status == "tampered":
            self.set_health(30, "SSH observation active; authenticated drift state failed verification.")
        elif (
            ssh_present
            and comparison.baseline_trusted
            and comparison.status == "stable"
            and not coverage
        ):
            self.set_health(90, "SSH local posture and authenticated drift observation active.")
        elif ssh_present:
            self.set_health(70, "SSH observation active; baseline remains provisional or posture requires review.")
        else:
            self.set_health(60, "No canonical SSH surface observed; absence is not proof that SSH is unavailable.")
        health_now = float(self._monotonic_clock())
        return {
            "config_state": config_state,
            "posture_findings": len(posture),
            "authorized_keys": len(inventory.entries),
            "services": len(runtime.services),
            "listeners": len(runtime.listeners),
            "processes": len(runtime.processes),
            "connections": len(runtime.connections),
            "configured_sources": (
                len(config_observation.sources) if config_observation is not None else 0
            ),
            "source_completeness": dict(sorted({
                **self._log_source_states,
                **self._runtime_source_states(runtime),
            }.items())),
            "source_last_failure": dict(sorted(
                (
                    self._windows_channel_code(channel), failure
                )
                for channel, failure in self._windows_event_last_failure.items()
            )),
            "source_retry_seconds": dict(sorted(
                (
                    self._windows_channel_code(channel),
                    int(max(0.0, retry_at - health_now) + 0.999),
                )
                for channel, retry_at in self._windows_event_next_retry.items()
                if retry_at > health_now
            )),
            "coverage_issues": len(coverage),
            "baseline_status": comparison.status,
            "baseline_trusted": comparison.baseline_trusted,
            "response_authorized": False,
        }

    def self_test(self) -> tuple[bool, str]:
        try:
            parsed = parse_sshd_config(
                "PasswordAuthentication no\nMatch User example\nPasswordAuthentication yes\n"
            )
            if parsed.option("PasswordAuthentication").value != "no":
                return False, "OpenSSH first-value/Match boundary parser failed"
            key = b"S" * 32
            analysis = analyze_openssh_logs(
                ("sshd: Failed password for example from 192.0.2.9 port 22",),
                privacy_key=key,
            )
            if not analysis.evidence or "192.0.2.9" in repr(analysis):
                return False, "OpenSSH event privacy analyzer failed"
        except Exception as exc:
            return False, f"SSH guard bounded self-test failed: {exc}"
        return True, "bounded parser, privacy tokens, and observe-only contract verified"

    def run(self) -> None:
        self.set_health(65, "SSH observe-only guard starting.")
        self._ensure_security_state()
        self._live_ingest_enabled.set()
        if self._bus is not None:
            self._bus.subscribe(self._on_bus_event)
        try:
            self._emit_observation(
                "SSH Surface / Key / Tunnel Guard online in read-only mode.",
                Severity.INFO,
                finding_code="ssh.guard.online",
            )
            while not self.stopping:
                self.observe_once()
                self.sleep(self._interval)
        finally:
            # EventBus deduplicates subscriptions but intentionally has no
            # unsubscribe API. This gate makes the retained callback inert
            # whenever the module is stopped or between lifecycle generations.
            self._live_ingest_enabled.clear()
            for source in tuple(self._windows_event_sources.values()):
                try:
                    source.close()
                except Exception:
                    pass
            self._windows_event_sources.clear()


def register() -> SSHSurfaceGuardModule:
    """Return the module for compatibility with legacy module loaders."""
    return SSHSurfaceGuardModule()


__all__ = ["SSHSurfaceGuardModule", "register"]
