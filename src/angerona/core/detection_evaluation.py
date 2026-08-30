"""Immutable, bounded replay evaluation for local detection packages.

DetectionForge never evaluates a live, moving query result.  A replay cohort
is first copied into canonical JSON rows and sealed with its source identity,
high-water mark, and loss metadata.  Comparisons therefore describe an exact
set of evidence and can be invalidated if any retained byte is changed.

The evaluator deliberately reports precision and recall only for a complete,
fully labelled cohort.  Match rates over ordinary telemetry are useful, but
they are not a substitute for ground truth.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import time
from dataclasses import asdict, dataclass
from typing import Any, Iterable, Mapping, Sequence

from angerona.core.detection_packages import DetectionPackage, validate_package
from angerona.core.evidence_store import EvidenceEnvelope

COHORT_SCHEMA = "angerona.detection-replay-cohort.v1"
EVALUATION_SCHEMA = "angerona.detection-evaluation.v1"
MAX_COHORT_ROWS = 20_000
MAX_COHORT_BYTES = 64 * 1024 * 1024
MAX_EVENT_BYTES = 256 * 1024
MAX_EVENT_FIELDS = 256
MAX_RULES_PER_SIDE = 128
MAX_REPLAY_EVALUATIONS = 250_000
MAX_REPLAY_WALL_MS = 30_000.0
SOURCE_KIND_CODES = frozenset(
    {"evidence-store", "curated-replay", "import", "fixtures", "synthetic"}
)
_SOURCE_KINDS = SOURCE_KIND_CODES
_REASON_CODES = {
    "cohort source reported evidence loss or incomplete custody": "cohort-incomplete",
    "rule replay failed budget or execution gates": "rule-replay-incomplete",
}
_METRIC_REASON_CODES = {
    "withheld: cohort has source loss or incomplete custody": "withheld-cohort-incomplete",
    "withheld: evaluation is incomplete or exceeded a work gate": "withheld-evaluation-incomplete",
    "withheld: cohort is not fully labelled": "withheld-cohort-unlabelled",
    "unavailable: labelled cohort has no predicted or actual positives": "unavailable-no-positives",
    "partial: no candidate positives; recall remains defined": "partial-no-candidate-positives",
    "partial: no labelled positives; precision remains defined": "partial-no-labelled-positives",
    "complete labelled-cohort metrics": "complete-labelled-cohort-metrics",
}
EVALUATION_REASON_CODES = frozenset(_REASON_CODES.values())
METRIC_REASON_CODES = frozenset(_METRIC_REASON_CODES.values())


class CohortValidationError(ValueError):
    """A replay cohort is ambiguous, oversized, or no longer authentic."""


class DetectionEvaluationError(ValueError):
    """A package set or comparison request cannot be evaluated safely."""


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
        raise CohortValidationError("replay evidence must be strict JSON data") from exc


def _sha256(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _bounded_text(value: object, name: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise CohortValidationError(f"{name} must be text")
    rendered = value.strip()
    if not rendered or len(rendered) > maximum or "\x00" in rendered:
        raise CohortValidationError(f"{name} must contain 1-{maximum} safe characters")
    return rendered


@dataclass(frozen=True)
class CohortLoss:
    """Exact evidence-loss state captured at the source high-water mark."""

    overflow: bool = False
    dropped_rows: int = 0
    incomplete_reason: str = ""
    excluded_after_high_water: int = 0

    def __post_init__(self) -> None:
        if type(self.overflow) is not bool:
            raise CohortValidationError("loss.overflow must be boolean")
        for name in ("dropped_rows", "excluded_after_high_water"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise CohortValidationError(f"loss.{name} must be a non-negative integer")
        if not isinstance(self.incomplete_reason, str) or len(self.incomplete_reason) > 512:
            raise CohortValidationError("loss.incomplete_reason is invalid")
        if "\x00" in self.incomplete_reason:
            raise CohortValidationError("loss.incomplete_reason contains a NUL")

    @property
    def complete(self) -> bool:
        return not self.overflow and self.dropped_rows == 0 and not self.incomplete_reason


@dataclass(frozen=True)
class ReplayRow:
    """One immutable canonical event admitted at or below the high-water mark."""

    event_id: str
    revision: int
    event_json: str
    label: bool | None = None
    label_source: str | None = None

    def __post_init__(self) -> None:
        _bounded_text(self.event_id, "event_id", 128)
        if type(self.revision) is not int or self.revision < 0:
            raise CohortValidationError("revision must be a non-negative integer")
        if not isinstance(self.event_json, str) or not self.event_json:
            raise CohortValidationError("event_json must contain canonical JSON")
        if len(self.event_json.encode("utf-8")) > MAX_EVENT_BYTES:
            raise CohortValidationError("replay event exceeds 256 KiB")
        try:
            decoded = json.loads(self.event_json)
        except (TypeError, ValueError) as exc:
            raise CohortValidationError("event_json is invalid") from exc
        if not isinstance(decoded, dict) or len(decoded) > MAX_EVENT_FIELDS:
            raise CohortValidationError("replay event must be a bounded object")
        if _canonical(decoded).decode("utf-8") != self.event_json:
            raise CohortValidationError("event_json is not canonical")
        if self.label is not None and type(self.label) is not bool:
            raise CohortValidationError("label must be true, false, or null")
        if self.label is None and self.label_source is not None:
            raise CohortValidationError("unlabelled rows cannot claim label provenance")
        if self.label is not None:
            _bounded_text(self.label_source, "label_source", 160)

    def event(self) -> dict[str, Any]:
        """Return a detached event; callers cannot mutate the sealed cohort."""
        decoded = json.loads(self.event_json)
        if not isinstance(decoded, dict):  # pragma: no cover - guarded in __post_init__
            raise CohortValidationError("sealed replay row is not an object")
        return decoded

    def canonical_record(self) -> dict[str, object]:
        return {
            "event": json.loads(self.event_json),
            "event_id": self.event_id,
            "label": self.label,
            "label_source": self.label_source,
            "revision": self.revision,
        }


@dataclass(frozen=True)
class ReplayCohort:
    """A byte-exact replay snapshot with explicit custody and completeness."""

    source_id: str
    source_kind: str
    high_water: int
    rows: tuple[ReplayRow, ...]
    loss: CohortLoss
    source_digest: str
    cohort_digest: str
    captured_at: float
    schema: str = COHORT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != COHORT_SCHEMA:
            raise CohortValidationError("unsupported replay cohort schema")
        _bounded_text(self.source_id, "source_id", 240)
        if self.source_kind not in _SOURCE_KINDS:
            raise CohortValidationError("unsupported replay source kind")
        if type(self.high_water) is not int or self.high_water < 0:
            raise CohortValidationError("high_water must be a non-negative integer")
        if not 1 <= len(self.rows) <= MAX_COHORT_ROWS:
            raise CohortValidationError("replay cohort has an invalid row count")
        if not isinstance(self.loss, CohortLoss):
            raise CohortValidationError("loss metadata is required")
        if not math.isfinite(float(self.captured_at)) or float(self.captured_at) <= 0:
            raise CohortValidationError("captured_at must be a positive finite timestamp")
        self.assert_intact()

    def _source_body(self) -> dict[str, object]:
        return {
            "high_water": self.high_water,
            "rows": [row.canonical_record() for row in self.rows],
            "source_id": self.source_id,
            "source_kind": self.source_kind,
        }

    def _cohort_body(self) -> dict[str, object]:
        return {
            "captured_at": self.captured_at,
            "high_water": self.high_water,
            "loss": asdict(self.loss),
            "rows": [row.canonical_record() for row in self.rows],
            "schema": self.schema,
            "source_digest": self.source_digest,
            "source_id": self.source_id,
            "source_kind": self.source_kind,
        }

    def assert_intact(self) -> None:
        if not hmac.compare_digest(self.source_digest, _sha256(self._source_body())):
            raise CohortValidationError("replay source digest verification failed")
        if not hmac.compare_digest(self.cohort_digest, _sha256(self._cohort_body())):
            raise CohortValidationError("replay cohort digest verification failed")
        seen: set[str] = set()
        previous: tuple[int, str] | None = None
        total = 0
        for row in self.rows:
            if row.revision > self.high_water:
                raise CohortValidationError("cohort contains a row after its high-water mark")
            marker = (row.revision, row.event_id)
            if previous is not None and marker < previous:
                raise CohortValidationError("cohort rows are not in canonical order")
            if row.event_id in seen:
                raise CohortValidationError("cohort event IDs must be unique")
            seen.add(row.event_id)
            previous = marker
            total += len(row.event_json.encode("utf-8"))
        if total > MAX_COHORT_BYTES:
            raise CohortValidationError("replay cohort exceeds 64 MiB")

    @property
    def fully_labelled(self) -> bool:
        return all(row.label is not None for row in self.rows)

    def summary(self) -> dict[str, object]:
        """Return exact metadata without exporting replay event content."""
        return {
            "schema": self.schema,
            "source_id": self.source_id,
            "source_kind": self.source_kind,
            "source_digest": self.source_digest,
            "cohort_digest": self.cohort_digest,
            "high_water": self.high_water,
            "row_count": len(self.rows),
            "fully_labelled": self.fully_labelled,
            "loss": asdict(self.loss),
        }


def _event_payload(value: object) -> tuple[str, Mapping[str, Any], bool | None, str | None]:
    if isinstance(value, EvidenceEnvelope):
        document = value.to_dict()
        attributes = dict(document.get("attributes") or {})
        event = {
            **attributes,
            "activity": document["activity"],
            "category": document["category"],
            "confidence": document["confidence"],
            "message": document["message"],
            "module": document["module"],
            "severity": document["severity"],
            "source": document["source"],
        }
        provenance = document.get("provenance") or {}
        raw_label = provenance.get("malicious") if isinstance(provenance, Mapping) else None
        label = raw_label if type(raw_label) is bool else None
        label_source = (
            str(provenance.get("label_source"))
            if label is not None and provenance.get("label_source")
            else ("evidence-provenance" if label is not None else None)
        )
        return value.event_id, event, label, label_source
    if not isinstance(value, Mapping):
        raise CohortValidationError("replay rows must be mappings or EvidenceEnvelope objects")
    if "event" in value:
        event = value.get("event")
        event_id = value.get("event_id")
        label = value.get("label")
        label_source = value.get("label_source")
    else:
        event = {key: item for key, item in value.items() if key not in {
            "event_id", "revision", "label", "label_source"
        }}
        event_id = value.get("event_id")
        label = value.get("label")
        label_source = value.get("label_source")
    if not isinstance(event, Mapping):
        raise CohortValidationError("replay row event must be an object")
    identifier = _bounded_text(event_id, "event_id", 128)
    if label is not None and type(label) is not bool:
        raise CohortValidationError("label must be true, false, or null")
    if label is None:
        label_source = None
    else:
        label_source = _bounded_text(label_source, "label_source", 160)
    return identifier, dict(event), label, label_source


def capture_replay_cohort(
    rows: Iterable[object],
    *,
    source_id: str,
    source_kind: str,
    high_water: int,
    loss: CohortLoss | None = None,
    captured_at: float | None = None,
) -> ReplayCohort:
    """Copy and seal only rows at or below ``high_water``.

    Each mapping must carry ``event_id`` and ``revision``.  Rows observed after
    the supplied high-water mark are excluded and counted in loss metadata;
    they can never silently alter an already-issued evaluation receipt.
    """
    _bounded_text(source_id, "source_id", 240)
    if source_kind not in _SOURCE_KINDS:
        raise CohortValidationError("unsupported replay source kind")
    if type(high_water) is not int or high_water < 0:
        raise CohortValidationError("high_water must be a non-negative integer")
    base_loss = loss or CohortLoss()
    admitted: list[ReplayRow] = []
    excluded = 0
    total = 0
    for index, value in enumerate(rows):
        if index >= MAX_COHORT_ROWS + 100_000:
            raise CohortValidationError("replay source exceeds its scan bound")
        revision_value = (
            value.get("revision", index + 1) if isinstance(value, Mapping) else index + 1
        )
        if type(revision_value) is not int or revision_value < 0:
            raise CohortValidationError("revision must be a non-negative integer")
        if revision_value > high_water:
            excluded += 1
            continue
        event_id, event, label, label_source = _event_payload(value)
        event_bytes = _canonical(event)
        if len(event_bytes) > MAX_EVENT_BYTES:
            raise CohortValidationError("replay event exceeds 256 KiB")
        total += len(event_bytes)
        if total > MAX_COHORT_BYTES:
            raise CohortValidationError("replay cohort exceeds 64 MiB")
        admitted.append(
            ReplayRow(
                event_id=event_id,
                revision=revision_value,
                event_json=event_bytes.decode("utf-8"),
                label=label,
                label_source=label_source,
            )
        )
        if len(admitted) > MAX_COHORT_ROWS:
            raise CohortValidationError(f"replay cohort exceeds {MAX_COHORT_ROWS} rows")
    if not admitted:
        raise CohortValidationError("replay cohort must contain at least one admitted row")
    admitted.sort(key=lambda row: (row.revision, row.event_id))
    exact_loss = CohortLoss(
        overflow=base_loss.overflow,
        dropped_rows=base_loss.dropped_rows,
        incomplete_reason=base_loss.incomplete_reason,
        excluded_after_high_water=base_loss.excluded_after_high_water + excluded,
    )
    source_body = {
        "high_water": high_water,
        "rows": [row.canonical_record() for row in admitted],
        "source_id": source_id,
        "source_kind": source_kind,
    }
    source_digest = _sha256(source_body)
    stamp = time.time() if captured_at is None else float(captured_at)
    cohort_body = {
        "captured_at": stamp,
        "high_water": high_water,
        "loss": asdict(exact_loss),
        "rows": source_body["rows"],
        "schema": COHORT_SCHEMA,
        "source_digest": source_digest,
        "source_id": source_id,
        "source_kind": source_kind,
    }
    return ReplayCohort(
        source_id=source_id,
        source_kind=source_kind,
        high_water=high_water,
        rows=tuple(admitted),
        loss=exact_loss,
        source_digest=source_digest,
        cohort_digest=_sha256(cohort_body),
        captured_at=stamp,
    )


@dataclass(frozen=True)
class RuleReplayStats:
    package_id: str
    package_digest: str
    side: str
    evaluated_rows: int
    matched_event_ids: tuple[str, ...]
    elapsed_ms: float
    maximum_event_ms: float
    max_eval_ms: float
    max_events_per_second: int
    budget_violations: int
    errors: tuple[str, ...]

    @property
    def complete(self) -> bool:
        return not self.errors and self.budget_violations == 0


@dataclass(frozen=True)
class DetectionComparison:
    cohort_digest: str
    source_digest: str
    source_kind: str
    high_water: int
    row_count: int
    loss: CohortLoss
    active_digests: tuple[str, ...]
    candidate_digests: tuple[str, ...]
    active_event_ids: tuple[str, ...]
    candidate_event_ids: tuple[str, ...]
    new_event_ids: tuple[str, ...]
    lost_event_ids: tuple[str, ...]
    shared_event_ids: tuple[str, ...]
    rule_stats: tuple[RuleReplayStats, ...]
    complete: bool
    reasons: tuple[str, ...]
    precision: float | None
    recall: float | None
    metric_reason: str
    labels_used: int
    evaluation_digest: str
    evaluated_at: float
    schema: str = EVALUATION_SCHEMA

    def assert_intact(self) -> None:
        if self.schema != EVALUATION_SCHEMA:
            raise DetectionEvaluationError("unsupported evaluation schema")
        if self.source_kind not in SOURCE_KIND_CODES:
            raise DetectionEvaluationError("unsupported evaluation source kind")
        for name in ("cohort_digest", "source_digest", "evaluation_digest"):
            value = getattr(self, name)
            if (
                not isinstance(value, str)
                or len(value) != 71
                or not value.startswith("sha256:")
                or any(character not in "0123456789abcdef" for character in value[7:])
            ):
                raise DetectionEvaluationError(f"{name} is not a lowercase SHA-256 digest")
        for name in ("high_water", "row_count", "labels_used"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise DetectionEvaluationError(f"{name} must be a non-negative integer")
        if self.row_count < 1 or self.labels_used > self.row_count:
            raise DetectionEvaluationError("evaluation row or label count is invalid")
        if not isinstance(self.loss, CohortLoss):
            raise DetectionEvaluationError("evaluation loss metadata is invalid")
        if (
            isinstance(self.evaluated_at, bool)
            or not isinstance(self.evaluated_at, (int, float))
            or not math.isfinite(float(self.evaluated_at))
            or float(self.evaluated_at) <= 0
        ):
            raise DetectionEvaluationError("evaluated_at must be a positive finite timestamp")
        if type(self.complete) is not bool:
            raise DetectionEvaluationError("evaluation completeness must be boolean")

        for name in ("active_digests", "candidate_digests"):
            values = getattr(self, name)
            if not isinstance(values, tuple) or len(values) > MAX_RULES_PER_SIDE:
                raise DetectionEvaluationError(f"{name} is invalid")
            if len(values) != len(set(values)):
                raise DetectionEvaluationError(f"{name} contains a duplicate")
            for value in values:
                if (
                    not isinstance(value, str)
                    or len(value) != 71
                    or not value.startswith("sha256:")
                    or any(character not in "0123456789abcdef" for character in value[7:])
                ):
                    raise DetectionEvaluationError(f"{name} contains an invalid digest")
        if not self.candidate_digests:
            raise DetectionEvaluationError("evaluation requires a candidate digest")

        event_sets: dict[str, set[str]] = {}
        for name in (
            "active_event_ids", "candidate_event_ids", "new_event_ids",
            "lost_event_ids", "shared_event_ids",
        ):
            values = getattr(self, name)
            if not isinstance(values, tuple) or len(values) > self.row_count:
                raise DetectionEvaluationError(f"{name} is invalid")
            if tuple(sorted(set(values))) != values:
                raise DetectionEvaluationError(f"{name} is not a unique canonical tuple")
            for value in values:
                if (
                    not isinstance(value, str)
                    or not 1 <= len(value) <= 128
                    or "\x00" in value
                ):
                    raise DetectionEvaluationError(f"{name} contains an invalid event ID")
            event_sets[name] = set(values)
        active_set = event_sets["active_event_ids"]
        candidate_set = event_sets["candidate_event_ids"]
        if event_sets["new_event_ids"] != candidate_set - active_set:
            raise DetectionEvaluationError("new-event comparison set is inconsistent")
        if event_sets["lost_event_ids"] != active_set - candidate_set:
            raise DetectionEvaluationError("lost-event comparison set is inconsistent")
        if event_sets["shared_event_ids"] != active_set & candidate_set:
            raise DetectionEvaluationError("shared-event comparison set is inconsistent")

        if not isinstance(self.rule_stats, tuple) or len(self.rule_stats) != (
            len(self.active_digests) + len(self.candidate_digests)
        ):
            raise DetectionEvaluationError("rule replay statistics are incomplete")
        active_matches: set[str] = set()
        candidate_matches: set[str] = set()
        stat_digests: dict[str, list[str]] = {"active": [], "candidate": []}
        for stat in self.rule_stats:
            if not isinstance(stat, RuleReplayStats) or stat.side not in {"active", "candidate"}:
                raise DetectionEvaluationError("rule replay statistic is invalid")
            expected_digests = (
                self.active_digests if stat.side == "active" else self.candidate_digests
            )
            if stat.package_digest not in expected_digests:
                raise DetectionEvaluationError("rule replay digest is not bound to its side")
            if (
                not isinstance(stat.package_id, str)
                or not 1 <= len(stat.package_id) <= 128
                or "\x00" in stat.package_id
            ):
                raise DetectionEvaluationError("rule replay package identity is invalid")
            if type(stat.evaluated_rows) is not int or not 0 <= stat.evaluated_rows <= self.row_count:
                raise DetectionEvaluationError("rule replay row count is invalid")
            if type(stat.budget_violations) is not int or stat.budget_violations < 0:
                raise DetectionEvaluationError("rule replay budget count is invalid")
            for value in (stat.elapsed_ms, stat.maximum_event_ms, stat.max_eval_ms):
                if (
                    isinstance(value, bool)
                    or not isinstance(value, (int, float))
                    or not math.isfinite(float(value))
                    or float(value) < 0
                ):
                    raise DetectionEvaluationError("rule replay timing is invalid")
            if type(stat.max_events_per_second) is not int or stat.max_events_per_second < 1:
                raise DetectionEvaluationError("rule replay rate budget is invalid")
            if tuple(sorted(set(stat.matched_event_ids))) != stat.matched_event_ids:
                raise DetectionEvaluationError("rule replay matches are not canonical")
            if any(
                not isinstance(error, str) or len(error) > 512 or "\x00" in error
                for error in stat.errors
            ):
                raise DetectionEvaluationError("rule replay error metadata is invalid")
            target = active_matches if stat.side == "active" else candidate_matches
            target.update(stat.matched_event_ids)
            stat_digests[stat.side].append(stat.package_digest)
        if tuple(stat_digests["active"]) != self.active_digests:
            raise DetectionEvaluationError("active rule replay order is incomplete")
        if tuple(stat_digests["candidate"]) != self.candidate_digests:
            raise DetectionEvaluationError("candidate rule replay order is incomplete")
        if active_matches != active_set or candidate_matches != candidate_set:
            raise DetectionEvaluationError("rule replay matches do not reproduce comparison sets")

        expected_reasons: list[str] = []
        if not self.loss.complete:
            expected_reasons.append(
                "cohort source reported evidence loss or incomplete custody"
            )
        if any(not item.complete for item in self.rule_stats):
            expected_reasons.append("rule replay failed budget or execution gates")
        if self.reasons != tuple(expected_reasons):
            raise DetectionEvaluationError("evaluation reason set is not a closed valid set")
        if self.complete != (not expected_reasons):
            raise DetectionEvaluationError("evaluation completeness is inconsistent")
        if self.metric_reason not in _METRIC_REASON_CODES:
            raise DetectionEvaluationError("evaluation metric reason is not a closed code source")
        for name in ("precision", "recall"):
            value = getattr(self, name)
            if value is not None and (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                or not 0.0 <= float(value) <= 1.0
            ):
                raise DetectionEvaluationError(f"{name} is not a finite ratio")
        if not self.complete:
            expected_metric_reason = (
                "withheld: cohort has source loss or incomplete custody"
                if not self.loss.complete
                else "withheld: evaluation is incomplete or exceeded a work gate"
            )
            if self.metric_reason != expected_metric_reason or self.labels_used != 0:
                raise DetectionEvaluationError("incomplete evaluation metric disposition is invalid")
        elif self.labels_used == 0:
            if (
                self.metric_reason != "withheld: cohort is not fully labelled"
                or self.precision is not None
                or self.recall is not None
            ):
                raise DetectionEvaluationError("unlabelled evaluation metric disposition is invalid")
        elif self.labels_used != self.row_count:
            raise DetectionEvaluationError("labelled evaluation count is incomplete")
        body = self.to_dict(include_digest=False)
        expected = _sha256(body)
        if not hmac.compare_digest(self.evaluation_digest, expected):
            raise DetectionEvaluationError("evaluation digest verification failed")

    @property
    def reason_codes(self) -> tuple[str, ...]:
        """Return closed, export-safe explanations after integrity validation."""
        self.assert_intact()
        return tuple(_REASON_CODES[value] for value in self.reasons)

    @property
    def metric_reason_code(self) -> str:
        """Return a closed, export-safe metric disposition code."""
        self.assert_intact()
        return _METRIC_REASON_CODES[self.metric_reason]

    def to_dict(self, *, include_digest: bool = True) -> dict[str, object]:
        document: dict[str, object] = {
            "schema": self.schema,
            "cohort_digest": self.cohort_digest,
            "source_digest": self.source_digest,
            "source_kind": self.source_kind,
            "high_water": self.high_water,
            "row_count": self.row_count,
            "loss": asdict(self.loss),
            "active_digests": list(self.active_digests),
            "candidate_digests": list(self.candidate_digests),
            "active_event_ids": list(self.active_event_ids),
            "candidate_event_ids": list(self.candidate_event_ids),
            "new_event_ids": list(self.new_event_ids),
            "lost_event_ids": list(self.lost_event_ids),
            "shared_event_ids": list(self.shared_event_ids),
            "rule_stats": [asdict(item) for item in self.rule_stats],
            "complete": self.complete,
            "reasons": list(self.reasons),
            "precision": self.precision,
            "recall": self.recall,
            "metric_reason": self.metric_reason,
            "labels_used": self.labels_used,
            "evaluated_at": self.evaluated_at,
        }
        if include_digest:
            document["evaluation_digest"] = self.evaluation_digest
        return document


@dataclass(frozen=True)
class _BoundPackage:
    package: DetectionPackage
    package_id: str
    digest: str
    max_eval_ms: float
    max_events_per_second: int


def _bind_package(package: DetectionPackage) -> _BoundPackage:
    if not isinstance(package, DetectionPackage):
        raise DetectionEvaluationError("replay rules must be DetectionPackage instances")
    # Copy through strict canonical JSON so a caller-owned package mapping
    # cannot be altered after admission.
    try:
        document = json.loads(_canonical(dict(package.document)).decode("utf-8"))
        validate_package(document)
    except Exception as exc:
        raise DetectionEvaluationError(f"package binding failed: {exc}") from exc
    snapshot = DetectionPackage(document)
    performance = document["performance"]
    return _BoundPackage(
        package=snapshot,
        package_id=snapshot.package_id,
        digest=str(document["digest"]),
        max_eval_ms=float(performance["max_eval_ms"]),
        max_events_per_second=int(performance["max_events_per_second"]),
    )


def _bind_side(value: DetectionPackage | Sequence[DetectionPackage] | None) -> tuple[_BoundPackage, ...]:
    if value is None:
        return ()
    packages = (value,) if isinstance(value, DetectionPackage) else tuple(value)
    if len(packages) > MAX_RULES_PER_SIDE:
        raise DetectionEvaluationError("package side exceeds 128 rules")
    bound = tuple(_bind_package(package) for package in packages)
    digests = [item.digest for item in bound]
    if len(digests) != len(set(digests)):
        raise DetectionEvaluationError("a package digest cannot appear twice on one side")
    return bound


def _evaluate_rule(
    cohort: ReplayCohort,
    rule: _BoundPackage,
    side: str,
    *,
    deadline: float,
) -> RuleReplayStats:
    matches: list[str] = []
    errors: list[str] = []
    violations = 0
    maximum = 0.0
    evaluated = 0
    started = time.perf_counter()
    for row in cohort.rows:
        if time.perf_counter() >= deadline:
            errors.append("replay wall-clock work budget exhausted")
            break
        event_started = time.perf_counter()
        try:
            matched = bool(rule.package.evaluate(row.event()))
        except Exception as exc:  # DetectionPackage currently fails closed; retain hardening.
            errors.append(f"{row.event_id}: {type(exc).__name__}")
            matched = False
        elapsed = (time.perf_counter() - event_started) * 1000.0
        maximum = max(maximum, elapsed)
        evaluated += 1
        if elapsed > rule.max_eval_ms:
            violations += 1
        if matched:
            matches.append(row.event_id)
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    return RuleReplayStats(
        package_id=rule.package_id,
        package_digest=rule.digest,
        side=side,
        evaluated_rows=evaluated,
        matched_event_ids=tuple(sorted(matches)),
        elapsed_ms=elapsed_ms,
        maximum_event_ms=maximum,
        max_eval_ms=rule.max_eval_ms,
        max_events_per_second=rule.max_events_per_second,
        budget_violations=violations,
        errors=tuple(errors[:64]),
    )


def compare_detection_packages(
    cohort: ReplayCohort,
    *,
    active: DetectionPackage | Sequence[DetectionPackage] | None,
    candidate: DetectionPackage | Sequence[DetectionPackage],
    evaluated_at: float | None = None,
) -> DetectionComparison:
    """Replay an exact cohort against active and candidate rule sets."""
    cohort.assert_intact()
    active_rules = _bind_side(active)
    candidate_rules = _bind_side(candidate)
    if not candidate_rules:
        raise DetectionEvaluationError("at least one candidate package is required")
    evaluation_count = len(cohort.rows) * (len(active_rules) + len(candidate_rules))
    if evaluation_count > MAX_REPLAY_EVALUATIONS:
        raise DetectionEvaluationError(
            "replay request exceeds its bounded rule-event work budget"
        )
    deadline = time.perf_counter() + (MAX_REPLAY_WALL_MS / 1000.0)
    stats = tuple(
        [
            _evaluate_rule(cohort, item, "active", deadline=deadline)
            for item in active_rules
        ]
        + [
            _evaluate_rule(cohort, item, "candidate", deadline=deadline)
            for item in candidate_rules
        ]
    )
    active_ids = sorted({
        event_id
        for item in stats if item.side == "active"
        for event_id in item.matched_event_ids
    })
    candidate_ids = sorted({
        event_id
        for item in stats if item.side == "candidate"
        for event_id in item.matched_event_ids
    })
    active_set, candidate_set = set(active_ids), set(candidate_ids)
    reasons: list[str] = []
    if not cohort.loss.complete:
        reasons.append("cohort source reported evidence loss or incomplete custody")
    failed_rules = [item for item in stats if not item.complete]
    if failed_rules:
        reasons.append("rule replay failed budget or execution gates")
    complete = not reasons

    precision: float | None = None
    recall: float | None = None
    labels_used = 0
    if not complete:
        metric_reason = (
            "withheld: cohort has source loss or incomplete custody"
            if not cohort.loss.complete
            else "withheld: evaluation is incomplete or exceeded a work gate"
        )
    elif not cohort.fully_labelled:
        metric_reason = "withheld: cohort is not fully labelled"
    elif not cohort.loss.complete:
        metric_reason = "withheld: cohort has source loss or incomplete custody"
    else:
        labels_used = len(cohort.rows)
        positives = {row.event_id for row in cohort.rows if row.label is True}
        true_positives = candidate_set & positives
        if candidate_set:
            precision = len(true_positives) / len(candidate_set)
        if positives:
            recall = len(true_positives) / len(positives)
        if precision is None and recall is None:
            metric_reason = "unavailable: labelled cohort has no predicted or actual positives"
        elif precision is None:
            metric_reason = "partial: no candidate positives; recall remains defined"
        elif recall is None:
            metric_reason = "partial: no labelled positives; precision remains defined"
        else:
            metric_reason = "complete labelled-cohort metrics"

    stamp = time.time() if evaluated_at is None else float(evaluated_at)
    if not math.isfinite(stamp) or stamp <= 0:
        raise DetectionEvaluationError("evaluated_at must be a positive finite timestamp")
    body: dict[str, object] = {
        "schema": EVALUATION_SCHEMA,
        "cohort_digest": cohort.cohort_digest,
        "source_digest": cohort.source_digest,
        "source_kind": cohort.source_kind,
        "high_water": cohort.high_water,
        "row_count": len(cohort.rows),
        "loss": asdict(cohort.loss),
        "active_digests": [item.digest for item in active_rules],
        "candidate_digests": [item.digest for item in candidate_rules],
        "active_event_ids": active_ids,
        "candidate_event_ids": candidate_ids,
        "new_event_ids": sorted(candidate_set - active_set),
        "lost_event_ids": sorted(active_set - candidate_set),
        "shared_event_ids": sorted(active_set & candidate_set),
        "rule_stats": [asdict(item) for item in stats],
        "complete": complete,
        "reasons": reasons,
        "precision": precision,
        "recall": recall,
        "metric_reason": metric_reason,
        "labels_used": labels_used,
        "evaluated_at": stamp,
    }
    comparison = DetectionComparison(
        cohort_digest=cohort.cohort_digest,
        source_digest=cohort.source_digest,
        source_kind=cohort.source_kind,
        high_water=cohort.high_water,
        row_count=len(cohort.rows),
        loss=cohort.loss,
        active_digests=tuple(item.digest for item in active_rules),
        candidate_digests=tuple(item.digest for item in candidate_rules),
        active_event_ids=tuple(active_ids),
        candidate_event_ids=tuple(candidate_ids),
        new_event_ids=tuple(body["new_event_ids"]),  # type: ignore[arg-type]
        lost_event_ids=tuple(body["lost_event_ids"]),  # type: ignore[arg-type]
        shared_event_ids=tuple(body["shared_event_ids"]),  # type: ignore[arg-type]
        rule_stats=stats,
        complete=complete,
        reasons=tuple(reasons),
        precision=precision,
        recall=recall,
        metric_reason=metric_reason,
        labels_used=labels_used,
        evaluation_digest=_sha256(body),
        evaluated_at=stamp,
    )
    comparison.assert_intact()
    return comparison


# Friendly aliases for service/UI callers.
capture_cohort = capture_replay_cohort
compare_packages = compare_detection_packages


__all__ = [
    "COHORT_SCHEMA",
    "EVALUATION_SCHEMA",
    "CohortLoss",
    "CohortValidationError",
    "DetectionComparison",
    "DetectionEvaluationError",
    "EVALUATION_REASON_CODES",
    "METRIC_REASON_CODES",
    "ReplayCohort",
    "ReplayRow",
    "RuleReplayStats",
    "SOURCE_KIND_CODES",
    "capture_cohort",
    "capture_replay_cohort",
    "compare_detection_packages",
    "compare_packages",
]
