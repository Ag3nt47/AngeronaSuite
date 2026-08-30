"""Immutable, evidence-bound exposure graph primitives for AegisPath.

The graph is deliberately a read-side model.  It has no adapters for sockets,
processes, the EventBus, SOAR, or host configuration.  Labels and properties
are inert data, and every relationship carries an explicit evidence binding so
that absence, age, provenance, privacy, and collection generation remain
visible to downstream analysis.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum
from heapq import nsmallest
from typing import Any, Callable


GRAPH_SCHEMA = "angerona.aegis-path.exposure-graph.v1"
COVERAGE_SCHEMA = "angerona.aegis-path.coverage-manifest.v1"
ABSENCE_SCHEMA = "angerona.aegis-path.relationship-absence.v1"
DEFAULT_MAX_NODES = 2_048
DEFAULT_MAX_EDGES = 8_192
HARD_MAX_NODES = 16_384
HARD_MAX_EDGES = 65_536
HARD_INPUT_NODES = 131_072
HARD_INPUT_EDGES = 524_288

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$")
_PROPERTY_KEY = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_CVE = re.compile(r"^CVE-[12][0-9]{3}-[0-9]{4,}$")
DEFAULT_SCOPE_ID = "local-host"
DEFAULT_POLICY_DIGEST = "sha256:" + hashlib.sha256(
    b"angerona/aegis-path/default-observe-only-policy/v1"
).hexdigest()


class NodeKind(str, Enum):
    ENTRY_POINT = "entry_point"
    ASSET = "asset"
    IDENTITY = "identity"
    SERVICE = "service"
    SOFTWARE = "software"
    VULNERABILITY = "vulnerability"
    CONTROL = "control"
    DATA = "data"
    ZONE = "zone"
    TARGET = "target"


class EdgeKind(str, Enum):
    EXPOSES = "exposes"
    REACHES = "reaches"
    AUTHENTICATES = "authenticates"
    RUNS = "runs"
    AFFECTED_BY = "affected_by"
    TRUSTS = "trusts"
    CONTAINS = "contains"
    PROTECTED_BY = "protected_by"
    TRANSITS = "transits"
    IMPACTS = "impacts"


class EvidenceProvenance(str, Enum):
    SENSOR = "sensor"
    INVENTORY = "inventory"
    CONFIGURATION = "configuration"
    SCANNER = "scanner"
    THREAT_INTELLIGENCE = "threat_intelligence"
    ANALYST_ATTESTATION = "analyst_attestation"
    SIGNED_IMPORT = "signed_import"


class EvidenceFreshness(str, Enum):
    CURRENT = "current"
    STALE = "stale"
    MISSING = "missing"
    UNKNOWN = "unknown"


class PrivacyClass(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    SENSITIVE = "sensitive"
    RESTRICTED = "restricted"


class AssertionState(str, Enum):
    CONFIRMED = "confirmed"
    SPECULATIVE = "speculative"
    CLOSED = "closed"


class Applicability(str, Enum):
    EXACT = "exact"
    ASSUMED = "assumed"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"


class ResourceStatus(str, Enum):
    COMPLETE = "COMPLETE"
    INCOMPLETE_RESOURCE_LIMIT = "INCOMPLETE_RESOURCE_LIMIT"


class CoverageStatus(str, Enum):
    """Semantic scope state, deliberately separate from processing status."""

    VERIFIED = "VERIFIED"
    UNVERIFIED = "UNVERIFIED"
    UNUSABLE = "UNUSABLE"


class CoverageDomain(str, Enum):
    """Closed semantic domain for an explicit no-relationship assertion."""

    EXPOSURE_RELATIONSHIPS = "declared-exposure-relationships"


def _finite(value: object, name: str, *, minimum: float = 0.0) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a finite number")
    rendered = float(value)
    if not math.isfinite(rendered) or rendered < minimum:
        raise ValueError(f"{name} must be a finite number >= {minimum}")
    return rendered


def _bounded_text(value: object, name: str, limit: int, *, empty: bool = False) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be text")
    if "\x00" in value or len(value) > limit or (not empty and not value.strip()):
        raise ValueError(f"{name} is empty or exceeds its bounded schema")
    return value


def _identifier(value: object, name: str) -> str:
    rendered = _bounded_text(value, name, 128)
    if not _ID.fullmatch(rendered):
        raise ValueError(f"{name} is not a valid bounded identifier")
    return rendered


def _generation(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("generation must be a non-negative integer")
    return value


def _enum(value: object, expected: type[Enum], name: str) -> None:
    if not isinstance(value, expected):
        raise ValueError(f"{name} must use the closed {expected.__name__} enum")


@dataclass(frozen=True, slots=True)
class ExposureNode:
    node_id: str
    kind: NodeKind
    label: str
    criticality: int = 0
    cve_id: str = ""
    known_exploited: bool | None = None
    epss: float | None = None
    control_effectiveness: float | None = None
    properties: tuple[tuple[str, str], ...] = ()
    threat_evidence: EvidenceBinding | None = None

    def __post_init__(self) -> None:
        _identifier(self.node_id, "node_id")
        _enum(self.kind, NodeKind, "kind")
        _bounded_text(self.label, "label", 512)
        if isinstance(self.criticality, bool) or not isinstance(self.criticality, int):
            raise ValueError("criticality must be an integer from 0 through 5")
        if not 0 <= self.criticality <= 5:
            raise ValueError("criticality must be an integer from 0 through 5")
        if self.cve_id:
            if self.kind is not NodeKind.VULNERABILITY or not _CVE.fullmatch(self.cve_id):
                raise ValueError("cve_id requires a vulnerability node and exact CVE syntax")
        if self.known_exploited is not None and not isinstance(
            self.known_exploited, bool
        ):
            raise ValueError("known_exploited must be true, false, or unknown")
        if self.epss is not None:
            epss = _finite(self.epss, "epss")
            if epss > 1.0:
                raise ValueError("epss must be between 0 and 1")
        if self.control_effectiveness is not None:
            effectiveness = _finite(self.control_effectiveness, "control_effectiveness")
            if effectiveness > 1.0:
                raise ValueError("control_effectiveness must be between 0 and 1")
        if self.threat_evidence is not None:
            if self.kind is not NodeKind.VULNERABILITY or not isinstance(
                self.threat_evidence, EvidenceBinding
            ):
                raise ValueError("threat evidence requires a vulnerability node")
            if self.threat_evidence.provenance not in {
                EvidenceProvenance.THREAT_INTELLIGENCE,
                EvidenceProvenance.SIGNED_IMPORT,
            }:
                raise ValueError("KEV/EPSS evidence requires threat-intelligence provenance")
            if not self.threat_evidence.digest or self.threat_evidence.expires_at <= 0.0:
                raise ValueError("KEV/EPSS evidence must be content-bound and time-bounded")
        if (self.known_exploited is not None or self.epss is not None) and (
            self.threat_evidence is None
        ):
            raise ValueError("KEV/EPSS values require bound threat evidence")
        if not isinstance(self.properties, tuple) or any(
            not isinstance(item, tuple) or len(item) != 2 for item in self.properties
        ):
            raise ValueError("properties must be an immutable tuple of key/value tuples")
        previous = ""
        for key, value in self.properties:
            if not isinstance(key, str) or not _PROPERTY_KEY.fullmatch(key):
                raise ValueError("property key is outside the closed bounded schema")
            _bounded_text(value, f"property {key}", 512, empty=True)
            if key <= previous:
                raise ValueError("properties must be unique and sorted by key")
            previous = key


@dataclass(frozen=True, slots=True)
class EvidenceBinding:
    evidence_id: str
    source: str
    provenance: EvidenceProvenance
    freshness: EvidenceFreshness
    confidence: float
    privacy: PrivacyClass
    generation: int
    observed_at: float
    expires_at: float = 0.0
    digest: str = ""

    def __post_init__(self) -> None:
        _identifier(self.evidence_id, "evidence_id")
        _bounded_text(self.source, "source", 256)
        _enum(self.provenance, EvidenceProvenance, "provenance")
        _enum(self.freshness, EvidenceFreshness, "freshness")
        _enum(self.privacy, PrivacyClass, "privacy")
        confidence = _finite(self.confidence, "confidence")
        if confidence > 1.0:
            raise ValueError("confidence must be between 0 and 1")
        _generation(self.generation)
        observed = _finite(self.observed_at, "observed_at")
        expires = _finite(self.expires_at, "expires_at")
        if expires and expires < observed:
            raise ValueError("expires_at cannot precede observed_at")
        if self.digest and not re.fullmatch(r"sha256:[0-9a-f]{64}", self.digest):
            raise ValueError("evidence digest must be an exact SHA-256 token")


def evidence_is_current_bound(
    evidence: object,
    *,
    at_time: float,
    generation: int | None = None,
) -> bool:
    """Return whether evidence is current, content-bound, and finitely leased.

    ``CURRENT`` is only a producer label.  Decision code additionally requires
    positive confidence, a SHA-256 content binding, an observation no later
    than the decision, and an expiry strictly after it.  A zero expiry is
    deliberately unbounded and therefore never decision-current.
    """
    if not isinstance(evidence, EvidenceBinding):
        return False
    try:
        current = _finite(at_time, "at_time")
    except (TypeError, ValueError, OverflowError):
        return False
    return bool(
        evidence.freshness is EvidenceFreshness.CURRENT
        and evidence.confidence > 0.0
        and evidence.digest
        and evidence.observed_at <= current
        and evidence.expires_at > current
        and (generation is None or evidence.generation == generation)
    )


@dataclass(frozen=True, slots=True)
class RelationshipAbsenceAttestation:
    """Finite, content-bound authority for an exact empty relationship domain.

    This is still a local trust boundary rather than a public-key verification
    service.  It prevents an ordinary self-declared empty edge list from being
    rendered green by requiring an explicit signed-import or analyst authority
    bound to the same scope, policy, domain, generation, and finite lease.
    """

    schema: str
    scope_id: str
    policy_digest: str
    coverage_domain: CoverageDomain
    authority_id: str
    evidence: EvidenceBinding
    digest: str

    def __post_init__(self) -> None:
        if self.schema != ABSENCE_SCHEMA:
            raise ValueError("relationship absence schema is not supported")
        _identifier(self.scope_id, "scope_id")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", self.policy_digest):
            raise ValueError("policy_digest must be an exact SHA-256 token")
        _enum(self.coverage_domain, CoverageDomain, "coverage_domain")
        _identifier(self.authority_id, "authority_id")
        if not isinstance(self.evidence, EvidenceBinding):
            raise ValueError("relationship absence requires bound authority evidence")
        if self.evidence.provenance not in {
            EvidenceProvenance.ANALYST_ATTESTATION,
            EvidenceProvenance.SIGNED_IMPORT,
        }:
            raise ValueError(
                "relationship absence authority must be analyst-attested or signed"
            )
        if not evidence_is_current_bound(
            self.evidence,
            at_time=self.evidence.observed_at,
            generation=self.evidence.generation,
        ):
            raise ValueError(
                "relationship absence authority must be current, finite, and content-bound"
            )
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", self.digest):
            raise ValueError("relationship absence digest must be an exact SHA-256 token")


@dataclass(frozen=True, slots=True)
class CoverageManifest:
    """Provider attestation describing the exact scope expected in one snapshot.

    The digest is tamper-evident, not an external signature. Trust in the
    manifest remains trust in the local provider/collector authority.
    """

    schema: str
    scope_id: str
    policy_digest: str
    expected_node_ids: tuple[str, ...]
    expected_edge_ids: tuple[str, ...]
    declared_complete: bool
    attested_at: float
    expires_at: float
    trust_basis: str
    digest: str
    relationship_absence: RelationshipAbsenceAttestation | None = None

    def __post_init__(self) -> None:
        if self.schema != COVERAGE_SCHEMA:
            raise ValueError("coverage manifest schema is not supported")
        _identifier(self.scope_id, "scope_id")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", self.policy_digest):
            raise ValueError("policy_digest must be an exact SHA-256 token")
        for name, rows, hard_limit in (
            ("expected_node_ids", self.expected_node_ids, HARD_MAX_NODES),
            ("expected_edge_ids", self.expected_edge_ids, HARD_MAX_EDGES),
        ):
            if not isinstance(rows, tuple) or len(rows) > hard_limit:
                raise ValueError(f"{name} must be a bounded immutable tuple")
            if tuple(sorted(rows)) != rows or len(set(rows)) != len(rows):
                raise ValueError(f"{name} must be unique and sorted")
            for value in rows:
                _identifier(value, name)
        if not isinstance(self.declared_complete, bool):
            raise ValueError("declared_complete must be boolean")
        attested = _finite(self.attested_at, "attested_at")
        expires = _finite(self.expires_at, "expires_at")
        if expires <= attested:
            raise ValueError("coverage manifest must have a bounded future expiry")
        _bounded_text(self.trust_basis, "trust_basis", 256)
        if self.relationship_absence is not None:
            if not isinstance(
                self.relationship_absence, RelationshipAbsenceAttestation
            ):
                raise ValueError(
                    "relationship_absence must use the closed attestation schema"
                )
            if self.expected_edge_ids:
                raise ValueError(
                    "relationship absence is meaningful only for an empty edge domain"
                )
            if (
                self.relationship_absence.scope_id != self.scope_id
                or self.relationship_absence.policy_digest != self.policy_digest
            ):
                raise ValueError(
                    "relationship absence must bind the manifest scope and policy"
                )
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", self.digest):
            raise ValueError("coverage manifest digest must be an exact SHA-256 token")


@dataclass(frozen=True, slots=True)
class ExposureEdge:
    edge_id: str
    source_id: str
    target_id: str
    kind: EdgeKind
    assertion: AssertionState
    applicability: Applicability
    evidence: EvidenceBinding
    reason: str
    observed_version: str = ""
    affected_range: str = ""

    def __post_init__(self) -> None:
        _identifier(self.edge_id, "edge_id")
        _identifier(self.source_id, "source_id")
        _identifier(self.target_id, "target_id")
        if self.source_id == self.target_id:
            raise ValueError("self edges are not exposure relationships")
        _enum(self.kind, EdgeKind, "kind")
        _enum(self.assertion, AssertionState, "assertion")
        _enum(self.applicability, Applicability, "applicability")
        if not isinstance(self.evidence, EvidenceBinding):
            raise ValueError("every edge requires an EvidenceBinding")
        _bounded_text(self.reason, "reason", 1_000)
        _bounded_text(self.observed_version, "observed_version", 256, empty=True)
        _bounded_text(self.affected_range, "affected_range", 512, empty=True)
        if self.applicability is Applicability.NOT_APPLICABLE and (
            self.kind is not EdgeKind.AFFECTED_BY
        ):
            raise ValueError("not_applicable is valid only for affected_by edges")
        if (
            self.kind is EdgeKind.AFFECTED_BY
            and self.assertion is AssertionState.CONFIRMED
            and self.applicability is not Applicability.EXACT
        ):
            raise ValueError("a confirmed CVE edge requires exact applicability")
        if self.kind is EdgeKind.AFFECTED_BY and (
            not self.observed_version
            or not self.affected_range
            or not self.evidence.digest
            or self.evidence.provenance
            not in {
                EvidenceProvenance.INVENTORY,
                EvidenceProvenance.SCANNER,
                EvidenceProvenance.SIGNED_IMPORT,
                EvidenceProvenance.ANALYST_ATTESTATION,
            }
        ):
            raise ValueError(
                "affected_by requires evidence-bound observed and affected versions"
            )
        if self.assertion is AssertionState.CLOSED and (
            self.evidence.freshness is not EvidenceFreshness.CURRENT
            or self.evidence.confidence <= 0.0
            or self.evidence.expires_at <= self.evidence.observed_at
            or not self.evidence.digest
            or self.applicability is Applicability.UNKNOWN
        ):
            raise ValueError(
                "missing, stale, unknown, unbound, or unbounded evidence cannot close an edge"
            )


@dataclass(frozen=True, slots=True)
class ExposureSnapshot:
    schema: str
    generation: int
    observed_at: float
    nodes: tuple[ExposureNode, ...]
    edges: tuple[ExposureEdge, ...]
    status: ResourceStatus
    truncation_reasons: tuple[str, ...]
    dropped_nodes: int
    dropped_edges: int
    scope_id: str
    policy_digest: str
    coverage_manifest: CoverageManifest | None
    coverage_status: CoverageStatus
    coverage_reasons: tuple[str, ...]
    digest: str

    def __post_init__(self) -> None:
        if self.schema != GRAPH_SCHEMA:
            raise ValueError("snapshot schema is not supported")
        _generation(self.generation)
        _finite(self.observed_at, "observed_at")
        if not isinstance(self.nodes, tuple) or any(
            not isinstance(node, ExposureNode) for node in self.nodes
        ):
            raise ValueError("snapshot nodes must be an immutable ExposureNode tuple")
        if not isinstance(self.edges, tuple) or any(
            not isinstance(edge, ExposureEdge) for edge in self.edges
        ):
            raise ValueError("snapshot edges must be an immutable ExposureEdge tuple")
        _enum(self.status, ResourceStatus, "status")
        if not isinstance(self.truncation_reasons, tuple) or any(
            not isinstance(reason, str) for reason in self.truncation_reasons
        ):
            raise ValueError("truncation reasons must be an immutable text tuple")
        for value in (self.dropped_nodes, self.dropped_edges):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError("dropped counts must be non-negative integers")
        _identifier(self.scope_id, "scope_id")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", self.policy_digest):
            raise ValueError("policy_digest must be an exact SHA-256 token")
        if self.coverage_manifest is not None and not isinstance(
            self.coverage_manifest, CoverageManifest
        ):
            raise ValueError("coverage_manifest must use the closed manifest schema")
        _enum(self.coverage_status, CoverageStatus, "coverage_status")
        if not isinstance(self.coverage_reasons, tuple) or any(
            not isinstance(reason, str) for reason in self.coverage_reasons
        ):
            raise ValueError("coverage reasons must be an immutable text tuple")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", self.digest):
            raise ValueError("snapshot digest must be an exact SHA-256 token")
        _validate_snapshot_structure(self)

    def node(self, node_id: str) -> ExposureNode:
        for node in self.nodes:
            if node.node_id == node_id:
                return node
        raise KeyError(node_id)

    def edge(self, edge_id: str) -> ExposureEdge:
        for edge in self.edges:
            if edge.edge_id == edge_id:
                return edge
        raise KeyError(edge_id)


def _node_fact(node: ExposureNode) -> dict[str, Any]:
    fact = {
        "node_id": node.node_id,
        "kind": node.kind.value,
        "label": node.label,
        "criticality": node.criticality,
        "cve_id": node.cve_id,
        "known_exploited": node.known_exploited,
        "epss": node.epss,
        "control_effectiveness": node.control_effectiveness,
        "properties": list(node.properties),
    }
    if node.threat_evidence is not None:
        fact["threat_evidence"] = _evidence_fact(node.threat_evidence)
    else:
        fact["threat_evidence"] = None
    return fact


def _evidence_fact(evidence: EvidenceBinding) -> dict[str, Any]:
    return {
        "evidence_id": evidence.evidence_id,
        "source": evidence.source,
        "provenance": evidence.provenance.value,
        "freshness": evidence.freshness.value,
        "confidence": evidence.confidence,
        "privacy": evidence.privacy.value,
        "generation": evidence.generation,
        "observed_at": evidence.observed_at,
        "expires_at": evidence.expires_at,
        "digest": evidence.digest,
    }


def _edge_fact(edge: ExposureEdge) -> dict[str, Any]:
    evidence = edge.evidence
    return {
        "edge_id": edge.edge_id,
        "source_id": edge.source_id,
        "target_id": edge.target_id,
        "kind": edge.kind.value,
        "assertion": edge.assertion.value,
        "applicability": edge.applicability.value,
        "reason": edge.reason,
        "observed_version": edge.observed_version,
        "affected_range": edge.affected_range,
        "evidence": _evidence_fact(evidence),
    }


def _absence_fact(
    attestation: RelationshipAbsenceAttestation | None,
) -> dict[str, Any] | None:
    if attestation is None:
        return None
    return {
        "schema": attestation.schema,
        "scope_id": attestation.scope_id,
        "policy_digest": attestation.policy_digest,
        "coverage_domain": attestation.coverage_domain.value,
        "authority_id": attestation.authority_id,
        "evidence": _evidence_fact(attestation.evidence),
    }


def _coverage_fact(manifest: CoverageManifest | None) -> dict[str, Any] | None:
    if manifest is None:
        return None
    return {
        "schema": manifest.schema,
        "scope_id": manifest.scope_id,
        "policy_digest": manifest.policy_digest,
        "expected_node_ids": list(manifest.expected_node_ids),
        "expected_edge_ids": list(manifest.expected_edge_ids),
        "declared_complete": manifest.declared_complete,
        "attested_at": manifest.attested_at,
        "expires_at": manifest.expires_at,
        "trust_basis": manifest.trust_basis,
        "relationship_absence": _absence_fact(manifest.relationship_absence),
    }


def _validate_snapshot_structure(
    snapshot: ExposureSnapshot,
    *,
    work_guard: Callable[[int], bool] | None = None,
) -> None:
    """Enforce builder-equivalent hard caps and graph invariants on direct values."""
    if len(snapshot.nodes) > HARD_MAX_NODES or len(snapshot.edges) > HARD_MAX_EDGES:
        raise ValueError("snapshot exceeds hard structural verification bounds")
    if work_guard is not None and not work_guard(512):
        raise _VerificationAborted("snapshot verification budget exhausted")
    node_ids: list[str] = []
    node_by_id: dict[str, ExposureNode] = {}
    for index, node in enumerate(snapshot.nodes):
        if index % 32 == 0 and work_guard is not None and not work_guard(256):
            raise _VerificationAborted("snapshot verification budget exhausted")
        if not isinstance(node, ExposureNode):
            raise ValueError("snapshot nodes must use the closed node schema")
        node_ids.append(node.node_id)
        node_by_id[node.node_id] = node
        threat = node.threat_evidence
        if threat is not None and (
            threat.generation != snapshot.generation
            or threat.observed_at > snapshot.observed_at
        ):
            raise ValueError("threat evidence is outside the snapshot generation")
    if tuple(node_ids) != tuple(sorted(node_ids)) or len(node_ids) != len(set(node_ids)):
        raise ValueError("snapshot node identifiers must be unique and sorted")

    edge_ids: list[str] = []
    for index, edge in enumerate(snapshot.edges):
        if index % 32 == 0 and work_guard is not None and not work_guard(384):
            raise _VerificationAborted("snapshot verification budget exhausted")
        if not isinstance(edge, ExposureEdge):
            raise ValueError("snapshot edges must use the closed edge schema")
        edge_ids.append(edge.edge_id)
        if edge.source_id not in node_by_id or edge.target_id not in node_by_id:
            raise ValueError("snapshot edge endpoint is not admitted")
        if (
            edge.evidence.generation != snapshot.generation
            or edge.evidence.observed_at > snapshot.observed_at
        ):
            raise ValueError("edge evidence is outside the snapshot generation")
        if edge.assertion is AssertionState.CLOSED and (
            edge.evidence.expires_at <= snapshot.observed_at
            or not evidence_is_current_bound(
                edge.evidence,
                at_time=snapshot.observed_at,
                generation=snapshot.generation,
            )
        ):
            raise ValueError("closed edge evidence is not current at snapshot time")
        if edge.kind is EdgeKind.AFFECTED_BY:
            source = node_by_id[edge.source_id]
            target = node_by_id[edge.target_id]
            if (
                source.kind not in {NodeKind.ASSET, NodeKind.SERVICE, NodeKind.SOFTWARE}
                or target.kind is not NodeKind.VULNERABILITY
                or not target.cve_id
            ):
                raise ValueError(
                    "affected_by direction must be asset/service/software to exact CVE"
                )
        if edge.kind is EdgeKind.PROTECTED_BY:
            source = node_by_id[edge.source_id]
            target = node_by_id[edge.target_id]
            if source.kind is NodeKind.CONTROL or target.kind is not NodeKind.CONTROL:
                raise ValueError(
                    "protected_by direction must be protected object to control"
                )
    if tuple(edge_ids) != tuple(sorted(edge_ids)) or len(edge_ids) != len(set(edge_ids)):
        raise ValueError("snapshot edge identifiers must be unique and sorted")

    if snapshot.status is ResourceStatus.COMPLETE:
        if snapshot.truncation_reasons or snapshot.dropped_nodes or snapshot.dropped_edges:
            raise ValueError("complete snapshot cannot contain loss or truncation")
    elif not snapshot.truncation_reasons:
        raise ValueError("incomplete snapshot must disclose a truncation reason")
    if not snapshot.coverage_reasons:
        raise ValueError("snapshot must disclose semantic coverage reasons")


class _VerificationAborted(RuntimeError):
    pass


def _digest(
    document: object,
    *,
    work_guard: Callable[[int], bool] | None = None,
) -> str:
    """Canonical streaming digest with an optional pre-emptible work guard."""
    encoder = json.JSONEncoder(
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    digest = hashlib.sha256()
    for chunk in encoder.iterencode(document):
        encoded = chunk.encode("utf-8")
        if work_guard is not None and not work_guard(len(encoded)):
            raise _VerificationAborted("snapshot verification budget exhausted")
        digest.update(encoded)
    return "sha256:" + digest.hexdigest()


def build_relationship_absence_attestation(
    *,
    scope_id: str,
    policy_digest: str,
    coverage_domain: CoverageDomain,
    authority_id: str,
    evidence: EvidenceBinding,
) -> RelationshipAbsenceAttestation:
    """Build an exact finite no-relationship attestation for one policy scope."""
    core = {
        "schema": ABSENCE_SCHEMA,
        "scope_id": scope_id,
        "policy_digest": policy_digest,
        "coverage_domain": (
            coverage_domain.value
            if isinstance(coverage_domain, CoverageDomain)
            else coverage_domain
        ),
        "authority_id": authority_id,
        "evidence": _evidence_fact(evidence),
    }
    return RelationshipAbsenceAttestation(
        schema=ABSENCE_SCHEMA,
        scope_id=scope_id,
        policy_digest=policy_digest,
        coverage_domain=coverage_domain,
        authority_id=authority_id,
        evidence=evidence,
        digest=_digest(core),
    )


def verify_relationship_absence_attestation(
    attestation: object,
    *,
    scope_id: str,
    policy_digest: str,
    generation: int,
    at_time: float,
) -> bool:
    """Fail closed for malformed, expired, substituted, or unauthorized absence."""
    try:
        return bool(
            isinstance(attestation, RelationshipAbsenceAttestation)
            and attestation.schema == ABSENCE_SCHEMA
            and attestation.scope_id == scope_id
            and attestation.policy_digest == policy_digest
            and attestation.coverage_domain
            is CoverageDomain.EXPOSURE_RELATIONSHIPS
            and attestation.evidence.provenance
            in {
                EvidenceProvenance.ANALYST_ATTESTATION,
                EvidenceProvenance.SIGNED_IMPORT,
            }
            and evidence_is_current_bound(
                attestation.evidence,
                at_time=at_time,
                generation=generation,
            )
            and attestation.digest == _digest(_absence_fact(attestation))
        )
    except (AttributeError, TypeError, ValueError, OverflowError):
        return False


def build_coverage_manifest(
    nodes: Sequence[ExposureNode],
    edges: Sequence[ExposureEdge],
    *,
    scope_id: str = DEFAULT_SCOPE_ID,
    policy_digest: str = DEFAULT_POLICY_DIGEST,
    attested_at: float,
    expires_at: float,
    declared_complete: bool = True,
    trust_basis: str = "local-provider-attestation-not-externally-signed",
    relationship_absence: RelationshipAbsenceAttestation | None = None,
) -> CoverageManifest:
    """Create a content-addressed provider scope attestation.

    This receipt proves later mutation, not provider truthfulness or external
    identity. Callers must protect and independently authorize the provider.
    """
    if not isinstance(nodes, Sequence) or isinstance(nodes, (str, bytes, bytearray)):
        raise ValueError("coverage nodes must be a sized sequence")
    if not isinstance(edges, Sequence) or isinstance(edges, (str, bytes, bytearray)):
        raise ValueError("coverage edges must be a sized sequence")
    if len(nodes) > HARD_MAX_NODES or len(edges) > HARD_MAX_EDGES:
        raise ValueError("coverage manifest scope exceeds hard verification bounds")
    if any(not isinstance(node, ExposureNode) for node in nodes) or any(
        not isinstance(edge, ExposureEdge) for edge in edges
    ):
        raise ValueError("coverage manifest rows use invalid schemas")
    core = {
        "schema": COVERAGE_SCHEMA,
        "scope_id": scope_id,
        "policy_digest": policy_digest,
        "expected_node_ids": sorted(node.node_id for node in nodes),
        "expected_edge_ids": sorted(edge.edge_id for edge in edges),
        "declared_complete": declared_complete,
        "attested_at": attested_at,
        "expires_at": expires_at,
        "trust_basis": trust_basis,
        "relationship_absence": _absence_fact(relationship_absence),
    }
    return CoverageManifest(
        schema=COVERAGE_SCHEMA,
        scope_id=scope_id,
        policy_digest=policy_digest,
        expected_node_ids=tuple(core["expected_node_ids"]),
        expected_edge_ids=tuple(core["expected_edge_ids"]),
        declared_complete=declared_complete,
        attested_at=attested_at,
        expires_at=expires_at,
        trust_basis=trust_basis,
        relationship_absence=relationship_absence,
        digest=_digest(core),
    )


def verify_coverage_manifest(manifest: object) -> bool:
    try:
        return bool(
            isinstance(manifest, CoverageManifest)
            and manifest.schema == COVERAGE_SCHEMA
            and manifest.digest == _digest(_coverage_fact(manifest))
        )
    except (AttributeError, TypeError, ValueError, OverflowError):
        return False


def _coverage_evaluation(
    *,
    nodes: Sequence[ExposureNode],
    edges: Sequence[ExposureEdge],
    processing_status: ResourceStatus,
    scope_id: str,
    policy_digest: str,
    manifest: CoverageManifest | None,
    generation: int,
    at_time: float,
) -> tuple[CoverageStatus, tuple[str, ...]]:
    reasons: set[str] = set()
    entry_count = sum(node.kind is NodeKind.ENTRY_POINT for node in nodes)
    target_count = sum(
        node.kind in {NodeKind.TARGET, NodeKind.DATA}
        or (node.kind is NodeKind.ASSET and node.criticality >= 4)
        for node in nodes
    )
    if not nodes:
        reasons.add("empty_graph")
    if not entry_count:
        reasons.add("no_declared_entry_points")
    if not target_count:
        reasons.add("no_declared_targets")
    if reasons:
        return CoverageStatus.UNUSABLE, tuple(sorted(reasons))
    if processing_status is ResourceStatus.INCOMPLETE_RESOURCE_LIMIT:
        reasons.add("processing_incomplete")
    if manifest is None:
        reasons.add("coverage_manifest_missing")
    elif not verify_coverage_manifest(manifest):
        reasons.add("coverage_manifest_digest_invalid")
    else:
        if manifest.scope_id != scope_id:
            reasons.add("coverage_scope_mismatch")
        if manifest.policy_digest != policy_digest:
            reasons.add("coverage_policy_mismatch")
        if not manifest.declared_complete:
            reasons.add("provider_did_not_attest_complete_scope")
        if manifest.attested_at > at_time:
            reasons.add("coverage_manifest_future_dated")
        if manifest.expires_at < at_time:
            reasons.add("coverage_manifest_expired")
        if manifest.expected_node_ids != tuple(node.node_id for node in nodes):
            reasons.add("coverage_node_set_mismatch")
        if manifest.expected_edge_ids != tuple(edge.edge_id for edge in edges):
            reasons.add("coverage_edge_set_mismatch")
    for edge in edges:
        if not evidence_is_current_bound(
            edge.evidence, at_time=at_time, generation=generation
        ):
            reasons.add("relationship_evidence_not_current_finite_and_bound")
            break
    for node in nodes:
        if node.threat_evidence is not None and not evidence_is_current_bound(
            node.threat_evidence, at_time=at_time, generation=generation
        ):
            reasons.add("threat_evidence_not_current_finite_and_bound")
            break
    if not edges:
        absence = manifest.relationship_absence if manifest is not None else None
        if not verify_relationship_absence_attestation(
            absence,
            scope_id=scope_id,
            policy_digest=policy_digest,
            generation=generation,
            at_time=at_time,
        ):
            reasons.add("authorized_relationship_absence_attestation_missing_or_invalid")
    if reasons:
        return CoverageStatus.UNVERIFIED, tuple(sorted(reasons))
    return CoverageStatus.VERIFIED, ("provider_attested_exact_declared_scope",)


def evaluate_snapshot_coverage(
    snapshot: ExposureSnapshot,
    *,
    at_time: float,
    work_guard: Callable[[int], bool] | None = None,
) -> tuple[CoverageStatus, tuple[str, ...]]:
    """Re-evaluate time-sensitive semantic coverage at the decision boundary."""
    if not isinstance(snapshot, ExposureSnapshot) or not verify_snapshot_digest(
        snapshot, work_guard=work_guard
    ):
        return CoverageStatus.UNVERIFIED, ("snapshot_digest_invalid",)
    current = _finite(at_time, "at_time")
    return _coverage_evaluation(
        nodes=snapshot.nodes,
        edges=snapshot.edges,
        processing_status=snapshot.status,
        scope_id=snapshot.scope_id,
        policy_digest=snapshot.policy_digest,
        manifest=snapshot.coverage_manifest,
        generation=snapshot.generation,
        at_time=current,
    )


def _bounded_selection(
    rows: Sequence[Any],
    limit: int,
    hard_limit: int,
    hard_input_limit: int,
    identifier: str,
    row_type: type,
) -> tuple[list[Any], int, bool]:
    if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes, bytearray)):
        raise ValueError("graph inputs must be sized sequences for bounded processing")
    limit = max(1, min(int(limit), hard_limit))
    total = len(rows)
    # Refuse to walk attacker-sized sequences indefinitely. Returning no rows
    # is deterministic under permutation and, crucially, cannot be mistaken
    # for a complete empty graph because the hard-limit reason is retained.
    if total > hard_input_limit:
        return [], total, True
    if any(not isinstance(row, row_type) for row in rows):
        raise ValueError(f"graph rows must contain only {row_type.__name__} values")
    # nsmallest has O(limit) auxiliary memory and makes truncation independent
    # of producer ordering.  The caller-owned sequence is never copied whole.
    selected = nsmallest(limit, rows, key=lambda row: str(getattr(row, identifier, "")))
    return selected, max(0, total - len(selected)), False


def build_exposure_snapshot(
    nodes: Sequence[ExposureNode],
    edges: Sequence[ExposureEdge],
    *,
    generation: int,
    observed_at: float,
    max_nodes: int = DEFAULT_MAX_NODES,
    max_edges: int = DEFAULT_MAX_EDGES,
    scope_id: str = DEFAULT_SCOPE_ID,
    policy_digest: str = DEFAULT_POLICY_DIGEST,
    coverage_manifest: CoverageManifest | None = None,
) -> ExposureSnapshot:
    """Build a deterministic snapshot, explicitly flagging every size truncation."""
    generation = _generation(generation)
    observed_at = _finite(observed_at, "observed_at")
    scope_id = _identifier(scope_id, "scope_id")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", policy_digest):
        raise ValueError("policy_digest must be an exact SHA-256 token")
    if coverage_manifest is not None and not isinstance(
        coverage_manifest, CoverageManifest
    ):
        raise ValueError("coverage_manifest must use the closed manifest schema")
    chosen_nodes, dropped_nodes, node_hard_limit = _bounded_selection(
        nodes,
        max_nodes,
        HARD_MAX_NODES,
        HARD_INPUT_NODES,
        "node_id",
        ExposureNode,
    )
    chosen_edges, initial_dropped_edges, edge_hard_limit = _bounded_selection(
        edges,
        max_edges,
        HARD_MAX_EDGES,
        HARD_INPUT_EDGES,
        "edge_id",
        ExposureEdge,
    )

    chosen_nodes.sort(key=lambda row: row.node_id)
    chosen_edges.sort(key=lambda row: row.edge_id)
    node_ids = [row.node_id for row in chosen_nodes]
    edge_ids = [row.edge_id for row in chosen_edges]
    if len(node_ids) != len(set(node_ids)) or len(edge_ids) != len(set(edge_ids)):
        raise ValueError("node and edge identifiers must be unique")
    admitted_nodes = set(node_ids)
    node_by_id = {node.node_id: node for node in chosen_nodes}
    for node in chosen_nodes:
        threat = node.threat_evidence
        if threat is None:
            continue
        if threat.generation != generation:
            raise ValueError("threat evidence generation does not match snapshot generation")
        if threat.observed_at > observed_at:
            raise ValueError("threat evidence cannot be observed after its snapshot")
    admitted_edges: list[ExposureEdge] = []
    orphan_edges = 0
    for edge in chosen_edges:
        if edge.evidence.generation != generation:
            raise ValueError("edge evidence generation does not match snapshot generation")
        if edge.evidence.observed_at > observed_at:
            raise ValueError("edge evidence cannot be observed after its snapshot")
        if edge.source_id not in admitted_nodes or edge.target_id not in admitted_nodes:
            orphan_edges += 1
            continue
        if edge.assertion is AssertionState.CLOSED and (
            not evidence_is_current_bound(
                edge.evidence,
                at_time=observed_at,
                generation=generation,
            )
        ):
            raise ValueError(
                "expired evidence or otherwise non-current evidence cannot close an edge"
            )
        if edge.kind is EdgeKind.AFFECTED_BY:
            source = node_by_id[edge.source_id]
            target = node_by_id[edge.target_id]
            if (
                source.kind not in {NodeKind.ASSET, NodeKind.SERVICE, NodeKind.SOFTWARE}
                or target.kind is not NodeKind.VULNERABILITY
                or not target.cve_id
            ):
                raise ValueError(
                    "affected_by direction must be asset/service/software to exact CVE"
                )
        if edge.kind is EdgeKind.PROTECTED_BY:
            source = node_by_id[edge.source_id]
            target = node_by_id[edge.target_id]
            if source.kind is NodeKind.CONTROL or target.kind is not NodeKind.CONTROL:
                raise ValueError("protected_by direction must be protected object to control")
        admitted_edges.append(edge)

    dropped_edges = initial_dropped_edges + orphan_edges
    reasons: list[str] = []
    if node_hard_limit:
        reasons.append("node_hard_input_limit")
    elif dropped_nodes:
        reasons.append("node_limit")
    if edge_hard_limit:
        reasons.append("edge_hard_input_limit")
    elif initial_dropped_edges:
        reasons.append("edge_limit")
    if orphan_edges:
        reasons.append("edge_endpoint_not_admitted")
    status = (
        ResourceStatus.INCOMPLETE_RESOURCE_LIMIT if reasons else ResourceStatus.COMPLETE
    )
    coverage_status, coverage_reasons = _coverage_evaluation(
        nodes=chosen_nodes,
        edges=admitted_edges,
        processing_status=status,
        scope_id=scope_id,
        policy_digest=policy_digest,
        manifest=coverage_manifest,
        generation=generation,
        at_time=observed_at,
    )
    core = {
        "schema": GRAPH_SCHEMA,
        "generation": generation,
        "observed_at": observed_at,
        "nodes": [_node_fact(row) for row in chosen_nodes],
        "edges": [_edge_fact(row) for row in admitted_edges],
        "status": status.value,
        "truncation_reasons": reasons,
        "dropped_nodes": dropped_nodes,
        "dropped_edges": dropped_edges,
        "scope_id": scope_id,
        "policy_digest": policy_digest,
        "coverage_manifest": _coverage_fact(coverage_manifest),
        "coverage_manifest_digest": (
            coverage_manifest.digest if coverage_manifest is not None else None
        ),
        "coverage_status": coverage_status.value,
        "coverage_reasons": list(coverage_reasons),
    }
    return ExposureSnapshot(
        schema=GRAPH_SCHEMA,
        generation=generation,
        observed_at=observed_at,
        nodes=tuple(chosen_nodes),
        edges=tuple(admitted_edges),
        status=status,
        truncation_reasons=tuple(reasons),
        dropped_nodes=dropped_nodes,
        dropped_edges=dropped_edges,
        scope_id=scope_id,
        policy_digest=policy_digest,
        coverage_manifest=coverage_manifest,
        coverage_status=coverage_status,
        coverage_reasons=coverage_reasons,
        digest=_digest(core),
    )


def _snapshot_core(
    snapshot: ExposureSnapshot,
    *,
    work_guard: Callable[[int], bool] | None = None,
) -> dict[str, Any]:
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    for index, row in enumerate(snapshot.nodes):
        if index % 16 == 0 and work_guard is not None and not work_guard(256):
            raise _VerificationAborted("snapshot verification budget exhausted")
        nodes.append(_node_fact(row))
    for index, row in enumerate(snapshot.edges):
        if index % 16 == 0 and work_guard is not None and not work_guard(384):
            raise _VerificationAborted("snapshot verification budget exhausted")
        edges.append(_edge_fact(row))
    return {
        "schema": snapshot.schema,
        "generation": snapshot.generation,
        "observed_at": snapshot.observed_at,
        "nodes": nodes,
        "edges": edges,
        "status": snapshot.status.value,
        "truncation_reasons": list(snapshot.truncation_reasons),
        "dropped_nodes": snapshot.dropped_nodes,
        "dropped_edges": snapshot.dropped_edges,
        "scope_id": snapshot.scope_id,
        "policy_digest": snapshot.policy_digest,
        "coverage_manifest": _coverage_fact(snapshot.coverage_manifest),
        "coverage_manifest_digest": (
            snapshot.coverage_manifest.digest
            if snapshot.coverage_manifest is not None
            else None
        ),
        "coverage_status": snapshot.coverage_status.value,
        "coverage_reasons": list(snapshot.coverage_reasons),
    }


def verify_snapshot_digest(
    snapshot: object,
    *,
    work_guard: Callable[[int], bool] | None = None,
) -> bool:
    """Verify exact bounded structure/content, returning false on malformed input."""
    if not isinstance(snapshot, ExposureSnapshot):
        return False
    try:
        _validate_snapshot_structure(snapshot, work_guard=work_guard)
        core = _snapshot_core(snapshot, work_guard=work_guard)
        return bool(
            snapshot.schema == GRAPH_SCHEMA
            and snapshot.digest == _digest(core, work_guard=work_guard)
        )
    except (
        AttributeError,
        TypeError,
        ValueError,
        OverflowError,
        _VerificationAborted,
    ):
        return False


__all__ = [
    "Applicability",
    "AssertionState",
    "CoverageManifest",
    "CoverageDomain",
    "CoverageStatus",
    "DEFAULT_POLICY_DIGEST",
    "DEFAULT_SCOPE_ID",
    "EdgeKind",
    "EvidenceBinding",
    "EvidenceFreshness",
    "EvidenceProvenance",
    "ExposureEdge",
    "ExposureNode",
    "ExposureSnapshot",
    "NodeKind",
    "PrivacyClass",
    "ResourceStatus",
    "RelationshipAbsenceAttestation",
    "build_coverage_manifest",
    "build_exposure_snapshot",
    "build_relationship_absence_attestation",
    "evidence_is_current_bound",
    "evaluate_snapshot_coverage",
    "verify_coverage_manifest",
    "verify_relationship_absence_attestation",
    "verify_snapshot_digest",
]
