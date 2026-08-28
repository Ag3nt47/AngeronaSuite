"""Contract for an independently held monotonic state high-water mark.

This module deliberately contains no local-file implementation.  Another HMAC,
DPAPI, registry, or ACL-protected value under the same host custody would still
be replayable with the protected state pair.  An implementation injected here
must authenticate a separately administered service or a policy-bound hardware
authority, durably enforce compare-and-swap, and reject duplicate or forked
revisions.  The existing Personal Sentinel compact witness is not an
implementation of this contract because its server-side monotonic enforcement
is not defined by this repository.

Only installation/domain identifiers, revisions, SHA-256 state digests, and
opaque authenticated heads cross this boundary.  Raw event rows, network
identifiers, paths, commands, credentials, and arbitrary payloads cannot be
passed through the interface.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Protocol


SCHEMA = "angerona.independent-high-water.v1"
ZERO_DIGEST = "0" * 64
AUDIT_DOMAIN = "audit-log-continuity"
NETWORK_DOMAIN = "network-trust-baseline"
PLATFORM_DOMAIN = "platform-attestation"
_DOMAINS = frozenset({AUDIT_DOMAIN, NETWORK_DOMAIN, PLATFORM_DOMAIN})
_HEX_32 = re.compile(r"^[0-9a-f]{32}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")


class HighWaterUnavailable(RuntimeError):
    """The independent authority could not provide an authenticated result."""


class HighWaterRejected(RuntimeError):
    """The independent authority rejected a transition or returned ambiguity."""


@dataclass(frozen=True)
class HighWaterHead:
    """Authenticated durable head returned by an independent authority."""

    schema: str
    installation_id: str
    domain: str
    revision: int
    state_digest: str
    previous_head: str
    head: str


@dataclass(frozen=True)
class HighWaterTransition:
    """Exact monotonic compare-and-swap request; contains no source evidence."""

    schema: str
    installation_id: str
    domain: str
    previous_revision: int
    previous_state_digest: str
    previous_head: str
    revision: int
    state_digest: str


@dataclass(frozen=True)
class HighWaterAssessment:
    """Local interpretation of one authenticated authority observation."""

    state: str
    reason: str
    independently_fresh: bool
    head: str = ZERO_DIGEST
    state_digest: str = ZERO_DIGEST


class IndependentHighWater(Protocol):
    """Strict injection point for a separately administered monotonic store.

    ``read_head`` must return an authenticated current head (or ``None`` only
    when the namespace is authoritatively absent). ``compare_and_advance`` must
    durably and atomically compare every previous field, reject duplicates and
    forks, and return the authenticated new head.  Transport/authentication,
    server durability, TPM policy, backup, clone, clearing, and re-enrollment
    are implementation responsibilities outside this local protocol.
    """

    @property
    def installation_id(self) -> str: ...

    def read_head(self, domain: str) -> HighWaterHead | None: ...

    def compare_and_advance(self, transition: HighWaterTransition) -> HighWaterHead: ...


def validate_installation_id(value: object) -> str:
    if not isinstance(value, str) or not _HEX_32.fullmatch(value):
        raise HighWaterRejected("installation identity is invalid")
    return value


def _validate_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _HEX_64.fullmatch(value):
        raise HighWaterRejected(f"{label} is invalid")
    return value


def validate_head(
    value: object,
    *,
    installation_id: str,
    domain: str,
) -> HighWaterHead:
    if not isinstance(value, HighWaterHead):
        raise HighWaterRejected("authority head contract is invalid")
    if (
        value.schema != SCHEMA
        or value.installation_id != installation_id
        or value.domain != domain
        or type(value.revision) is not int
        or not 1 <= value.revision <= 2**63 - 1
    ):
        raise HighWaterRejected("authority head identity is invalid")
    _validate_digest(value.state_digest, "authority state digest")
    _validate_digest(value.previous_head, "authority previous head")
    _validate_digest(value.head, "authority head")
    if value.state_digest == ZERO_DIGEST or value.head == ZERO_DIGEST:
        raise HighWaterRejected("authority head is not bound to a state")
    if value.revision == 1 and value.previous_head != ZERO_DIGEST:
        raise HighWaterRejected("first authority head has a predecessor")
    if value.revision > 1 and value.previous_head == ZERO_DIGEST:
        raise HighWaterRejected("authority chain predecessor is missing")
    return value


def state_pair_digest(
    *,
    domain: str,
    installation_id: str,
    revision: int,
    primary_payload: bytes,
    epoch_payload: bytes,
) -> str:
    """Digest the exact authenticated pair without exposing either document."""
    if domain not in _DOMAINS:
        raise HighWaterRejected("high-water domain is invalid")
    validate_installation_id(installation_id)
    if type(revision) is not int or not 1 <= revision <= 2**63 - 1:
        raise HighWaterRejected("state revision is invalid")
    if not isinstance(primary_payload, bytes) or not isinstance(epoch_payload, bytes):
        raise HighWaterRejected("state pair payload type is invalid")
    document = {
        "domain": domain,
        "epoch_sha256": hashlib.sha256(epoch_payload).hexdigest(),
        "installation_id": installation_id,
        "primary_sha256": hashlib.sha256(primary_payload).hexdigest(),
        "revision": revision,
        "schema": SCHEMA,
    }
    return hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def assess_high_water(
    authority: IndependentHighWater | None,
    *,
    domain: str,
    installation_id: str,
    revision: int,
    state_digest: str,
) -> HighWaterAssessment:
    """Compare local authenticated state to an independently queried head."""
    if authority is None:
        return HighWaterAssessment(
            "local-authenticity-only",
            "no independent high-water authority is configured",
            False,
            state_digest=state_digest,
        )
    try:
        authority_id = validate_installation_id(authority.installation_id)
        if authority_id != installation_id:
            return HighWaterAssessment(
                "installation-mismatch",
                "local state belongs to a different installation identity",
                False,
                state_digest=state_digest,
            )
        observed = authority.read_head(domain)
        if observed is None:
            return HighWaterAssessment(
                "ready-first-enrollment" if revision == 0 else "migration-required",
                "independent namespace is absent",
                False,
                state_digest=state_digest,
            )
        head = validate_head(observed, installation_id=installation_id, domain=domain)
    except HighWaterUnavailable:
        return HighWaterAssessment(
            "provisional-offline",
            "independent high-water authority is unavailable",
            False,
            state_digest=state_digest,
        )
    except Exception:
        return HighWaterAssessment(
            "authority-rejected",
            "independent high-water authority returned an invalid result",
            False,
            state_digest=state_digest,
        )
    if head.revision > revision:
        return HighWaterAssessment(
            "local-behind",
            "local state is behind the independent high-water head",
            False,
            head=head.head,
            state_digest=state_digest,
        )
    if head.revision < revision:
        return HighWaterAssessment(
            "local-ahead",
            "local state is ahead of the independent high-water head",
            False,
            head=head.head,
            state_digest=state_digest,
        )
    if head.state_digest != state_digest:
        return HighWaterAssessment(
            "fork-detected",
            "local state conflicts with the independent high-water head",
            False,
            head=head.head,
            state_digest=state_digest,
        )
    return HighWaterAssessment(
        "verified",
        "local state matches the independently authenticated high-water head",
        True,
        head=head.head,
        state_digest=state_digest,
    )


def advance_high_water(
    authority: IndependentHighWater,
    *,
    domain: str,
    installation_id: str,
    previous_revision: int,
    previous_state_digest: str,
    previous_head: str,
    revision: int,
    state_digest: str,
) -> HighWaterAssessment:
    """Request and strictly validate one external monotonic transition."""
    try:
        authority_id = validate_installation_id(authority.installation_id)
        if authority_id != installation_id:
            raise HighWaterRejected("installation identity changed")
        transition = HighWaterTransition(
            SCHEMA,
            installation_id,
            domain,
            previous_revision,
            _validate_digest(previous_state_digest, "previous state digest"),
            _validate_digest(previous_head, "previous head"),
            revision,
            _validate_digest(state_digest, "state digest"),
        )
        if revision != previous_revision + 1:
            raise HighWaterRejected("revision is not monotonic")
        if state_digest == ZERO_DIGEST:
            raise HighWaterRejected("new state digest is empty")
        if previous_revision == 0 and (
            previous_state_digest != ZERO_DIGEST or previous_head != ZERO_DIGEST
        ):
            raise HighWaterRejected("first transition has an unexpected predecessor")
        if previous_revision > 0 and (
            previous_state_digest == ZERO_DIGEST or previous_head == ZERO_DIGEST
        ):
            raise HighWaterRejected("transition predecessor is incomplete")
        returned = validate_head(
            authority.compare_and_advance(transition),
            installation_id=installation_id,
            domain=domain,
        )
        if (
            returned.revision != revision
            or returned.state_digest != state_digest
            or returned.previous_head != previous_head
        ):
            raise HighWaterRejected("authority transition echo is inconsistent")
        return HighWaterAssessment(
            "verified",
            "independent high-water transition committed",
            True,
            head=returned.head,
            state_digest=state_digest,
        )
    except HighWaterUnavailable:
        return HighWaterAssessment(
            "provisional-offline",
            "independent high-water authority is unavailable",
            False,
            head=previous_head,
            state_digest=previous_state_digest,
        )
    except Exception:
        return HighWaterAssessment(
            "advance-rejected",
            "independent high-water transition was rejected",
            False,
            head=previous_head,
            state_digest=previous_state_digest,
        )


__all__ = [
    "AUDIT_DOMAIN",
    "NETWORK_DOMAIN",
    "PLATFORM_DOMAIN",
    "SCHEMA",
    "ZERO_DIGEST",
    "HighWaterAssessment",
    "HighWaterHead",
    "HighWaterRejected",
    "HighWaterTransition",
    "HighWaterUnavailable",
    "IndependentHighWater",
    "advance_high_water",
    "assess_high_water",
    "state_pair_digest",
    "validate_head",
    "validate_installation_id",
]
