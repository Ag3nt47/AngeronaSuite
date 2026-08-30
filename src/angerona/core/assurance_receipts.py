"""Object-bound, one-time detector receipts for defensive assurance probes."""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import secrets
import threading
import time
import weakref
from collections import OrderedDict
from dataclasses import dataclass
from typing import Callable, Mapping


_HEX32 = re.compile(r"[0-9a-f]{32}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9_.:/-]{1,160}\Z")
_MAX_ACTIVE = 32
_MAX_LIFETIME_S = 90.0

PRODUCER_CONTRACTS: Mapping[
    str, tuple[str, str, Mapping[str, frozenset[str]]]
] = {
    "APID": (
        "API Patch / Anti-Blinding Detector",
        "angerona.builtin.api_patch_detector",
        {"apid": frozenset({"api_prolog_integrity_observed"})},
    ),
    "NDRD": (
        "Network Protocol Deep Decoder",
        "angerona.builtin.network_protocol_decoder",
        {"ndrd": frozenset({"dns_entropy_observed"})},
    ),
    "FIM": (
        "File Integrity Monitor",
        "angerona.builtin.file_integrity",
        {"fim": frozenset({"file_content_observed"})},
    ),
    "AMSI": (
        "AMSI Bridge",
        "angerona.builtin.amsi_bridge",
        {"amsi": frozenset({"content_signature_observed"})},
    ),
}

RECEIPT_FIELDS = frozenset({
    "assurance_receipt_version",
    "receipt_type",
    "probe_id",
    "probe_kind",
    "challenge_digest",
    "target_digest",
    "responder_code",
    "responder_module",
    "capability_id",
    "observation",
    "source_epoch",
    "lifecycle_generation",
    "observed_at",
    "producer_mac",
})


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def assurance_target_digest(
    probe_kind: str, target_ref: str, evidence_digest: str = ""
) -> str:
    """Bind a probe kind, exact local target reference, and observed content."""
    core = {
        "contract": "angerona-assurance-target-v1",
        "probe_kind": str(probe_kind),
        "target_ref": str(target_ref),
        "evidence_digest": str(evidence_digest),
    }
    return hashlib.sha256(_canonical(core)).hexdigest()


@dataclass(frozen=True)
class AssuranceChallenge:
    probe_id: str
    probe_kind: str
    challenge_digest: str
    target_digest: str
    target_ref: str
    issued_at: float
    expires_at: float

    def __post_init__(self) -> None:
        if not _HEX32.fullmatch(self.probe_id):
            raise ValueError("invalid assurance probe ID")
        if not _TOKEN.fullmatch(self.probe_kind):
            raise ValueError("invalid assurance probe kind")
        if not _HEX64.fullmatch(self.challenge_digest) or not _HEX64.fullmatch(
            self.target_digest
        ):
            raise ValueError("invalid assurance challenge digest")
        if not isinstance(self.target_ref, str) or not 1 <= len(self.target_ref) <= 1024:
            raise ValueError("invalid assurance target reference")
        if not all(math.isfinite(value) and value >= 0 for value in (
            self.issued_at, self.expires_at
        )):
            raise ValueError("invalid assurance challenge time")
        if not 0 < self.expires_at - self.issued_at <= _MAX_LIFETIME_S:
            raise ValueError("invalid assurance challenge lifetime")


@dataclass(frozen=True)
class _ProducerEnrollment:
    producer_ref: weakref.ReferenceType[object]
    code: str
    module_name: str
    capability_id: str
    observations: Mapping[str, frozenset[str]]
    source_epoch: str
    key: bytes


class DetectorReceiptIssuer:
    """Object capability issued only to one manager-registered detector."""

    __slots__ = ("__broker", "__producer_ref")

    def __init__(self, broker: "AssuranceReceiptBroker", producer: object) -> None:
        self.__broker = broker
        self.__producer_ref = weakref.ref(producer)

    def active(self, producer: object, probe_kind: str) -> tuple[AssuranceChallenge, ...]:
        enrolled = self.__producer_ref()
        if enrolled is None or producer is not enrolled:
            return ()
        return self.__broker._active_for(producer, probe_kind)

    def issue(
        self,
        producer: object,
        probe_id: str,
        *,
        observation: str,
        observed_target_digest: str,
        observed_at: float | None = None,
    ) -> dict[str, object] | None:
        enrolled = self.__producer_ref()
        if enrolled is None or producer is not enrolled:
            return None
        return self.__broker._issue(
            producer,
            probe_id,
            observation=observation,
            observed_target_digest=observed_target_digest,
            observed_at=observed_at,
        )


class AssuranceReceiptBroker:
    """Manager-held verifier binding receipts to registered module objects."""

    def __init__(self, registry: Callable[[], Mapping[str, object]]) -> None:
        self.__root = secrets.token_bytes(32)
        self.__registry = registry
        self.__lock = threading.RLock()
        self.__consumer_ref: weakref.ReferenceType[object] | None = None
        self.__producers: dict[int, _ProducerEnrollment] = {}
        self.__by_code: dict[str, _ProducerEnrollment] = {}
        self.__active: OrderedDict[str, AssuranceChallenge] = OrderedDict()
        self.__issued: OrderedDict[tuple[str, str], dict[str, object]] = OrderedDict()

    def enroll_consumer(self, consumer: object) -> None:
        if (
            str(getattr(consumer, "CODE", "")) != "CHAOS"
            or str(getattr(consumer, "name", "")) != "CHAOS"
        ):
            raise ValueError("invalid assurance consumer identity")
        with self.__lock:
            if self.__consumer_ref is not None and self.__consumer_ref() is not consumer:
                raise ValueError("assurance consumer is already enrolled")
            self.__consumer_ref = weakref.ref(consumer)

    def enroll_producer(
        self,
        producer: object,
        *,
        code: str,
        module_name: str,
        capability_id: str,
    ) -> DetectorReceiptIssuer:
        expected = PRODUCER_CONTRACTS.get(str(code))
        if expected is None or expected[0:2] != (module_name, capability_id):
            raise ValueError("detector is not in the assurance producer contract")
        if (
            str(getattr(producer, "CODE", "")) != code
            or str(getattr(producer, "name", "")) != module_name
        ):
            raise ValueError("detector object identity does not match its contract")
        with self.__lock:
            existing = self.__producers.get(id(producer))
            if existing is None:
                source_epoch = secrets.token_urlsafe(24)
                key = hmac.new(
                    self.__root,
                    _canonical({
                        "capability_id": capability_id,
                        "code": code,
                        "module_name": module_name,
                        "source_epoch": source_epoch,
                    }),
                    hashlib.sha256,
                ).digest()
                existing = _ProducerEnrollment(
                    weakref.ref(producer),
                    code,
                    module_name,
                    capability_id,
                    expected[2],
                    source_epoch,
                    key,
                )
                self.__producers[id(producer)] = existing
                self.__by_code[code] = existing
        return DetectorReceiptIssuer(self, producer)

    def register_challenge(
        self, consumer: object, challenge: AssuranceChallenge
    ) -> bool:
        with self.__lock:
            if self.__consumer_ref is None or self.__consumer_ref() is not consumer:
                return False
            if challenge.probe_kind not in {
                kind
                for enrollment in self.__producers.values()
                for kind in enrollment.observations
            }:
                return False
            now = time.time()
            self._expire_locked(now)
            if challenge.expires_at <= now - 2.0 or challenge.probe_id in self.__active:
                return False
            self.__active[challenge.probe_id] = challenge
            self.__active.move_to_end(challenge.probe_id)
            while len(self.__active) > _MAX_ACTIVE:
                expired_id, _expired = self.__active.popitem(last=False)
                for key in tuple(self.__issued):
                    if key[1] == expired_id:
                        self.__issued.pop(key, None)
            return True

    def _registry_matches(self, enrollment: _ProducerEnrollment) -> bool:
        producer = enrollment.producer_ref()
        if producer is None:
            return False
        try:
            return self.__registry().get(enrollment.module_name) is producer
        except Exception:
            return False

    def _expire_locked(self, now: float) -> None:
        for probe_id, challenge in tuple(self.__active.items()):
            if challenge.expires_at < now:
                self.__active.pop(probe_id, None)
                for key in tuple(self.__issued):
                    if key[1] == probe_id:
                        self.__issued.pop(key, None)

    def _active_for(
        self, producer: object, probe_kind: str
    ) -> tuple[AssuranceChallenge, ...]:
        with self.__lock:
            enrollment = self.__producers.get(id(producer))
            if (
                enrollment is None
                or enrollment.producer_ref() is not producer
                or probe_kind not in enrollment.observations
                or not self._registry_matches(enrollment)
            ):
                return ()
            self._expire_locked(time.time())
            return tuple(
                challenge
                for challenge in self.__active.values()
                if challenge.probe_kind == probe_kind
            )

    def _issue(
        self,
        producer: object,
        probe_id: str,
        *,
        observation: str,
        observed_target_digest: str,
        observed_at: float | None,
    ) -> dict[str, object] | None:
        stamp = time.time() if observed_at is None else float(observed_at)
        with self.__lock:
            enrollment = self.__producers.get(id(producer))
            challenge = self.__active.get(str(probe_id))
            if (
                enrollment is None
                or enrollment.producer_ref() is not producer
                or challenge is None
                or not self._registry_matches(enrollment)
                or challenge.probe_kind not in enrollment.observations
                or observation not in enrollment.observations[challenge.probe_kind]
                or observed_target_digest != challenge.target_digest
                or not math.isfinite(stamp)
                or stamp < challenge.issued_at - 1.0
                or stamp > challenge.expires_at + 2.0
            ):
                return None
            cache_key = (enrollment.code, challenge.probe_id)
            cached = self.__issued.get(cache_key)
            if cached is not None:
                return dict(cached)
            generation = int(getattr(producer, "_lifecycle_generation", 0))
            core: dict[str, object] = {
                "assurance_receipt_version": 1,
                "receipt_type": "detector_object_observation",
                "probe_id": challenge.probe_id,
                "probe_kind": challenge.probe_kind,
                "challenge_digest": challenge.challenge_digest,
                "target_digest": challenge.target_digest,
                "responder_code": enrollment.code,
                "responder_module": enrollment.module_name,
                "capability_id": enrollment.capability_id,
                "observation": observation,
                "source_epoch": enrollment.source_epoch,
                "lifecycle_generation": generation,
                "observed_at": stamp,
            }
            receipt = {
                **core,
                "producer_mac": hmac.new(
                    enrollment.key, _canonical(core), hashlib.sha256
                ).hexdigest(),
            }
            self.__issued[cache_key] = receipt
            self.__issued.move_to_end(cache_key)
            while len(self.__issued) > _MAX_ACTIVE * len(PRODUCER_CONTRACTS):
                self.__issued.popitem(last=False)
            return dict(receipt)

    def verify_and_consume(
        self,
        consumer: object,
        receipt: object,
        *,
        now: float | None = None,
    ) -> bool:
        stamp = time.time() if now is None else float(now)
        if not isinstance(receipt, dict) or set(receipt) != RECEIPT_FIELDS:
            return False
        if not math.isfinite(stamp):
            return False
        code = str(receipt.get("responder_code") or "")
        probe_id = str(receipt.get("probe_id") or "")
        with self.__lock:
            if self.__consumer_ref is None or self.__consumer_ref() is not consumer:
                return False
            self._expire_locked(stamp)
            enrollment = self.__by_code.get(code)
            challenge = self.__active.get(probe_id)
            producer = enrollment.producer_ref() if enrollment is not None else None
            if (
                enrollment is None
                or producer is None
                or challenge is None
                or not self._registry_matches(enrollment)
                or receipt.get("assurance_receipt_version") != 1
                or receipt.get("receipt_type") != "detector_object_observation"
                or receipt.get("probe_kind") != challenge.probe_kind
                or receipt.get("challenge_digest") != challenge.challenge_digest
                or receipt.get("target_digest") != challenge.target_digest
                or receipt.get("responder_module") != enrollment.module_name
                or receipt.get("capability_id") != enrollment.capability_id
                or receipt.get("source_epoch") != enrollment.source_epoch
                or receipt.get("observation")
                not in enrollment.observations.get(challenge.probe_kind, ())
                or receipt.get("lifecycle_generation")
                != int(getattr(producer, "_lifecycle_generation", 0))
            ):
                return False
            try:
                observed_at = float(receipt["observed_at"])
            except (TypeError, ValueError, OverflowError):
                return False
            if (
                not math.isfinite(observed_at)
                or observed_at < challenge.issued_at - 1.0
                or observed_at > challenge.expires_at + 2.0
                or observed_at > stamp + 2.0
            ):
                return False
            core = {key: receipt[key] for key in RECEIPT_FIELDS if key != "producer_mac"}
            supplied = str(receipt.get("producer_mac") or "")
            if not _HEX64.fullmatch(supplied) or not hmac.compare_digest(
                supplied,
                hmac.new(enrollment.key, _canonical(core), hashlib.sha256).hexdigest(),
            ):
                return False
            self.__active.pop(probe_id, None)
            self.__issued.pop((code, probe_id), None)
            return True
