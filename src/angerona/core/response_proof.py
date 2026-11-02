"""Bounded immutable producer receipts; same-process provenance, not isolation.

Only a detector's native observation path may retain a receipt. Event text,
transport signatures and caller-supplied flags cannot create one. This module
does no host, filesystem, policy, clock or native work; owners provide clocks.
"""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
import hashlib
import json
import math

MAX_PROOF_BYTES = 65536
MAX_PROOF_NODES = 512
MAX_PROOF_SECONDS = 30.0
MAX_PROOF_RECEIPTS = 4096


def proof_digest(payload: object) -> str:
    """Reject oversized/custom input before serializing a complete plain tree."""
    pending, visited, budget = [(payload, 0)], 0, MAX_PROOF_BYTES
    while pending:
        value, depth = pending.pop()
        visited += 1
        if visited > MAX_PROOF_NODES or depth > 8:
            raise ValueError("response_proof_payload_bounds")
        if type(value) is str:
            budget -= len(value) * 4
        elif type(value) is int:
            if value.bit_length() > 64:
                raise ValueError("response_proof_scalar_bounds")
            budget -= 32
        elif type(value) is float:
            if not math.isfinite(value):
                raise ValueError("response_proof_nonfinite")
            budget -= 32
        elif value is None or type(value) is bool:
            budget -= 8
        elif type(value) is dict:
            if len(value) > 64 or any(type(key) is not str for key in value):
                raise ValueError("response_proof_mapping_bounds")
            pending.extend((key, depth + 1) for key in value)
            pending.extend((part, depth + 1) for part in value.values())
        elif type(value) in (list, tuple):
            if len(value) > 128:
                raise ValueError("response_proof_sequence_bounds")
            pending.extend((part, depth + 1) for part in value)
        else:
            raise ValueError("response_proof_plain_types_required")
        if budget < 0:
            raise ValueError("response_proof_byte_bounds")
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=False, allow_nan=False).encode("utf-8")
    if len(raw) > MAX_PROOF_BYTES:
        raise ValueError("response_proof_byte_bounds")
    return hashlib.sha256(raw).hexdigest()


def event_proof_digest(event) -> str:
    return proof_digest({"module": event.module, "message": event.message,
                         "severity": int(event.severity), "ts": event.ts,
                         "details": event.details})


@dataclass(frozen=True)
class ProducerResponseProof:
    generation: int
    observed_monotonic: float
    expires_monotonic: float
    review_digest: str


class ProducerResponseProofs:
    """Caller holds its own lifecycle/receipt lock around this bounded state."""

    def __init__(self):
        self._receipts = OrderedDict()

    def retain(self, event, *, generation, now, review) -> None:
        if (type(generation) is not int or generation < 0
                or type(now) not in (int, float) or not math.isfinite(now) or now < 0):
            raise ValueError("response_proof_owner_clock_invalid")
        digest = event_proof_digest(event)
        # Re-retaining the same exact event never renews its original deadline.
        self._receipts.setdefault(digest, ProducerResponseProof(
            generation, now, now + MAX_PROOF_SECONDS, proof_digest(review)))
        while len(self._receipts) > MAX_PROOF_RECEIPTS:
            self._receipts.popitem(last=False)

    def verify(self, event, *, generation, now, review) -> bool:
        if (type(generation) is not int or type(now) not in (int, float)
                or not math.isfinite(now) or now < 0):
            return False
        try:
            receipt = self._receipts.get(event_proof_digest(event))
            return bool(receipt is not None and receipt.generation == generation
                        and receipt.observed_monotonic <= now < receipt.expires_monotonic
                        and receipt.review_digest == proof_digest(review))
        except (ValueError, TypeError, AttributeError, OverflowError, RecursionError):
            return False
