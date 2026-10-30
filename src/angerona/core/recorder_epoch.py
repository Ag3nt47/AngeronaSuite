"""Bounded recorder commitments and independently signed append-only receipts.

These receipts preserve stored-byte commitments, not original producer trust.
The independent authority must enforce successor admission, keep its signing key
outside the monitored host and expose a freshly authenticated current head.
Missing/pruned rows remain loss; a local receipt cannot certify its own freshness.
No host HMAC key is rotated and no Python secure-erasure claim is made here.
"""
from __future__ import annotations

import base64
from dataclasses import asdict, dataclass
import hashlib
import json
import math
import re
from typing import Iterable, Protocol


SCHEMA = "angerona.recorder-epoch-receipt.v1"
MAX_EPOCH_ROWS = 4096
MAX_ROW_BYTES = 512 * 1024
MAX_EPOCH_BYTES = 16 * 1024 * 1024
ZERO = "0" * 64
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_IDENTITY = re.compile(r"[0-9a-f]{32}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_ROW_DOMAIN = b"Angerona-Recorder-Row-v1\0"
_ROOT_DOMAIN = b"Angerona-Recorder-Range-v1\0"
_RECEIPT_DOMAIN = b"Angerona-Recorder-Epoch-v1\0"


class EpochRejected(ValueError):
    """An epoch or its independent archival receipt was ambiguous."""


class EpochSigner(Protocol):
    @property
    def key_id(self) -> str: ...
    def sign(self, payload: bytes) -> str: ...


class EpochVerifier(Protocol):
    @property
    def key_id(self) -> str: ...
    def verify(self, payload: bytes, signature: str) -> bool: ...


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _integer(value: object, label: str, *, zero=False) -> int:
    if type(value) is not int or not (0 if zero else 1) <= value <= 2**63 - 1:
        raise EpochRejected(label + " is invalid")
    return value


def _digest(value: object, label: str, *, empty=False) -> str:
    if type(value) is not str or not _HEX.fullmatch(value) or not empty and value == ZERO:
        raise EpochRejected(label + " is invalid")
    return value


@dataclass(frozen=True)
class EpochClaim:
    epoch: int
    first_id: int
    last_id: int
    count: int
    rows_root: str
    previous_receipt: str

    def __post_init__(self):
        for field in ("epoch", "first_id", "last_id", "count"):
            _integer(getattr(self, field), field)
        if not self.first_id <= self.last_id or not self.count <= min(MAX_EPOCH_ROWS, self.last_id - self.first_id + 1):
            raise EpochRejected("recorder range/count is inconsistent")
        _digest(self.rows_root, "rows root")
        _digest(self.previous_receipt, "predecessor receipt", empty=self.epoch == 1)
        if self.epoch == 1 and self.previous_receipt != ZERO:
            raise EpochRejected("first recorder epoch has a predecessor")


def parse_claim(value: object) -> EpochClaim:
    if type(value) is not dict or set(value) != set(EpochClaim.__dataclass_fields__):
        raise EpochRejected("recorder epoch claim schema is invalid")
    return EpochClaim(**value)


@dataclass(frozen=True)
class EpochReceipt:
    schema: str
    installation_id: str
    client_instance_id: str
    key_id: str
    sealed_at_ms: int
    claim: EpochClaim
    signature: str

    def body(self) -> dict:
        value = asdict(self)
        value.pop("signature")
        return value

    def digest(self) -> str:
        return hashlib.sha256(canonical(asdict(self))).hexdigest()


def _receipt_shape(receipt: EpochReceipt) -> None:
    if (type(receipt) is not EpochReceipt or receipt.schema != SCHEMA
            or type(receipt.claim) is not EpochClaim
            or type(receipt.installation_id) is not str or not _IDENTITY.fullmatch(receipt.installation_id)
            or type(receipt.client_instance_id) is not str or not _TOKEN.fullmatch(receipt.client_instance_id)
            or type(receipt.key_id) is not str or not _TOKEN.fullmatch(receipt.key_id)):
        raise EpochRejected("recorder receipt identity/schema is invalid")
    _integer(receipt.sealed_at_ms, "seal time", zero=True)
    if receipt.sealed_at_ms > 32_503_680_000_000:
        raise EpochRejected("seal time exceeds the supported range")
    if type(receipt.signature) is not str or len(receipt.signature) != 86:
        raise EpochRejected("archival receipt signature size/type is invalid")
    try:
        raw = base64.b64decode(receipt.signature + "=" * (-len(receipt.signature) % 4),
                               altchars=b"-_", validate=True)
        canonical_signature = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    except Exception as exc:
        raise EpochRejected("archival receipt signature is malformed") from exc
    if len(raw) != 64 or canonical_signature != receipt.signature:
        raise EpochRejected("archival receipt requires one canonical Ed25519 signature")


def parse_receipt(value: object) -> EpochReceipt:
    if type(value) is not dict or set(value) != set(EpochReceipt.__dataclass_fields__):
        raise EpochRejected("recorder receipt schema is invalid")
    copied = dict(value)
    copied["claim"] = parse_claim(copied["claim"])
    receipt = EpochReceipt(**copied)
    _receipt_shape(receipt)
    return receipt


def verify_receipt(receipt: EpochReceipt, verifier: EpochVerifier, *,
                   installation_id: str, client_instance_id: str) -> EpochReceipt:
    _receipt_shape(receipt)
    if (receipt.installation_id != installation_id or receipt.client_instance_id != client_instance_id
            or receipt.key_id != verifier.key_id
            or verifier.verify(_RECEIPT_DOMAIN + canonical(receipt.body()), receipt.signature) is not True):
        raise EpochRejected("independent recorder receipt verification failed")
    return receipt


def admit_successor(claim: EpochClaim, current: EpochReceipt | None) -> None:
    if type(claim) is not EpochClaim:
        raise EpochRejected("recorder claim type is invalid")
    if current is None:
        if claim.epoch != 1 or claim.previous_receipt != ZERO:
            raise EpochRejected("recorder namespace requires its first epoch")
        return
    _receipt_shape(current)
    if (claim.epoch != current.claim.epoch + 1 or claim.previous_receipt != current.digest()
            or claim.first_id <= current.claim.last_id):
        raise EpochRejected("recorder authority refuses duplicate, overlapping or forked history")


def issue_receipt(claim: EpochClaim, *, current: EpochReceipt | None, signer: EpochSigner,
                  installation_id: str, client_instance_id: str, sealed_at: float) -> EpochReceipt:
    admit_successor(claim, current)
    if (type(sealed_at) not in (int, float) or not math.isfinite(sealed_at)
            or not 0 <= sealed_at <= 32_503_680_000):
        raise EpochRejected("recorder authority time is invalid")
    body = dict(schema=SCHEMA, installation_id=installation_id, client_instance_id=client_instance_id,
                key_id=signer.key_id, sealed_at_ms=int(sealed_at * 1000), claim=asdict(claim))
    receipt = parse_receipt({**body, "signature": signer.sign(_RECEIPT_DOMAIN + canonical(body))})
    return receipt


@dataclass(frozen=True)
class RowCommitment:
    row_id: int
    digest: str


def commit_rows(rows: Iterable[tuple]) -> tuple[RowCommitment, ...]:
    """Hash exact stored id/ts/module/severity/message/details/HMAC fields.

    Details remain their exact SQLite text, including whitespace. This does not
    retag a record or assert that its original HMAC/producer was trusted.
    """
    result, total, previous = [], 0, 0
    for row in rows:
        if len(result) >= MAX_EPOCH_ROWS or type(row) is not tuple or len(row) != 7:
            raise EpochRejected("recorder row/count bound is invalid")
        row_id, ts, module, severity, message, details, hmac_sig = row
        _integer(row_id, "row ID")
        if (row_id <= previous or type(ts) not in (int, float) or not math.isfinite(ts)
                or type(severity) is not int or not 0 <= severity <= 100
                or type(module) is not str or type(message) is not str
                or details is not None and type(details) is not str or type(hmac_sig) is not str):
            raise EpochRejected("recorder row fields/order are invalid")
        # Reject oversized fields before encoding or allocating a full JSON row.
        if any(len(value) > MAX_ROW_BYTES for value in (module, message, details or "", hmac_sig)):
            raise EpochRejected("recorder row exceeds its field bound")
        raw = canonical(row)
        total += len(raw)
        if len(raw) > MAX_ROW_BYTES or total > MAX_EPOCH_BYTES:
            raise EpochRejected("recorder row/epoch byte bound exceeded")
        result.append(RowCommitment(row_id, hashlib.sha256(_ROW_DOMAIN + raw).hexdigest()))
        previous = row_id
    if not result:
        raise EpochRejected("an empty recorder range cannot be sealed")
    return tuple(result)


def rows_root(rows: tuple[RowCommitment, ...]) -> str:
    if type(rows) is not tuple or not 1 <= len(rows) <= MAX_EPOCH_ROWS:
        raise EpochRejected("row commitment count is invalid")
    digest = hashlib.sha256(_ROOT_DOMAIN + len(rows).to_bytes(4, "big"))
    previous = 0
    for item in rows:
        if type(item) is not RowCommitment or _integer(item.row_id, "row ID") <= previous:
            raise EpochRejected("row commitment order is invalid")
        digest.update(item.row_id.to_bytes(8, "big"))
        digest.update(bytes.fromhex(_digest(item.digest, "row digest")))
        previous = item.row_id
    return digest.hexdigest()


def claim_rows(rows: tuple[RowCommitment, ...], *, current: EpochReceipt | None) -> EpochClaim:
    root = rows_root(rows)
    claim = EpochClaim(1 if current is None else current.claim.epoch + 1,
                       rows[0].row_id, rows[-1].row_id, len(rows), root,
                       ZERO if current is None else current.digest())
    admit_successor(claim, current)
    return claim


@dataclass(frozen=True)
class EpochRangeAssessment:
    state: str
    verified_rows: int
    missing_rows: int
    changed_rows: int
    unexpected_rows: int
    # An archived receipt alone is not a fresh observation of the current head.
    independently_current: bool = False
    producer_authenticity_verified: bool = False


def verify_row_range(receipt: EpochReceipt, commitments: tuple[RowCommitment, ...],
                     actual_rows: Iterable[tuple], verifier: EpochVerifier, *,
                     installation_id: str, client_instance_id: str) -> EpochRangeAssessment:
    verify_receipt(receipt, verifier, installation_id=installation_id, client_instance_id=client_instance_id)
    if (rows_root(commitments) != receipt.claim.rows_root or len(commitments) != receipt.claim.count
            or commitments[0].row_id != receipt.claim.first_id or commitments[-1].row_id != receipt.claim.last_id):
        raise EpochRejected("local row index does not match the independently signed range")
    expected = {item.row_id: item.digest for item in commitments}
    # The empty retained range is explicit loss. Otherwise use the same bounded
    # ordering/field contract as admission; no HMAC is regenerated or trusted.
    iterator = iter(actual_rows)
    absent = object()
    first = next(iterator, absent)
    if first is absent:
        actual = ()
    else:
        from itertools import chain
        actual = commit_rows(chain((first,), iterator))
    present = {item.row_id: item.digest for item in actual}
    if any(not receipt.claim.first_id <= row_id <= receipt.claim.last_id for row_id in present):
        raise EpochRejected("verification rows escaped the signed epoch range")
    missing = len(expected.keys() - present.keys())
    unexpected = len(present.keys() - expected.keys())
    changed = sum(present[row_id] != digest for row_id, digest in expected.items() if row_id in present)
    verified = len(expected) - missing - changed
    return EpochRangeAssessment("record-mismatch" if changed or unexpected else
                                "rows-unavailable" if missing else "verified-stored-bytes",
                                verified, missing, changed, unexpected)
