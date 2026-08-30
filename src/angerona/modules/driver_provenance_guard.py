"""Read-only driver provenance and BYOVD posture guard.

The guard joins image hash, Authenticode/catalog evidence, a bounded local
blocklist disposition, HVCI, and Secure Boot state. A configured service path
is explicitly an unbound disk sample: only a trusted kernel load receipt may
bind it to a loaded image. Missing evidence is ``unknown`` rather than safe.
This module cannot unload, disable, quarantine, delete, or otherwise control a
driver.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import math
import re
import secrets
import sys
import threading
import time
from dataclasses import asdict, dataclass, replace
from typing import Callable, Mapping, Protocol

from angerona.core.module_base import BaseModule, Severity
from angerona.core.privilege import trusted_powershell_path
from angerona.core.win import run_hidden
from angerona.modules.intel_sync import is_known_bad_driver
from angerona.modules.platform_attestation_guard import (
    BootPostureProvider,
    WindowsBootPostureProvider,
)


SCHEMA = "angerona.driver-provenance-evidence.v2"
MAX_DRIVERS = 256
MAX_OUTPUT_BYTES = 512 * 1024
MAX_DRIVER_BYTES = 128 * 1024 * 1024
_HEX_40_OR_64 = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_EVIDENCE_REQUIRED_KEYS = frozenset(
    {
        "schema",
        "driver_token",
        "image_sha256",
        "image_size",
        "load_state",
        "binding_state",
        "binding_source",
        "binding_receipt_sha256",
        "signer_status",
        "signer_thumbprint",
        "catalog_status",
        "blocklist_status",
        "blocklist_source",
        "hvci_enabled",
        "secure_boot",
        "observed_at",
    }
)
_EVIDENCE_KEYS = _EVIDENCE_REQUIRED_KEYS | {"binding_receipt"}
_LOAD_RECEIPT_SCHEMA = "angerona.driver-load-receipt.v1"
_LOAD_RECEIPT_KEYS = frozenset(
    {
        "schema",
        "receipt_id",
        "authority_id",
        "host_id",
        "install_id",
        "boot_id",
        "load_generation",
        "driver_token",
        "object_identity",
        "image_base",
        "image_size",
        "image_sha256",
        "load_state",
        "code_integrity_disposition",
        "issued_at",
        "expires_at",
        "signature_ed25519",
    }
)
SUPPORTED_PLATFORMS = ("windows",)
_MAX_REPLAY_AUTHORITIES = 256
_MAX_RECEIPTS_PER_AUTHORITY = 8192
_RECEIPT_REPLAY_LOCK = threading.Lock()
_CONSUMED_LOAD_RECEIPTS: dict[
    tuple[str, str, str, str], dict[str, float]
] = {}


class DriverEvidenceRejected(ValueError):
    """Driver evidence was ambiguous or outside the bounded schema."""


def _optional_bool(value: object, field: str) -> bool | None:
    if value is None or type(value) is bool:
        return value
    raise DriverEvidenceRejected(f"{field} must be boolean or null")


def _finite_timestamp(value: object, field: str) -> float:
    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        or not math.isfinite(float(value))
        or not 0.0 <= float(value) <= 32_503_680_000.0
    ):
        raise DriverEvidenceRejected(f"{field} is invalid")
    return float(value)


@dataclass(frozen=True)
class DriverLoadReceipt:
    """One signed observation from an explicitly enrolled kernel authority."""

    schema: str
    receipt_id: str
    authority_id: str
    host_id: str
    install_id: str
    boot_id: str
    load_generation: int
    driver_token: str
    object_identity: str
    image_base: int
    image_size: int
    image_sha256: str
    load_state: str
    code_integrity_disposition: str
    issued_at: float
    expires_at: float
    signature_ed25519: str

    def __post_init__(self) -> None:
        if self.schema != _LOAD_RECEIPT_SCHEMA:
            raise DriverEvidenceRejected("driver load receipt schema is invalid")
        for field in (
            "receipt_id", "authority_id", "host_id", "install_id", "boot_id",
            "driver_token", "object_identity", "image_sha256",
        ):
            value = getattr(self, field)
            if not isinstance(value, str) or not _HEX_64.fullmatch(value):
                raise DriverEvidenceRejected(f"driver load receipt {field} is invalid")
        if (
            type(self.load_generation) is not int
            or not 1 <= self.load_generation < 2**63
            or type(self.image_base) is not int
            or not 0 <= self.image_base < 2**64
            or type(self.image_size) is not int
            or not 1 <= self.image_size <= MAX_DRIVER_BYTES
        ):
            raise DriverEvidenceRejected("driver load receipt object range is invalid")
        if self.load_state not in {"running", "stopped"}:
            raise DriverEvidenceRejected("driver load receipt state is invalid")
        if self.code_integrity_disposition not in {
            "trusted", "untrusted", "unknown"
        }:
            raise DriverEvidenceRejected(
                "driver load receipt Code Integrity disposition is invalid"
            )
        issued = _finite_timestamp(self.issued_at, "driver load receipt issued_at")
        expires = _finite_timestamp(self.expires_at, "driver load receipt expires_at")
        if not issued < expires or expires - issued > 300.0:
            raise DriverEvidenceRejected("driver load receipt lifetime is invalid")
        try:
            signature = base64.b64decode(
                self.signature_ed25519.encode("ascii"), validate=True
            )
        except (UnicodeError, ValueError, binascii.Error) as exc:
            raise DriverEvidenceRejected(
                "driver load receipt signature is invalid"
            ) from exc
        if len(signature) != 64:
            raise DriverEvidenceRejected("driver load receipt signature is invalid")

    def unsigned_dict(self) -> dict[str, object]:
        body = asdict(self)
        body.pop("signature_ed25519", None)
        return body

    def signing_bytes(self) -> bytes:
        return json.dumps(
            self.unsigned_dict(),
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")

    def digest(self) -> str:
        return hashlib.sha256(
            json.dumps(
                asdict(self),
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()

    @classmethod
    def issue(cls, private_key: object, **claims: object) -> "DriverLoadReceipt":
        """Create a receipt for an issuer fixture/adapter; trust stays verifier-side."""
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
            )
        except Exception as exc:  # pragma: no cover - dependency contract
            raise DriverEvidenceRejected("Ed25519 support is unavailable") from exc
        if not isinstance(private_key, Ed25519PrivateKey):
            raise DriverEvidenceRejected("driver load receipt issuer is invalid")
        values = dict(claims)
        values.setdefault("schema", _LOAD_RECEIPT_SCHEMA)
        values.setdefault("receipt_id", secrets.token_hex(32))
        values["signature_ed25519"] = base64.b64encode(b"\0" * 64).decode("ascii")
        provisional = cls(**values)  # type: ignore[arg-type]
        signature = private_key.sign(provisional.signing_bytes())
        return replace(
            provisional,
            signature_ed25519=base64.b64encode(signature).decode("ascii"),
        )


def parse_driver_load_receipt(value: Mapping[str, object]) -> DriverLoadReceipt:
    if not isinstance(value, Mapping) or set(value) != _LOAD_RECEIPT_KEYS:
        raise DriverEvidenceRejected("driver load receipt contract is invalid")
    try:
        return DriverLoadReceipt(**dict(value))
    except TypeError as exc:
        raise DriverEvidenceRejected("driver load receipt contract is invalid") from exc


class DriverLoadReceiptVerifier:
    """Verify freshness/binding against one enrolled Ed25519 kernel authority."""

    def __init__(
        self,
        public_key: object,
        *,
        authority_id: str,
        host_id: str,
        install_id: str,
        boot_id: str,
        clock: Callable[[], float] = time.time,
    ) -> None:
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey,
            )
        except Exception as exc:  # pragma: no cover - dependency contract
            raise DriverEvidenceRejected("Ed25519 support is unavailable") from exc
        if isinstance(public_key, bytes):
            try:
                public_key = Ed25519PublicKey.from_public_bytes(public_key)
            except ValueError as exc:
                raise DriverEvidenceRejected(
                    "driver load receipt public key is invalid"
                ) from exc
        if not isinstance(public_key, Ed25519PublicKey):
            raise DriverEvidenceRejected("driver load receipt public key is invalid")
        for label, value in {
            "authority_id": authority_id,
            "host_id": host_id,
            "install_id": install_id,
            "boot_id": boot_id,
        }.items():
            if not isinstance(value, str) or not _HEX_64.fullmatch(value):
                raise DriverEvidenceRejected(f"driver load verifier {label} is invalid")
        if not callable(clock):
            raise DriverEvidenceRejected("driver load verifier clock is invalid")
        self._public_key = public_key
        self._authority_id = authority_id
        self._host_id = host_id
        self._install_id = install_id
        self._boot_id = boot_id
        self._clock = clock

    def _consume_once(self, receipt: DriverLoadReceipt, now: float) -> bool:
        """Atomically consume a receipt across every verifier in its trust domain."""
        domain = (
            self._authority_id,
            self._host_id,
            self._install_id,
            self._boot_id,
        )
        with _RECEIPT_REPLAY_LOCK:
            for authority, consumed in tuple(_CONSUMED_LOAD_RECEIPTS.items()):
                expired = tuple(
                    receipt_id
                    for receipt_id, expires_at in consumed.items()
                    if expires_at + 5.0 < now
                )
                for receipt_id in expired:
                    consumed.pop(receipt_id, None)
                if not consumed and authority != domain:
                    _CONSUMED_LOAD_RECEIPTS.pop(authority, None)
            consumed = _CONSUMED_LOAD_RECEIPTS.get(domain)
            if consumed is None:
                if len(_CONSUMED_LOAD_RECEIPTS) >= _MAX_REPLAY_AUTHORITIES:
                    return False
                consumed = {}
                _CONSUMED_LOAD_RECEIPTS[domain] = consumed
            if receipt.receipt_id in consumed:
                return False
            if len(consumed) >= _MAX_RECEIPTS_PER_AUTHORITY:
                return False
            consumed[receipt.receipt_id] = float(receipt.expires_at)
        return True

    def verify(
        self, evidence: "DriverProvenanceEvidence", receipt: DriverLoadReceipt
    ) -> bool:
        if not isinstance(receipt, DriverLoadReceipt):
            return False
        try:
            now = float(self._clock())
        except Exception:
            return False
        if (
            not math.isfinite(now)
            or receipt.authority_id != self._authority_id
            or receipt.host_id != self._host_id
            or receipt.install_id != self._install_id
            or receipt.boot_id != self._boot_id
            or receipt.driver_token != evidence.driver_token
            or receipt.image_sha256 != evidence.image_sha256
            or receipt.image_size != evidence.image_size
            or receipt.load_state != evidence.load_state
            or receipt.code_integrity_disposition != "trusted"
            or evidence.binding_receipt_sha256 != receipt.digest()
            or not receipt.issued_at - 5.0
            <= float(evidence.observed_at)
            <= receipt.expires_at + 5.0
            or not receipt.issued_at - 5.0 <= now <= receipt.expires_at
            or now - receipt.issued_at > 300.0
        ):
            return False
        try:
            signature = base64.b64decode(
                receipt.signature_ed25519.encode("ascii"), validate=True
            )
            self._public_key.verify(signature, receipt.signing_bytes())
        except Exception:
            return False
        return self._consume_once(receipt, now)


@dataclass(frozen=True)
class DriverProvenanceEvidence:
    schema: str
    driver_token: str
    image_sha256: str | None
    image_size: int | None
    load_state: str
    binding_state: str
    binding_source: str
    binding_receipt_sha256: str | None
    signer_status: str
    signer_thumbprint: str | None
    catalog_status: str
    blocklist_status: str
    blocklist_source: str
    hvci_enabled: bool | None
    secure_boot: bool | None
    observed_at: float
    binding_receipt: DriverLoadReceipt | None = None

    def __post_init__(self) -> None:
        if self.schema != SCHEMA:
            raise DriverEvidenceRejected("driver evidence schema version is invalid")
        if not isinstance(self.driver_token, str) or not _HEX_64.fullmatch(self.driver_token):
            raise DriverEvidenceRejected("driver identity token is invalid")
        if self.image_sha256 is not None and (
            not isinstance(self.image_sha256, str) or not _HEX_64.fullmatch(self.image_sha256)
        ):
            raise DriverEvidenceRejected("driver image hash is invalid")
        if self.image_size is not None and (
            type(self.image_size) is not int or not 0 <= self.image_size <= MAX_DRIVER_BYTES
        ):
            raise DriverEvidenceRejected("driver image size is invalid")
        if self.load_state not in {"running", "stopped", "unknown"}:
            raise DriverEvidenceRejected("driver load state is invalid")
        if self.binding_state not in {
            "loaded-image-bound",
            "configured-path-sample-unbound",
            "unknown",
        }:
            raise DriverEvidenceRejected("driver binding state is invalid")
        if self.binding_source not in {
            "kernel-load-receipt",
            "configured-service-path",
            "unavailable",
        }:
            raise DriverEvidenceRejected("driver binding source is invalid")
        if self.binding_receipt_sha256 is not None and (
            not isinstance(self.binding_receipt_sha256, str)
            or not _HEX_64.fullmatch(self.binding_receipt_sha256)
        ):
            raise DriverEvidenceRejected("driver binding receipt is invalid")
        if self.binding_receipt is not None and not isinstance(
            self.binding_receipt, DriverLoadReceipt
        ):
            raise DriverEvidenceRejected("typed driver binding receipt is invalid")
        if self.binding_receipt is not None and (
            self.binding_receipt_sha256 is None
            or not hmac.compare_digest(
                self.binding_receipt_sha256, self.binding_receipt.digest()
            )
        ):
            raise DriverEvidenceRejected(
                "typed driver binding receipt digest does not match"
            )
        if self.binding_state == "loaded-image-bound":
            if (
                self.binding_source != "kernel-load-receipt"
                or self.binding_receipt_sha256 is None
                or self.load_state == "unknown"
            ):
                raise DriverEvidenceRejected(
                    "loaded-image binding lacks a trusted load receipt"
                )
        elif (
            self.binding_receipt_sha256 is not None
            or self.binding_receipt is not None
            or self.binding_source == "kernel-load-receipt"
            or self.load_state != "unknown"
        ):
            raise DriverEvidenceRejected(
                "unbound disk evidence cannot claim an exact load state"
            )
        if self.signer_status not in {"trusted", "untrusted", "unknown"}:
            raise DriverEvidenceRejected("driver signer status is invalid")
        if self.signer_thumbprint is not None and (
            not isinstance(self.signer_thumbprint, str)
            or not _HEX_40_OR_64.fullmatch(self.signer_thumbprint)
        ):
            raise DriverEvidenceRejected("driver signer thumbprint is invalid")
        if self.catalog_status not in {"trusted", "not-present", "untrusted", "unknown"}:
            raise DriverEvidenceRejected("driver catalog status is invalid")
        if self.blocklist_status not in {"listed", "not-listed", "unknown"}:
            raise DriverEvidenceRejected("driver blocklist status is invalid")
        if self.blocklist_source not in {
            "microsoft-policy",
            "local-hash-policy",
            "bundled-name-match",
            "bundled-name-no-match",
            "unavailable",
        }:
            raise DriverEvidenceRejected("driver blocklist source is invalid")
        if self.blocklist_status == "listed" and self.blocklist_source in {
            "bundled-name-no-match",
            "unavailable",
        }:
            raise DriverEvidenceRejected("listed driver has no affirmative blocklist source")
        if self.blocklist_status == "not-listed" and self.blocklist_source not in {
            "microsoft-policy",
            "local-hash-policy",
        }:
            raise DriverEvidenceRejected("not-listed claim lacks a complete policy source")
        if self.blocklist_status == "unknown" and self.blocklist_source not in {
            "bundled-name-no-match",
            "unavailable",
        }:
            raise DriverEvidenceRejected("unknown blocklist claim has an inconsistent source")
        _optional_bool(self.hvci_enabled, "hvci_enabled")
        _optional_bool(self.secure_boot, "secure_boot")
        if (
            not isinstance(self.observed_at, (int, float))
            or isinstance(self.observed_at, bool)
            or not math.isfinite(float(self.observed_at))
            or not 0.0 <= float(self.observed_at) <= 32_503_680_000.0
        ):
            raise DriverEvidenceRejected("driver observation time is invalid")

    def digest(self) -> str:
        return hashlib.sha256(
            json.dumps(
                asdict(self), sort_keys=True, separators=(",", ":"), allow_nan=False
            ).encode("utf-8")
        ).hexdigest()

    def posture_digest(self) -> str:
        """Stable dedupe digest; the evidence receipt still retains observed_at."""

        body = asdict(self)
        body.pop("observed_at", None)
        receipt = body.pop("binding_receipt", None)
        body.pop("binding_receipt_sha256", None)
        if isinstance(receipt, dict):
            body["binding_authority_posture"] = {
                key: receipt.get(key)
                for key in (
                    "authority_id", "host_id", "install_id", "boot_id",
                    "load_generation", "driver_token", "object_identity",
                    "image_base", "image_size", "image_sha256", "load_state",
                    "code_integrity_disposition",
                )
            }
        return hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()


def parse_driver_evidence(value: Mapping[str, object]) -> DriverProvenanceEvidence:
    if not isinstance(value, Mapping) or set(value) not in {
        _EVIDENCE_REQUIRED_KEYS,
        _EVIDENCE_KEYS,
    }:
        raise DriverEvidenceRejected("driver evidence schema is invalid")
    document = dict(value)
    raw_receipt = document.get("binding_receipt")
    if raw_receipt is not None:
        if not isinstance(raw_receipt, Mapping):
            raise DriverEvidenceRejected("typed driver binding receipt is invalid")
        document["binding_receipt"] = parse_driver_load_receipt(raw_receipt)
    else:
        document["binding_receipt"] = None
    for field in ("hvci_enabled", "secure_boot"):
        document[field] = _optional_bool(document[field], field)
    try:
        return DriverProvenanceEvidence(**document)
    except TypeError as exc:
        raise DriverEvidenceRejected("driver evidence contract is invalid") from exc


@dataclass(frozen=True)
class DriverProvenanceAssessment:
    state: str
    severity: str
    evidence_complete: bool
    response_authorized: bool
    risks: tuple[str, ...]
    unknown: tuple[str, ...]
    evidence_digest: str

    def event_details(self, driver_token: str) -> dict:
        return {
            "schema": "angerona.driver-provenance-assessment.v1",
            "driver_token": driver_token,
            "state": self.state,
            "evidence_complete": self.evidence_complete,
            "risk_codes": list(self.risks),
            "unknown_fields": list(self.unknown),
            "evidence_sha256": self.evidence_digest,
            "raw_driver_path_omitted": True,
            "driver_control_performed": False,
            "response_authorized": False,
            "response_authority": "observe-only",
        }


def assess_driver_provenance(
    evidence: DriverProvenanceEvidence,
    receipt_verifier: DriverLoadReceiptVerifier | None = None,
) -> DriverProvenanceAssessment:
    if not isinstance(evidence, DriverProvenanceEvidence):
        raise TypeError("driver provenance evidence contract is invalid")
    risks: list[str] = []
    unknown: list[str] = []
    claimed_loaded_binding = evidence.binding_state == "loaded-image-bound"
    loaded_image_bound = False
    if (
        claimed_loaded_binding
        and receipt_verifier is not None
        and evidence.binding_receipt is not None
    ):
        loaded_image_bound = receipt_verifier.verify(
            evidence, evidence.binding_receipt
        )
    if not loaded_image_bound:
        unknown.append("loaded_image_binding")
        if claimed_loaded_binding:
            unknown.append("load_receipt_authentication")
    if evidence.load_state == "unknown":
        unknown.append("load_state")
    if evidence.image_sha256 is None:
        unknown.append("image_sha256")
    if evidence.image_size is None:
        unknown.append("image_size")
    if evidence.signer_status == "untrusted":
        risks.append(
            "loaded-driver-signature-untrusted"
            if loaded_image_bound
            else "configured-path-signature-untrusted"
        )
    elif evidence.signer_status == "unknown":
        unknown.append("signer_status")
    elif evidence.signer_thumbprint is None:
        unknown.append("signer_thumbprint")
    if evidence.catalog_status == "untrusted":
        risks.append(
            "loaded-driver-catalog-untrusted"
            if loaded_image_bound
            else "configured-path-catalog-untrusted"
        )
    elif evidence.catalog_status == "unknown":
        unknown.append("catalog_status")
    if evidence.blocklist_status == "listed":
        risks.append("known-vulnerable-driver-listed")
    elif evidence.blocklist_status == "unknown":
        unknown.append("blocklist_status")
    if evidence.hvci_enabled is False:
        risks.append("hvci-not-running")
    elif evidence.hvci_enabled is None:
        unknown.append("hvci_enabled")
    if evidence.secure_boot is False:
        risks.append("secure-boot-disabled")
    elif evidence.secure_boot is None:
        unknown.append("secure_boot")
    evidence_complete = not unknown and loaded_image_bound
    if (
        "known-vulnerable-driver-listed" in risks
        and loaded_image_bound
        and evidence.load_state == "running"
    ):
        state, severity = "critical-loaded-blocklisted-driver", "critical"
    elif risks:
        state, severity = "driver-provenance-risk", "high"
    elif unknown:
        state, severity = "incomplete-driver-evidence", "medium"
    else:
        state, severity = "provenance-verified", "info"
    return DriverProvenanceAssessment(
        state=state,
        severity=severity,
        evidence_complete=evidence_complete,
        response_authorized=False,
        risks=tuple(sorted(set(risks))),
        unknown=tuple(sorted(set(unknown))),
        evidence_digest=evidence.digest(),
    )


@dataclass(frozen=True)
class DriverCollection:
    evidence: tuple[DriverProvenanceEvidence, ...]
    complete: bool
    reason: str
    total_count: int | None = None
    truncated: bool = False


class DriverEvidenceProvider(Protocol):
    def collect(self) -> DriverCollection: ...


class WindowsDriverEvidenceProvider:
    """Collect bounded, unbound configured-path samples through PowerShell."""

    def __init__(self, posture_provider: BootPostureProvider | None = None) -> None:
        self._posture_provider = posture_provider or WindowsBootPostureProvider()

    @staticmethod
    def _query() -> object | None:
        if not sys.platform.startswith("win"):
            return None
        script = r"""
$rows = [Collections.Generic.List[object]]::new()
$allDrivers = @(Get-CimInstance Win32_SystemDriver -Filter "State='Running'" |
  Sort-Object Name)
$totalCount = [int]$allDrivers.Count
$drivers = @($allDrivers | Select-Object -First 256)
foreach ($driver in $drivers) {
  $raw = [Environment]::ExpandEnvironmentVariables([string]$driver.PathName)
  $path = $null
  if ($raw -match '^\s*"([^"]+\.sys)"') { $path = $Matches[1] }
  elseif ($raw -match '^\s*(.+?\.sys)(?:\s|$)') { $path = $Matches[1] }
  if ($path -and $path.StartsWith('\SystemRoot\', [StringComparison]::OrdinalIgnoreCase)) {
    $path = Join-Path $env:SystemRoot $path.Substring(12)
  }
  if ($path -and $path.StartsWith('\??\', [StringComparison]::OrdinalIgnoreCase)) {
    $path = $path.Substring(4)
  }
  if ($path -and $path.StartsWith('\\?\', [StringComparison]::OrdinalIgnoreCase)) {
    $path = $path.Substring(4)
  }
  if ($path -and $path -notmatch '^[A-Za-z]:\\') { $path = $null }
  $hash = $null; $size = $null; $sigStatus = 'Unknown'; $sigType = 'Unknown'; $thumb = $null
  if ($path -and (Test-Path -LiteralPath $path -PathType Leaf)) {
    try {
      $item = Get-Item -LiteralPath $path -ErrorAction Stop
      $beforeLength = [int64]$item.Length; $beforeWrite = [int64]$item.LastWriteTimeUtc.Ticks
      if (-not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -and
          $item.Length -le 134217728) {
        $size = [int64]$item.Length
        $hash = [string](Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash
        $sig = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
        $sigStatus = [string]$sig.Status
        $sigType = [string]$sig.SignatureType
        if ($sig.SignerCertificate) { $thumb = [string]$sig.SignerCertificate.Thumbprint }
        $after = Get-Item -LiteralPath $path -ErrorAction Stop
        if ([int64]$after.Length -ne $beforeLength -or
            [int64]$after.LastWriteTimeUtc.Ticks -ne $beforeWrite) {
          $hash = $null; $size = $null; $sigStatus = 'Unknown'; $sigType = 'Unknown'; $thumb = $null
        }
      }
    } catch { }
  }
  $fileName = if ($path) { [IO.Path]::GetFileName($path) } else { '' }
  [void]$rows.Add([pscustomobject]@{
    name = ([string]$driver.Name).Substring(0, [Math]::Min(256, ([string]$driver.Name).Length))
    file_name = $fileName
    hash = $hash; size = $size; signature_status = $sigStatus
    signature_type = $sigType; signer_thumbprint = $thumb
  })
}
[pscustomobject]@{
  schema = 'angerona.driver-inventory.v1'
  total_count = $totalCount
  truncated = ($totalCount -gt 256)
  rows = @($rows)
} | ConvertTo-Json -Compress -Depth 4
"""
        try:
            powershell = trusted_powershell_path().resolve(strict=True)
        except Exception:
            return None
        command = [
            str(powershell),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            "$ErrorActionPreference='Stop'; " + script,
        ]
        try:
            result = run_hidden(
                command,
                capture_output=True,
                text=True,
                timeout=45,
                check=False,
            )
            output = (result.stdout or "").strip()
            if result.returncode != 0 or not output or len(output.encode("utf-8")) > MAX_OUTPUT_BYTES:
                return None
            return json.loads(output)
        except Exception:
            return None

    def collect(self) -> DriverCollection:
        document = self._query()
        if document is None:
            return DriverCollection((), False, "driver-inventory-unavailable")
        if not isinstance(document, dict) or set(document) != {
            "schema", "total_count", "truncated", "rows"
        }:
            return DriverCollection((), False, "driver-inventory-schema-invalid")
        total_count = document.get("total_count")
        truncated = document.get("truncated")
        rows = document.get("rows")
        if (
            document.get("schema") != "angerona.driver-inventory.v1"
            or type(total_count) is not int
            or not 0 <= total_count <= 65_536
            or type(truncated) is not bool
            or truncated is not (total_count > MAX_DRIVERS)
            or not isinstance(rows, list)
            or len(rows) > MAX_DRIVERS
            or len(rows) != min(total_count, MAX_DRIVERS)
        ):
            return DriverCollection(
                (), False, "driver-inventory-schema-invalid", total_count=None, truncated=False
            )
        posture = self._posture_provider.snapshot()
        secure_boot = posture.get("secure_boot")
        if type(secure_boot) is not bool:
            secure_boot = None
        hvci = posture.get("hvci")
        if type(hvci) is not bool:
            hvci = None
        observed = time.time()
        evidence: list[DriverProvenanceEvidence] = []
        for row in rows:
            if not isinstance(row, dict) or set(row) != {
                "name",
                "file_name",
                "hash",
                "size",
                "signature_status",
                "signature_type",
                "signer_thumbprint",
            }:
                return DriverCollection(
                    tuple(evidence), False, "driver-row-schema-invalid", total_count, truncated
                )
            name = row.get("name")
            if not isinstance(name, str) or not name or len(name) > 256:
                return DriverCollection(
                    tuple(evidence), False, "driver-name-invalid", total_count, truncated
                )
            file_name = row.get("file_name")
            if not isinstance(file_name, str) or len(file_name) > 260:
                return DriverCollection(
                    tuple(evidence), False, "driver-file-name-invalid", total_count, truncated
                )
            token = hashlib.sha256(
                ("driver:" + name.casefold() + "|" + file_name.casefold()).encode("utf-8")
            ).hexdigest()
            image_hash = row.get("hash")
            if isinstance(image_hash, str):
                image_hash = image_hash.casefold()
            if not isinstance(image_hash, str) or not _HEX_64.fullmatch(image_hash):
                image_hash = None
            size = row.get("size")
            if type(size) is not int or not 0 <= size <= MAX_DRIVER_BYTES:
                size = None
            signature_status_text = str(row.get("signature_status") or "").casefold()
            if signature_status_text == "valid":
                signer_status = "trusted"
            elif signature_status_text in {
                "notsigned",
                "hashmismatch",
                "nottrusted",
                "unknownerror",
                "incompatible",
            }:
                signer_status = "untrusted"
            else:
                signer_status = "unknown"
            signature_type = str(row.get("signature_type") or "").casefold()
            if signature_type == "catalog":
                catalog_status = "trusted" if signer_status == "trusted" else "untrusted"
            elif signature_type in {"authenticode", "none"}:
                catalog_status = "not-present"
            else:
                catalog_status = "unknown"
            thumbprint = row.get("signer_thumbprint")
            if isinstance(thumbprint, str):
                thumbprint = thumbprint.casefold()
            if not isinstance(thumbprint, str) or not _HEX_40_OR_64.fullmatch(thumbprint):
                thumbprint = None
            block_match = is_known_bad_driver(file_name or name, image_hash or "")
            block_status = "listed" if block_match else "unknown"
            block_source = "bundled-name-match" if block_match else "bundled-name-no-match"
            evidence.append(
                DriverProvenanceEvidence(
                    schema=SCHEMA,
                    driver_token=token,
                    image_sha256=image_hash,
                    image_size=size,
                    load_state="unknown",
                    binding_state="configured-path-sample-unbound",
                    binding_source="configured-service-path",
                    binding_receipt_sha256=None,
                    signer_status=signer_status,
                    signer_thumbprint=thumbprint,
                    catalog_status=catalog_status,
                    blocklist_status=block_status,
                    blocklist_source=block_source,
                    hvci_enabled=hvci,
                    secure_boot=secure_boot,
                    observed_at=observed,
                )
            )
        return DriverCollection(
            tuple(evidence),
            not truncated,
            (
                "driver-inventory-truncated"
                if truncated
                else "bounded-configured-driver-path-inventory-unbound"
            ),
            total_count,
            truncated,
        )


class DriverProvenanceGuard(BaseModule):
    CODE = "DPVG"
    NAME = "Driver Provenance Guard"
    name = "Driver Provenance Guard"
    description = (
        "Joins bounded configured-path samples with signer/catalog, blocklist, "
        "HVCI, and Secure Boot evidence; loaded-image proof requires a trusted "
        "kernel load receipt."
    )
    category = "Integrity"
    version = "1.13.0"
    supported_platforms = frozenset(SUPPORTED_PLATFORMS)
    capability_mode = "observe"
    platform_requirements = (
        "Windows driver inventory access",
        "file hash and Authenticode query access",
    )
    _INTERVAL = 900.0

    def __init__(
        self,
        provider: DriverEvidenceProvider | None = None,
        *,
        receipt_verifier: DriverLoadReceiptVerifier | None = None,
    ) -> None:
        super().__init__()
        self._provider = provider or WindowsDriverEvidenceProvider()
        if receipt_verifier is not None and not isinstance(
            receipt_verifier, DriverLoadReceiptVerifier
        ):
            raise DriverEvidenceRejected("driver load receipt verifier is invalid")
        self._receipt_verifier = receipt_verifier
        self._last_digests: dict[str, str] = {}
        self._last_collection_digest = ""

    def observe_once(self) -> tuple[DriverProvenanceAssessment, ...]:
        collection = self._provider.collect()
        if not isinstance(collection, DriverCollection):
            raise DriverEvidenceRejected("driver evidence provider contract is invalid")
        if len(collection.evidence) > MAX_DRIVERS:
            raise DriverEvidenceRejected("driver evidence exceeded its record bound")
        if (
            not isinstance(collection.evidence, tuple)
            or type(collection.complete) is not bool
            or not isinstance(collection.reason, str)
            or not collection.reason
            or type(collection.truncated) is not bool
            or (
                collection.total_count is not None
                and (
                    type(collection.total_count) is not int
                    or not 0 <= collection.total_count <= 65_536
                )
            )
        ):
            raise DriverEvidenceRejected("driver collection metadata is invalid")
        inconsistency = ""
        if collection.complete and not collection.evidence:
            inconsistency = "driver-inventory-empty-cannot-prove-coverage"
        elif collection.complete and collection.truncated:
            inconsistency = "driver-inventory-complete-truncated-conflict"
        elif (
            collection.complete
            and collection.total_count is not None
            and collection.total_count != len(collection.evidence)
        ):
            inconsistency = "driver-inventory-count-mismatch"
        elif collection.truncated and (
            collection.total_count is None
            or collection.total_count <= len(collection.evidence)
        ):
            inconsistency = "driver-inventory-truncation-mismatch"
        if inconsistency:
            collection = DriverCollection(
                collection.evidence,
                False,
                inconsistency,
                collection.total_count,
                collection.truncated,
            )
        if not collection.complete:
            self.set_health(20, collection.reason)
            self.emit(
                "Driver provenance coverage is incomplete",
                Severity.HIGH,
                schema="angerona.driver-provenance-coverage.v1",
                reason_code=collection.reason,
                observed_driver_count=len(collection.evidence),
                reported_driver_count=collection.total_count,
                omitted_driver_count=(
                    max(0, collection.total_count - len(collection.evidence))
                    if collection.total_count is not None
                    else None
                ),
                collection_truncated=collection.truncated,
                driver_control_performed=False,
                response_authorized=False,
                response_authority="observe-only",
            )
        assessments: list[DriverProvenanceAssessment] = []
        current_digests: dict[str, str] = {}
        worst = 100
        incomplete_count = 0
        verified_count = 0
        for evidence in collection.evidence:
            if not isinstance(evidence, DriverProvenanceEvidence):
                raise DriverEvidenceRejected("driver evidence provider returned an invalid record")
            result = assess_driver_provenance(evidence, self._receipt_verifier)
            assessments.append(result)
            posture_digest = evidence.posture_digest()
            current_digests[evidence.driver_token] = posture_digest
            if result.severity == "critical":
                worst = min(worst, 5)
            elif result.severity == "high":
                worst = min(worst, 20)
            elif result.severity == "medium":
                worst = min(worst, 55)
                incomplete_count += 1
            else:
                verified_count += 1
            if self._last_digests.get(evidence.driver_token) == posture_digest:
                continue
            if result.severity not in {"critical", "high"}:
                continue
            if not set(result.risks).intersection(
                {
                    "known-vulnerable-driver-listed",
                    "loaded-driver-signature-untrusted",
                    "loaded-driver-catalog-untrusted",
                    "configured-path-signature-untrusted",
                    "configured-path-catalog-untrusted",
                }
            ):
                continue
            severity = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "info": Severity.INFO,
            }[result.severity]
            self.emit(
                "Driver provenance: " + result.state,
                severity,
                **result.event_details(evidence.driver_token),
                blocklist_source=evidence.blocklist_source,
                binding_state=evidence.binding_state,
                binding_source=evidence.binding_source,
                user_mode_observation=True,
                attribution="not-assessed",
                mitre_tags=["T1068", "T1562.001"],
            )
        disappeared = set(self._last_digests) - set(current_digests)
        if disappeared:
            self.emit(
                "Driver provenance evidence set changed",
                Severity.MEDIUM,
                schema="angerona.driver-provenance-set.v1",
                disappeared_count=len(disappeared),
                driver_tokens_omitted=True,
                driver_control_performed=False,
                response_authorized=False,
                response_authority="observe-only",
            )
        collection_digest = hashlib.sha256(
            "|".join(
                f"{token}:{digest}" for token, digest in sorted(current_digests.items())
            ).encode("ascii")
        ).hexdigest()
        if collection.complete and collection_digest != self._last_collection_digest:
            high_or_critical_count = sum(
                item.severity in {"high", "critical"} for item in assessments
            )
            self.emit(
                "Driver provenance scan completed",
                Severity.HIGH
                if high_or_critical_count
                else Severity.MEDIUM
                if incomplete_count
                else Severity.INFO,
                schema="angerona.driver-provenance-scan.v1",
                observed_driver_count=len(collection.evidence),
                verified_count=verified_count,
                incomplete_count=incomplete_count,
                high_or_critical_count=high_or_critical_count,
                collection_sha256=collection_digest,
                driver_tokens_omitted=True,
                driver_control_performed=False,
                response_authorized=False,
                response_authority="observe-only",
            )
        self._last_digests = current_digests
        self._last_collection_digest = collection_digest
        if collection.complete and assessments:
            note = "driver provenance verified" if worst == 100 else "driver evidence requires review"
            self.set_health(worst, note)
        return tuple(assessments)

    def run(self) -> None:
        if not sys.platform.startswith("win"):
            self.set_health(0, "Windows driver provenance evidence is unavailable on this host")
            while not self.stopping:
                self.sleep(self._INTERVAL)
            return
        while not self.stopping:
            self.observe_once()
            self.sleep(self._INTERVAL)

    def self_test(self) -> tuple[bool, str]:
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
            )
        except Exception as exc:
            return False, f"Ed25519 verifier unavailable: {type(exc).__name__}"
        private_key = Ed25519PrivateKey.generate()
        now = time.time()
        authority_id = "1" * 64
        host_id = "2" * 64
        install_id = "3" * 64
        boot_id = "4" * 64
        receipt = DriverLoadReceipt.issue(
            private_key,
            authority_id=authority_id,
            host_id=host_id,
            install_id=install_id,
            boot_id=boot_id,
            load_generation=1,
            driver_token="a" * 64,
            object_identity="5" * 64,
            image_base=0x100000,
            image_size=4096,
            image_sha256="b" * 64,
            load_state="running",
            code_integrity_disposition="trusted",
            issued_at=now,
            expires_at=now + 60.0,
        )
        fixture = DriverProvenanceEvidence(
            schema=SCHEMA,
            driver_token="a" * 64,
            image_sha256="b" * 64,
            image_size=4096,
            load_state="running",
            binding_state="loaded-image-bound",
            binding_source="kernel-load-receipt",
            binding_receipt_sha256=receipt.digest(),
            signer_status="trusted",
            signer_thumbprint="c" * 40,
            catalog_status="trusted",
            blocklist_status="not-listed",
            blocklist_source="local-hash-policy",
            hvci_enabled=True,
            secure_boot=True,
            observed_at=now,
            binding_receipt=receipt,
        )
        verifier = DriverLoadReceiptVerifier(
            private_key.public_key(),
            authority_id=authority_id,
            host_id=host_id,
            install_id=install_id,
            boot_id=boot_id,
            clock=lambda: now,
        )
        result = assess_driver_provenance(fixture, verifier)
        if result.state != "provenance-verified" or result.response_authorized:
            return False, "driver evidence join failed its observe-only contract"
        return True, "hash/signer/catalog/blocklist/HVCI/boot evidence join passed offline"


def register() -> DriverProvenanceGuard:
    return DriverProvenanceGuard()


__all__ = [
    "DriverCollection",
    "DriverEvidenceProvider",
    "DriverEvidenceRejected",
    "DriverProvenanceAssessment",
    "DriverProvenanceEvidence",
    "DriverProvenanceGuard",
    "DriverLoadReceipt",
    "DriverLoadReceiptVerifier",
    "MAX_DRIVERS",
    "SCHEMA",
    "WindowsDriverEvidenceProvider",
    "assess_driver_provenance",
    "parse_driver_evidence",
    "parse_driver_load_receipt",
    "register",
]
