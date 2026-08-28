"""Read-only driver provenance and BYOVD posture guard.

The guard joins image hash, Authenticode/catalog evidence, a bounded local
blocklist disposition, HVCI, and Secure Boot state.  Missing evidence is
``unknown`` rather than safe.  This module cannot unload, disable, quarantine,
delete, or otherwise control a driver.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import sys
import time
from dataclasses import asdict, dataclass
from typing import Mapping, Protocol

from angerona.core.module_base import BaseModule, Severity
from angerona.core.privilege import trusted_powershell_path
from angerona.core.win import run_hidden
from angerona.modules.intel_sync import is_known_bad_driver
from angerona.modules.platform_attestation_guard import (
    BootPostureProvider,
    WindowsBootPostureProvider,
)


SCHEMA = "angerona.driver-provenance-evidence.v1"
MAX_DRIVERS = 256
MAX_OUTPUT_BYTES = 512 * 1024
MAX_DRIVER_BYTES = 128 * 1024 * 1024
_HEX_40_OR_64 = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_EVIDENCE_KEYS = frozenset(
    {
        "schema",
        "driver_token",
        "image_sha256",
        "image_size",
        "load_state",
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
SUPPORTED_PLATFORMS = ("windows",)


class DriverEvidenceRejected(ValueError):
    """Driver evidence was ambiguous or outside the bounded schema."""


def _optional_bool(value: object, field: str) -> bool | None:
    if value is None or type(value) is bool:
        return value
    raise DriverEvidenceRejected(f"{field} must be boolean or null")


@dataclass(frozen=True)
class DriverProvenanceEvidence:
    schema: str
    driver_token: str
    image_sha256: str | None
    image_size: int | None
    load_state: str
    signer_status: str
    signer_thumbprint: str | None
    catalog_status: str
    blocklist_status: str
    blocklist_source: str
    hvci_enabled: bool | None
    secure_boot: bool | None
    observed_at: float

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
        return hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()


def parse_driver_evidence(value: Mapping[str, object]) -> DriverProvenanceEvidence:
    if not isinstance(value, Mapping) or set(value) != _EVIDENCE_KEYS:
        raise DriverEvidenceRejected("driver evidence schema is invalid")
    document = dict(value)
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
) -> DriverProvenanceAssessment:
    if not isinstance(evidence, DriverProvenanceEvidence):
        raise TypeError("driver provenance evidence contract is invalid")
    risks: list[str] = []
    unknown: list[str] = []
    if evidence.load_state == "unknown":
        unknown.append("load_state")
    if evidence.image_sha256 is None:
        unknown.append("image_sha256")
    if evidence.image_size is None:
        unknown.append("image_size")
    if evidence.signer_status == "untrusted":
        risks.append("loaded-driver-signature-untrusted")
    elif evidence.signer_status == "unknown":
        unknown.append("signer_status")
    elif evidence.signer_thumbprint is None:
        unknown.append("signer_thumbprint")
    if evidence.catalog_status == "untrusted":
        risks.append("loaded-driver-catalog-untrusted")
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
    evidence_complete = not unknown
    if "known-vulnerable-driver-listed" in risks and evidence.load_state == "running":
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
    """Collect bounded loaded-driver metadata through a fixed PowerShell query."""

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
                    load_state="running",
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
                else "bounded-loaded-driver-inventory"
            ),
            total_count,
            truncated,
        )


class DriverProvenanceGuard(BaseModule):
    CODE = "DPVG"
    NAME = "Driver Provenance Guard"
    name = "Driver Provenance Guard"
    description = (
        "Joins loaded-driver hash, signer/catalog evidence, blocklist disposition, "
        "HVCI, and Secure Boot state without changing driver state."
    )
    category = "Integrity"
    version = "1.0.0"
    supported_platforms = frozenset(SUPPORTED_PLATFORMS)
    capability_mode = "observe"
    platform_requirements = (
        "Windows driver inventory access",
        "file hash and Authenticode query access",
    )
    _INTERVAL = 900.0

    def __init__(self, provider: DriverEvidenceProvider | None = None) -> None:
        super().__init__()
        self._provider = provider or WindowsDriverEvidenceProvider()
        self._last_digests: dict[str, str] = {}
        self._last_collection_digest = ""

    def observe_once(self) -> tuple[DriverProvenanceAssessment, ...]:
        collection = self._provider.collect()
        if not isinstance(collection, DriverCollection):
            raise DriverEvidenceRejected("driver evidence provider contract is invalid")
        if len(collection.evidence) > MAX_DRIVERS:
            raise DriverEvidenceRejected("driver evidence exceeded its record bound")
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
            result = assess_driver_provenance(evidence)
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
                user_mode_observation=True,
                attribution="not-assessed",
                mitre_tags=["T1068", "T1562.001"],
            )
        disappeared = set(self._last_digests) - set(current_digests)
        if disappeared:
            self.emit(
                "Loaded-driver evidence set changed",
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
        if collection.complete:
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
        fixture = DriverProvenanceEvidence(
            schema=SCHEMA,
            driver_token="a" * 64,
            image_sha256="b" * 64,
            image_size=4096,
            load_state="running",
            signer_status="trusted",
            signer_thumbprint="c" * 40,
            catalog_status="trusted",
            blocklist_status="not-listed",
            blocklist_source="local-hash-policy",
            hvci_enabled=True,
            secure_boot=True,
            observed_at=1_800_000_000.0,
        )
        result = assess_driver_provenance(fixture)
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
    "MAX_DRIVERS",
    "SCHEMA",
    "WindowsDriverEvidenceProvider",
    "assess_driver_provenance",
    "parse_driver_evidence",
    "register",
]
