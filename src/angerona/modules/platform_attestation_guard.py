"""Observe-only measured-boot and platform-attestation guard.

The default Windows collector reports OS posture and TPM presence.  It does not
fabricate a TPM quote.  Hardware attestation is reported only when an injected
quote provider and verifier successfully validate a nonce-bound quote.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import sys
import time
from dataclasses import asdict
from typing import Mapping, Protocol

from angerona.core.measured_boot import (
    QUOTE_SCHEMA,
    SCHEMA,
    MeasuredBootAssessment,
    MeasuredBootEvidence,
    TpmQuoteVerifier,
    assess_measured_boot,
    parse_measured_boot_evidence,
)
from angerona.core.module_base import BaseModule, Severity
from angerona.core.privilege import trusted_powershell_path, trusted_windows_directories
from angerona.core.win import run_hidden


SUPPORTED_PLATFORMS = ("windows",)


class MeasuredBootProvider(Protocol):
    def collect(self, challenge_nonce: str) -> MeasuredBootEvidence | Mapping[str, object]: ...


class BootPostureProvider(Protocol):
    def snapshot(self) -> dict: ...


def _trusted_powershell_json(script: str, *, timeout: float = 10.0) -> object | None:
    if not sys.platform.startswith("win"):
        return None
    try:
        powershell = trusted_powershell_path().resolve(strict=True)
        result = run_hidden(
            [
                str(powershell),
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                "$ErrorActionPreference='Stop'; "
                + script
                + " | ConvertTo-Json -Compress -Depth 4",
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        output = (result.stdout or "").strip()
        if result.returncode != 0 or not output or len(output.encode("utf-8")) > 128 * 1024:
            return None
        return json.loads(output)
    except Exception:
        return None


class WindowsBootPostureProvider:
    """Query boot controls through a WinAPI-rooted PowerShell executable."""

    def snapshot(self) -> dict:
        if not sys.platform.startswith("win"):
            return {
                "secure_boot": None,
                "vbs_status": None,
                "hvci": None,
                "testsigning": None,
                "debug": None,
                "nointegritychecks": None,
            }
        try:
            _windows, system = trusted_windows_directories()
            bcdedit = str((system / "bcdedit.exe").resolve(strict=True)).replace("'", "''")
        except Exception:
            bcdedit = ""
        script = (
            "$secure=$null;$vbs=$null;$hvci=$null;$test=$null;$debug=$null;$nointegrity=$null;"
            "try {$secure=[bool](Confirm-SecureBootUEFI)} catch {};"
            "try {$d=Get-CimInstance -Namespace root\\Microsoft\\Windows\\DeviceGuard "
            "-ClassName Win32_DeviceGuard;$vbs=[int]$d.VirtualizationBasedSecurityStatus;"
            "$hvci=[bool](@($d.SecurityServicesRunning) -contains 2)} catch {};"
        )
        if bcdedit:
            script += (
                f"try {{$b=(& '{bcdedit}' /enum '{{current}}' 2>$null | Out-String);"
                "if ($LASTEXITCODE -eq 0) {"
                "$test=[bool]($b -match '(?im)^\\s*testsigning\\s+(yes|on|true|1)\\s*$');"
                "$debug=[bool]($b -match '(?im)^\\s*debug\\s+(yes|on|true|1)\\s*$');"
                "$nointegrity=[bool]($b -match "
                "'(?im)^\\s*nointegritychecks\\s+(yes|on|true|1)\\s*$')}} catch {{}};"
            )
        script += (
            "[pscustomobject]@{secure_boot=$secure;vbs_status=$vbs;hvci=$hvci;"
            "testsigning=$test;debug=$debug;nointegritychecks=$nointegrity}"
        )
        value = _trusted_powershell_json(script)
        if not isinstance(value, dict):
            return {
                "secure_boot": None,
                "vbs_status": None,
                "hvci": None,
                "testsigning": None,
                "debug": None,
                "nointegritychecks": None,
            }
        return {
            "secure_boot": value.get("secure_boot")
            if type(value.get("secure_boot")) is bool
            else None,
            "vbs_status": value.get("vbs_status")
            if type(value.get("vbs_status")) is int
            else None,
            "hvci": value.get("hvci") if type(value.get("hvci")) is bool else None,
            "testsigning": value.get("testsigning")
            if type(value.get("testsigning")) is bool
            else None,
            "debug": value.get("debug") if type(value.get("debug")) is bool else None,
            "nointegritychecks": value.get("nointegritychecks")
            if type(value.get("nointegritychecks")) is bool
            else None,
        }


class WindowsMeasuredBootProvider:
    """Bounded OS posture collector; quote collection must be injected."""

    def __init__(self, posture_provider: BootPostureProvider | None = None) -> None:
        self._posture_provider = posture_provider or WindowsBootPostureProvider()

    def _tpm(self) -> tuple[bool | None, str | None]:
        if not sys.platform.startswith("win"):
            return None, None
        value = _trusted_powershell_json(
            "$t=Get-Tpm; $w=Get-CimInstance -Namespace root\\CIMV2\\Security\\MicrosoftTpm "
            "-ClassName Win32_Tpm -ErrorAction SilentlyContinue; "
            "[pscustomobject]@{present=[bool]$t.TpmPresent; spec=[string]$w.SpecVersion}"
        )
        if not isinstance(value, dict):
            return None, None
        present = value.get("present")
        if type(present) is not bool:
            present = None
        version = value.get("spec")
        if not isinstance(version, str) or not version or len(version) > 32:
            version = None
        return present, version

    @staticmethod
    def _dma_posture() -> tuple[bool | None, bool | None]:
        """Return capability and restrictive-policy evidence, never an active-IOMMU claim."""

        if not sys.platform.startswith("win"):
            return None, None
        value = _trusted_powershell_json(
            "$d=Get-CimInstance -Namespace root\\Microsoft\\Windows\\DeviceGuard "
            "-ClassName Win32_DeviceGuard; $p=$null; try {$p=[int](Get-ItemPropertyValue "
            "-LiteralPath 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Kernel DMA Protection' "
            "-Name DeviceEnumerationPolicy -ErrorAction Stop)} catch {}; "
            "[pscustomobject]@{available=@($d.AvailableSecurityProperties);policy=$p}"
        )
        if not isinstance(value, dict):
            return None, None
        available = value.get("available")
        if not isinstance(available, list):
            available = [] if available is None else [available]
        try:
            dma_available = 3 in {int(item) for item in available}
        except (TypeError, ValueError):
            dma_available = None
        policy = value.get("policy")
        restrictive = policy in {0, 1} if type(policy) is int and policy in {0, 1, 2} else None
        return dma_available, restrictive

    def collect(self, challenge_nonce: str) -> Mapping[str, object]:
        del challenge_nonce  # OS posture is not a TPM quote and is never labelled as one.
        snapshot = self._posture_provider.snapshot() if sys.platform.startswith("win") else {}
        vbs = snapshot.get("vbs_status")
        vbs_running = bool(vbs >= 2) if type(vbs) is int else None
        no_integrity = snapshot.get("nointegritychecks")
        code_integrity = (not no_integrity) if type(no_integrity) is bool else None
        present, version = self._tpm()
        dma_available, dma_policy = self._dma_posture()
        return {
            "schema": SCHEMA,
            "observed_at": time.time(),
            "os_posture": {
                "secure_boot": snapshot.get("secure_boot")
                if type(snapshot.get("secure_boot")) is bool
                else None,
                "vbs_running": vbs_running,
                "hvci_running": snapshot.get("hvci")
                if type(snapshot.get("hvci")) is bool
                else None,
                "code_integrity_enabled": code_integrity,
                "test_signing": snapshot.get("testsigning")
                if type(snapshot.get("testsigning")) is bool
                else None,
                "boot_debug": snapshot.get("debug")
                if type(snapshot.get("debug")) is bool
                else None,
                "dma_protection_available": dma_available,
                "external_dma_policy_restrictive": dma_policy,
            },
            "tpm": {"present": present, "version": version, "quote": None},
        }


class PlatformAttestationGuard(BaseModule):
    CODE = "PATG"
    NAME = "Platform Attestation Guard"
    name = "Platform Attestation Guard"
    description = (
        "Appraises Secure Boot, VBS/HVCI, Code Integrity, boot flags, and optional "
        "nonce-bound TPM quotes without claiming kernel or hardware enforcement."
    )
    category = "Integrity"
    version = "1.13.0"
    supported_platforms = frozenset(SUPPORTED_PLATFORMS)
    capability_mode = "observe"
    platform_requirements = (
        "Windows boot-posture query access",
        "optional enrolled TPM attestation verifier",
    )
    _INTERVAL = 300.0

    def __init__(
        self,
        provider: MeasuredBootProvider | None = None,
        *,
        quote_verifier: TpmQuoteVerifier | None = None,
        nonce_factory=None,
    ) -> None:
        super().__init__()
        self._provider = provider or WindowsMeasuredBootProvider()
        self._quote_verifier = quote_verifier
        self._nonce_factory = nonce_factory or (lambda: secrets.token_urlsafe(32))
        self._last_fingerprint = ""
        self._last_state = ""

    def observe_once(self) -> MeasuredBootAssessment:
        nonce = self._nonce_factory()
        if not isinstance(nonce, str):
            raise ValueError("platform attestation nonce source returned an invalid type")
        raw = self._provider.collect(nonce)
        evidence = raw if isinstance(raw, MeasuredBootEvidence) else parse_measured_boot_evidence(raw)
        result = assess_measured_boot(
            evidence,
            expected_nonce=nonce,
            quote_verifier=self._quote_verifier,
        )
        quote = evidence.tpm.quote
        fingerprint = hashlib.sha256(
            json.dumps(
                {
                    "os_posture": asdict(evidence.os_posture),
                    "tpm_present": evidence.tpm.present,
                    "tpm_version": evidence.tpm.version,
                    "quote_key_id": quote.key_id if quote is not None else None,
                    "pcr_digest": quote.pcr_digest if quote is not None else None,
                    "quote_state": result.quote_state,
                    "risks": result.risks,
                    "unknown": result.unknown,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        if result.state == "hardware-attested":
            health = 100
        elif result.state == "os-posture-only":
            health = 82
        elif result.state == "incomplete-evidence":
            health = 45
        elif result.state == "insecure-posture":
            health = 20
        else:
            health = 10
        note = (
            ", ".join(result.risks)
            or ("unknown: " + ", ".join(result.unknown) if result.unknown else result.state)
        )
        self.set_health(health, note)
        if (
            fingerprint != self._last_fingerprint
            or result.state != self._last_state
        ):
            if result.risks:
                severity = Severity.CRITICAL if "tpm-quote-verification-failed" in result.risks else Severity.HIGH
                message = "Platform trust evidence rejected: " + ", ".join(result.risks)
            elif result.unknown:
                severity = Severity.MEDIUM
                message = "Platform trust evidence is incomplete"
            else:
                severity = Severity.INFO
                message = (
                    "Platform hardware attestation verified"
                    if result.hardware_attested
                    else "Platform OS posture observed without a verified TPM quote"
                )
            self.emit(
                message,
                severity,
                **result.event_details(),
                user_mode_observation=True,
                attribution="not-assessed",
                mitre_tags=["T1547", "T1562.001"],
            )
            self._last_fingerprint = fingerprint
            self._last_state = result.state
        return result

    def run(self) -> None:
        if not sys.platform.startswith("win"):
            self.set_health(0, "Windows measured-boot evidence is unavailable on this host")
            while not self.stopping:
                self.sleep(self._INTERVAL)
            return
        while not self.stopping:
            self.observe_once()
            self.sleep(self._INTERVAL)

    def self_test(self) -> tuple[bool, str]:
        nonce = "n" * 43

        class FixtureProvider:
            def collect(self, challenge_nonce: str):
                quote = {
                    "schema": QUOTE_SCHEMA,
                    "nonce": challenge_nonce,
                    "pcr_digest": "1" * 64,
                    "attestation_blob": "fixture_attestation",
                    "signature": "fixture_signature",
                    "key_id": "fixture-ak",
                }
                return {
                    "schema": SCHEMA,
                    "observed_at": 1_800_000_000.0,
                    "os_posture": {
                        "secure_boot": True,
                        "vbs_running": True,
                        "hvci_running": True,
                        "code_integrity_enabled": True,
                        "test_signing": False,
                        "boot_debug": False,
                        "dma_protection_available": True,
                        "external_dma_policy_restrictive": True,
                    },
                    "tpm": {"present": True, "version": "2.0", "quote": quote},
                }

        class FixtureVerifier:
            def verify(self, quote, *, expected_nonce, evidence_digest):
                return (
                    quote.nonce == expected_nonce
                    and len(evidence_digest) == 64
                    and quote.key_id == "fixture-ak"
                )

        probe = PlatformAttestationGuard(
            FixtureProvider(),
            quote_verifier=FixtureVerifier(),
            nonce_factory=lambda: nonce,
        )
        result = probe.observe_once()
        if not result.hardware_attested or result.response_authorized:
            return False, "nonce-bound platform attestation boundary failed"
        return True, "strict OS posture and injected TPM quote verifier passed offline"


def register() -> PlatformAttestationGuard:
    return PlatformAttestationGuard()


__all__ = [
    "MeasuredBootProvider",
    "BootPostureProvider",
    "PlatformAttestationGuard",
    "WindowsMeasuredBootProvider",
    "WindowsBootPostureProvider",
    "register",
]
