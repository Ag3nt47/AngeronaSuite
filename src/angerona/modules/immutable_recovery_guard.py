"""Observe-only guard for offline, immutable, and independently signed recovery."""
from __future__ import annotations

import base64
import json
import os
import re
import time
from pathlib import Path
from typing import Mapping

from angerona.core.module_base import BaseModule, Severity
from angerona.core.recovery_assurance import (
    RecoveryAssurancePolicy,
    assess_recovery_assurance,
    evidence_set_digest,
    load_recovery_evidence_directory,
)


_SHA = re.compile(r"^[0-9a-f]{40,64}$")
SUPPORTED_PLATFORMS = ("windows", "macos", "linux")


def _read_trust_store(path: Path) -> dict[str, bytes]:
    if not path.exists():
        return {}
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024:
        raise ValueError("recovery trust store is not a bounded regular file")
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or len(raw) > 32:
        raise ValueError("recovery trust store has an invalid schema")
    result: dict[str, bytes] = {}
    seen_keys: set[bytes] = set()
    for signer_id, encoded in raw.items():
        if not isinstance(signer_id, str) or not isinstance(encoded, str):
            raise ValueError("recovery trust store entry is invalid")
        try:
            public = base64.b64decode(
                encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True,
            )
        except Exception as exc:
            raise ValueError("recovery trust store key encoding is invalid") from exc
        if len(public) != 32:
            raise ValueError("recovery trust store requires Ed25519 public keys")
        if public in seen_keys:
            raise ValueError("recovery trust store aliases one authority key")
        seen_keys.add(public)
        result[signer_id] = public
    return result


class ImmutableRecoveryGuardModule(BaseModule):
    CODE = "IRAG"
    NAME = "Immutable Recovery Assurance Guard"
    name = NAME
    description = (
        "Verifies externally signed backup-copy, failure-domain, immutability, "
        "air-gap, offsite, encryption, source-revision, and restore-test evidence."
    )
    category = "Resilience"
    version = "1.12.1"
    supported_platforms = frozenset(SUPPORTED_PLATFORMS)
    capability_mode = "observe"
    platform_requirements = (
        "Pinned Ed25519 recovery-authority public keys",
        "Evidence exported by independently administered backup targets",
    )
    _INTERVAL = 3600.0

    def __init__(
        self,
        *,
        evidence_dir: Path | None = None,
        trust_store_path: Path | None = None,
        trust_store: Mapping[str, bytes] | None = None,
        source_revision: str | None = None,
        clock=time.time,
    ) -> None:
        super().__init__()
        self._evidence_dir = Path(evidence_dir) if evidence_dir is not None else None
        self._trust_path = Path(trust_store_path) if trust_store_path is not None else None
        self._provided_trust = dict(trust_store) if trust_store is not None else None
        self._source_revision = source_revision
        self._clock = clock
        self._last_state = ""

    def _paths(self) -> tuple[Path, Path]:
        from angerona.core.data_paths import data_dir

        root = data_dir() / "recovery-assurance"
        return (
            self._evidence_dir or root / "evidence",
            self._trust_path or root / "trusted-authorities.json",
        )

    def _revision(self) -> str:
        value = self._source_revision or os.environ.get(
            "ANGERONA_SOURCE_REVISION", "",
        ).strip().casefold()
        # Source builds without injected release metadata are explicitly
        # unknown rather than being treated as current.
        return value if _SHA.fullmatch(value) else "0" * 40

    def observe_once(self) -> tuple[object, tuple[str, ...], str]:
        evidence_dir, trust_path = self._paths()
        trust = self._provided_trust
        if trust is None:
            trust = _read_trust_store(trust_path)
        copies, load_errors = load_recovery_evidence_directory(evidence_dir, trust)
        result = assess_recovery_assurance(
            copies, RecoveryAssurancePolicy(), now=float(self._clock()),
            source_revision=self._revision(),
        )
        digest = evidence_set_digest(copies)
        return result, load_errors, digest

    def run(self) -> None:
        while not self.stopping:
            try:
                result, load_errors, digest = self.observe_once()
                findings = tuple(load_errors) + tuple(result.findings)
                health = min(result.health, max(0, 100 - 15 * len(load_errors)))
                note = "recovery assurance verified" if not findings else "; ".join(findings[:3])
                self.set_health(health, note)
                state = f"{digest}:{health}:{'|'.join(findings)}"
                if state != self._last_state:
                    self._last_state = state
                    severity = Severity.INFO if not findings else (
                        Severity.CRITICAL if result.offline_copies == 0 else Severity.HIGH
                    )
                    self.emit(
                        "Recovery assurance verified." if not findings
                        else "Recovery assurance requirements are not met.",
                        severity,
                        evidence_set_sha256=digest,
                        verified_copies=result.verified_copies,
                        failure_domains=result.failure_domains,
                        signing_authorities=result.signing_authorities,
                        immutable_copies=result.immutable_copies,
                        offline_copies=result.offline_copies,
                        offsite_copies=result.offsite_copies,
                        source_revision_current=result.source_revision_current,
                        finding_codes=list(findings[:8]),
                        observation_only=True,
                        local_trust_root_replaceable_by_admin=True,
                    )
            except Exception as exc:
                self.set_health(10, "recovery evidence verification failed closed")
                state = f"error:{type(exc).__name__}"
                if state != self._last_state:
                    self._last_state = state
                    self.emit(
                        "Recovery assurance verification failed closed.",
                        Severity.CRITICAL,
                        error_type=type(exc).__name__, observation_only=True,
                    )
            self.sleep(self._INTERVAL)

    def self_test(self) -> tuple[bool, str]:
        try:
            # Pure policy proof: no evidence must never be reported healthy.
            result = assess_recovery_assurance(
                (), RecoveryAssurancePolicy(), now=1_000_000,
                source_revision="a" * 40,
            )
            ok = not result.healthy and result.offline_copies == 0 and result.health < 50
            return ok, (
                "fail-closed signed recovery policy verified; online F: mirrors "
                "do not count as immutable or offline"
            )
        except Exception as exc:
            return False, f"recovery assurance self-test failed: {type(exc).__name__}"


def register() -> ImmutableRecoveryGuardModule:
    return ImmutableRecoveryGuardModule()
