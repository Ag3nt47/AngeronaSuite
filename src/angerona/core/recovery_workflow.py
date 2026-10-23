"""Operator-authorized local recovery workflow for the existing guard worker.

No threads, network transport, key/signer generation, live replacement or backup
deletion. Imported signed statements remain assertions about the backup target;
a separate measured proof describes only a real isolated extraction and reread.
"""
from __future__ import annotations

import base64
import copy
import hashlib
from itertools import islice
import os
from pathlib import Path
import re
import threading
import time

from angerona.core.engine_transport import canonical, create_private_file, decode, private_directory, verify_private
from angerona.core.executable_trust import _open_sealed
from angerona.core.recovery_assurance import (
    MAX_EVIDENCE_BYTES, RecoveryAssurancePolicy, assess_recovery_assurance,
    load_recovery_evidence_directory, verify_recovery_envelope,
)
from angerona.core.recovery_drill import protected_keys, restore_external_archive, verify_external_restore
from angerona.core.source_sandbox import _absolute, _hold_plain_directories, _validate_chain, _validate_regular_file

MAX_RETAINED_DRILLS = 16
_SIGNER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@-]{2,127}\Z")


def _read(path, maximum):
    path = _absolute(path)
    if str(path).startswith(("\\\\", "//")):
        raise ValueError("Recovery import requires an explicitly selected local path")
    _validate_chain(path)
    with _hold_plain_directories(path.parent):
        _validate_regular_file(path)
        before = path.stat()
        if before.st_nlink != 1 or not 1 <= before.st_size <= maximum:
            raise ValueError("Recovery input is linked or exceeds its bound")
        with _open_sealed(path) as stream:
            held = os.fstat(stream.fileno())
            def identity(value):
                return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns
            if identity(held) != identity(before):
                raise ValueError("Recovery import identity changed")
            raw = stream.read(maximum + 1)
            if (len(raw) > maximum or identity(os.fstat(stream.fileno())) != identity(before)
                    or identity(path.stat()) != identity(before)):
                raise ValueError("Recovery import changed during read")
    return raw


def _write(path, payload, *, replace=False):
    target = path.with_name(".recovery-" + os.urandom(12).hex()) if replace else path
    descriptor = create_private_file(target)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        if replace:
            if path.exists():
                verify_private(path)
            os.replace(target, path)
    finally:
        if replace:
            target.unlink(missing_ok=True)


class RecoveryWorkflow:
    """All mutating/IO methods run on ImmutableRecoveryGuard's one worker."""

    def __init__(self, data_root, *, source_revision="0" * 40, clock=time.time,
                 monotonic=time.monotonic, key_loader=None, continue_work=lambda: True):
        self.data_root = Path(data_root)
        self.root = self.data_root / "recovery-assurance"
        self.evidence = self.root / "evidence"
        self.trust_path = self.root / "trusted-authorities.json"
        self.drills = self.root / "drills"
        self.revision, self.clock, self.monotonic = source_revision, clock, monotonic
        self.key_loader = key_loader or (lambda: protected_keys(create=False, data_root=self.data_root))
        self.continue_work = continue_work
        self._lock = threading.Lock()
        self._view = {"status": "deployment-required", "latest_signed_revision": None,
            "latest_verified_revision": None, "latest_restore_seconds": None,
            "last_verified_at": None, "finding_codes": ["no independently signed backup imported"],
            "physical_independence_proven": False, "live_paths_modified": False,
            "schedule_enabled": False, "schedule_status": "disabled", "next_drill_at": None}
        self._recipe = None
        self._last_restore = None
        self._interval = 24 * 3600
        self._due = None

    def snapshot(self):
        with self._lock:
            result = copy.deepcopy(self._view)
        if result.get("last_verified_at") is not None:
            age = self.clock() - result["last_verified_at"]
            result["last_verified_age_seconds"] = age if age >= 0 else None
            if age < 0:
                result.update(status="freshness-unknown", clock_warning="local-clock-before-last-verification")
        return result

    def _set(self, **values):
        with self._lock:
            self._view.update(values)

    def _check(self):
        if self.continue_work() is not True:
            raise InterruptedError("Recovery work cancelled or workspace held")

    def _prepare(self):
        self._check()
        _validate_chain(self.root, allow_missing_tail=True)
        private_directory(self.root)
        self._check()
        private_directory(self.evidence)
        self._check()
        private_directory(self.drills)

    def _trust(self):
        if not self.trust_path.exists():
            return {}
        verify_private(self.trust_path)
        raw = decode(_read(self.trust_path, MAX_EVIDENCE_BYTES))
        if len(raw) > 32:
            raise ValueError("Recovery signer enrollment exceeds its bound")
        keys = {}
        for name, value in raw.items():
            if not isinstance(name, str) or not _SIGNER.fullmatch(name) or not isinstance(value, str):
                raise ValueError("Recovery signer enrollment is invalid")
            key = base64.b64decode(value, validate=True)
            if len(key) != 32 or key in keys.values():
                raise ValueError("Recovery signer keys are invalid or aliased")
            keys[name] = key
        return keys

    def enroll_authority(self, signer_id, public_key):
        self._prepare()
        if (not isinstance(signer_id, str) or not _SIGNER.fullmatch(signer_id)
                or not isinstance(public_key, bytes) or len(public_key) != 32):
            raise ValueError("Explicit Ed25519 recovery public-key enrollment is invalid")
        keys = self._trust()
        if signer_id in keys and keys[signer_id] != public_key:
            raise ValueError("Existing recovery signer enrollment may not be replaced")
        if (public_key in [key for name, key in keys.items() if name != signer_id]
                or (signer_id not in keys and len(keys) >= 32)):
            raise ValueError("Recovery authority aliases or enrollment capacity are rejected")
        keys[signer_id] = public_key
        self._check()
        _write(self.trust_path, canonical({name: base64.b64encode(key).decode()
                                         for name, key in keys.items()}), replace=True)
        self._set(status="signer-enrolled", enrolled_signers=sorted(keys))

    def refresh_assurance(self):
        self._check()
        trust = self._trust()
        copies, errors = load_recovery_evidence_directory(self.evidence, trust)
        now = float(self.clock())
        result = assess_recovery_assurance(copies, RecoveryAssurancePolicy(), now=now,
                                           source_revision=self.revision)
        latest = max(copies, key=lambda row: row.statement.verified_at) if copies else None
        signed_state = "deployment-required"
        if latest is not None:
            statement = latest.statement
            signed_state = ("future-dated" if max(statement.created_at, statement.verified_at,
                            statement.restore_tested_at) > now + 300 else "stale" if
                            now - statement.created_at > 7 * 86400 or now - statement.verified_at > 7 * 86400
                            else "signature-verified-assertion")
        self._set(status="signed-evidence-current" if result.healthy and not errors else "coverage-gap",
            latest_signed_status=signed_state,
            latest_signed_revision=latest.statement.source_revision if latest else None,
            latest_signed_age_seconds=max(0, now - latest.statement.created_at) if latest else None,
            latest_signed_verification_age_seconds=max(0, now - latest.statement.verified_at) if latest else None,
            signed_claims_only=True, physical_independence_proven=False,
            finding_codes=list((*errors, *result.findings))[:16],
            verified_copy_count=result.verified_copies, signing_authority_count=result.signing_authorities,
            enrolled_signers=sorted(trust))
        return result

    def import_evidence(self, path):
        self._prepare()
        raw = _read(path, MAX_EVIDENCE_BYTES)
        verified = verify_recovery_envelope(raw, self._trust())
        target = self.evidence / (hashlib.sha256(raw).hexdigest() + ".json")
        if target.exists():
            if _read(target, MAX_EVIDENCE_BYTES) != raw:
                raise ValueError("Recovery evidence destination changed")
        else:
            if len(list(islice(self.evidence.glob("*.json"), 65))) >= 64:
                raise ValueError("Recovery evidence retention capacity reached")
            self._check()
            _write(target, raw)
        self.refresh_assurance()
        return target, verified

    def restore(self, archive, evidence, *, keys=None):
        self._prepare()
        evidence_path, verified = self.import_evidence(evidence)
        statement = verified.statement
        now = self.clock()
        if (max(statement.created_at, statement.verified_at, statement.restore_tested_at) > now + 300
                or now - statement.created_at > 7 * 86400 or now - statement.verified_at > 7 * 86400
                or not statement.encrypted):
            raise ValueError("Signed recovery copy is stale, future-dated or not encrypted")
        # Retain test artifacts without an unbounded scheduled plaintext backlog.
        with os.scandir(self.drills) as listing:
            entries = list(islice(listing, MAX_RETAINED_DRILLS + 1))
        if len(entries) >= MAX_RETAINED_DRILLS:
            self._set(schedule_enabled=False, schedule_status="retention-review-required")
            self._due = None
            raise ValueError("Isolated restore retention requires operator review; no artifacts deleted")
        reusable = keys is None
        borrowed = self.key_loader() if reusable else keys
        if (not isinstance(borrowed, tuple) or len(borrowed) != 2
                or any(not isinstance(key, (bytes, bytearray)) or len(key) != 32 for key in borrowed)):
            raise ValueError("Original recovery encryption and audit keys are required")
        try:
            self._set(status="restoring")
            result = restore_external_archive(archive, self.drills,
                encryption_key=bytes(borrowed[0]), audit_key=bytes(borrowed[1]),
                archive_sha256=statement.archive_sha256, manifest_sha256=statement.manifest_sha256,
                archive_size_bytes=statement.size_bytes,
                evidence_sha256=hashlib.sha256(_read(evidence_path, MAX_EVIDENCE_BYTES)).hexdigest(),
                source_revision=statement.source_revision, continue_work=self.continue_work)
            proof = result["proof"]
            self._last_restore = result["directory"]
            self._check()
            _write(self.root / "latest-local-restore.json", canonical({"restore_id": proof["restore_id"]}), replace=True)
            self._recipe = {"archive": str(Path(result["directory"]) / "backup.angerona"),
                            "evidence": str(evidence_path), "reusable_keys": reusable}
            if not reusable:
                self._due = None
                self._set(schedule_enabled=False, schedule_status="fresh-unlock-required", next_drill_at=None)
            self._set(status="isolated-restore-verified", latest_verified_revision=proof["source_revision"],
                latest_restore_seconds=proof["duration_seconds"], last_verified_at=proof["completed_at"],
                actual_restored_bytes_reread=True, restored_file_count=len(proof["inventory"]),
                last_restore_directory=result["directory"],
                separate_identity_claimed_by_signer=statement.separate_identity,
                offline_claimed_by_signer=statement.air_gapped, physical_independence_proven=False,
                fresh_unlock_required=not reusable, error="")
            return result
        finally:
            for key in borrowed:
                if isinstance(key, bytearray):
                    key[:] = b"\0" * len(key)

    def recheck(self, *, keys=None):
        self._check()
        if self._last_restore is None:
            pointer = decode(_read(self.root / "latest-local-restore.json", 1024))
            if (set(pointer) != {"restore_id"} or not isinstance(pointer["restore_id"], str)
                    or not re.fullmatch("[0-9a-f]{32}", pointer["restore_id"])):
                raise ValueError("No valid local isolated restore is available for recheck")
            self._last_restore = str(self.drills / ("restore-" + pointer["restore_id"]))
        borrowed = self.key_loader() if keys is None else keys
        try:
            result = verify_external_restore(self._last_restore, encryption_key=bytes(borrowed[0]),
                audit_key=bytes(borrowed[1]), continue_work=self.continue_work)
            proof = result["proof"]
            evidence = self.evidence / (proof["evidence_sha256"] + ".json")
            raw = _read(evidence, MAX_EVIDENCE_BYTES)
            signed = verify_recovery_envelope(raw, self._trust()).statement
            if (hashlib.sha256(raw).hexdigest() != proof["evidence_sha256"]
                    or signed.archive_sha256 != proof["archive_sha256"]
                    or signed.manifest_sha256 != proof["manifest_sha256"]
                    or signed.source_revision != proof["source_revision"]):
                raise ValueError("Isolated restore proof no longer has its enrolled signed evidence")
            self._recipe = {"archive": str(Path(self._last_restore) / "backup.angerona"),
                            "evidence": str(evidence), "reusable_keys": keys is None}
            if keys is not None:
                self._due = None
                self._set(schedule_enabled=False, schedule_status="fresh-unlock-required", next_drill_at=None)
            self._set(status="isolated-restore-rechecked", last_verified_at=result["checked_at"],
                latest_verified_revision=proof["source_revision"], latest_restore_seconds=proof["duration_seconds"],
                last_restore_directory=self._last_restore, actual_restored_bytes_reread=True,
                fresh_unlock_required=keys is not None, error="")
            return result
        finally:
            for key in borrowed:
                if isinstance(key, bytearray):
                    key[:] = b"\0" * len(key)

    def configure_schedule(self, enabled, interval_hours=24):
        self._check()
        if type(enabled) is not bool or type(interval_hours) is not int or not 1 <= interval_hours <= 720:
            raise ValueError("Recurring restore cadence is invalid")
        if enabled and (self._recipe is None or not self._recipe["reusable_keys"]):
            raise ValueError("A verified authorized archive and existing protected reusable keys are required")
        self._interval = interval_hours * 3600
        self._due = self.monotonic() + self._interval if enabled else None
        self._set(schedule_enabled=enabled, schedule_status="opted-in-runtime-only" if enabled else "disabled",
                  next_drill_at=self.clock() + self._interval if enabled else None)

    def cancel_schedule(self):
        """IO-free teardown; stopped workers must not revive an earlier opt-in."""
        self._due = None
        self._set(schedule_enabled=False, schedule_status="disabled-after-worker-stop", next_drill_at=None)

    def tick(self):
        if self._due is None or self.monotonic() < self._due:
            return
        if self.continue_work() is not True:
            self._set(schedule_status="workspace-held")
            return
        recipe = dict(self._recipe)
        self._due = self.monotonic() + self._interval
        self._set(next_drill_at=self.clock() + self._interval)
        self.restore(recipe["archive"], recipe["evidence"])

    def failure(self, error):
        # Error text can contain paths or credentials from platform providers.
        self._set(status="held" if isinstance(error, InterruptedError) else "verification-failed",
                  error=type(error).__name__, actual_restored_bytes_reread=False)
