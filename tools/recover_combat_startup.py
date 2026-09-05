"""Inspect, or explicitly finish, one interrupted startup-deception checkpoint.

This maintenance command never truncates a journal, creates a signing key,
replays an action or starts Combat. It refuses every history containing a host
containment action. Run with Angerona stopped; inspection is the default.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import stat
import sys
import uuid

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from angerona.modules.adversary_combat import (  # noqa: E402
    AdversaryCombat, JournalIntegrityError, _JOURNAL_CONTEXT,
)
from angerona.core.secure_store import _path_traverses_reparse, _private_acl  # noqa: E402


def _read_regular(path: Path, maximum: int) -> bytes:
    if _path_traverses_reparse(path):
        raise ValueError("Recovery input traverses a link or reparse point")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0)
                         | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or not 0 < before.st_size <= maximum):
            raise ValueError("Recovery input is not a bounded ordinary file")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(maximum + 1)
        after, current = os.fstat(descriptor), path.stat(follow_symlinks=False)
        identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
        if (len(raw) != before.st_size or identity(before) != identity(after)
                or identity(after) != identity(current) or current.st_nlink != 1):
            raise ValueError("Recovery input changed during inspection")
        return raw
    finally:
        os.close(descriptor)


def _no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate journal field")
        result[key] = value
    return result


def _require_stopped() -> None:
    import psutil

    for process in psutil.process_iter(["pid", "name"]):
        if process.pid == os.getpid():
            continue
        name = str(process.info.get("name") or "").casefold()
        if not (name.startswith("angerona") or name.startswith("python")):
            continue
        try:
            arguments = process.cmdline()
        except psutil.NoSuchProcess:
            continue
        except psutil.AccessDenied as exc:
            raise ValueError("Cannot verify that every Angerona process is stopped") from exc
        if name.startswith("angerona") or any(
            arg == "angerona" or arg.startswith("angerona.")
            or "/angerona/__main__.py" in arg.replace("\\", "/").casefold()
            for arg in arguments
        ):
            raise ValueError("Stop Angerona before applying checkpoint recovery")


def inspect_startup(root: Path):
    """Return a non-secret report and the exact authenticated repair inputs."""
    root = Path(os.path.abspath(root))
    module = AdversaryCombat(root)
    key_bytes = _read_regular(root / "bus.key", 256)
    key = bytes.fromhex(key_bytes.decode("ascii").strip())
    if len(key) != 32:
        raise ValueError("Existing bus authority is invalid")
    module._journal_key_cache = hmac.new(key, _JOURNAL_CONTEXT, hashlib.sha256).digest()
    journal = _read_regular(module.receipt_path, 32 * 1024 * 1024)
    # Pin the encrypted store too: unrelated credential writes invalidate the
    # review token rather than being overwritten by a stale recovery plan.
    encrypted = _read_regular(root / "secrets.dpapi", 1024 * 1024)
    witness_bytes = _read_regular(module.recovery_witness_path, 16 * 1024)
    anchor = module._validated_recovery_anchor(module._read_recovery_anchor_value())
    module._verify_recovery_witness(anchor)
    if anchor["schema"] != 2:
        raise ValueError("Legacy recovery authority requires separate migration")
    lines = journal.splitlines()
    if not journal.endswith(b"\n") or not 1 <= len(lines) <= 32768:
        raise ValueError("Startup journal is incomplete or exceeds its record budget")
    records = []
    previous = "0" * 64
    for sequence, line in enumerate(lines, 1):
        if len(line) > 64 * 1024:
            raise ValueError("Journal record exceeds its byte budget")
        record = json.loads(line, object_pairs_hook=_no_duplicate_keys)
        if not isinstance(record, dict) or not module._signed_journal_schema_valid(record):
            raise ValueError("Journal record schema is invalid")
        signature = record["record_hmac"]
        core = {k: v for k, v in record.items() if k != "record_hmac"}
        if (record["sequence"] != sequence or record["previous_hmac"] != previous
                or not hmac.compare_digest(signature, module._record_hmac(core))):
            raise ValueError("Journal chain authentication failed")
        if (record.get("action") != "activate_honeypots"
                or record.get("combat_id") != "startup"
                or record.get("target") != "Smart Deception"
                or record.get("reversible") is not True
                or record.get("details", {}).get("module") != "Smart Deception"
                or record["record_type"] != ("intent" if sequence % 2 else "commit")):
            raise ValueError("Recovery is restricted to paired startup-deception history")
        if sequence % 2 == 0 and record["action_id"] != records[-1]["action_id"]:
            raise ValueError("Startup completion is not paired with its intent")
        previous = signature
        records.append(record)
    tail = records[-1]
    if (len(records) % 2 != 1 or anchor["last_journal_sequence"] != len(records) - 1
            or anchor["last_journal_hmac"] != tail["previous_hmac"]
            or anchor["active_action_id"] or anchor["active_challenge_sequence"]
            or anchor["consumed_terminal_sequence"] or anchor["challenge_counter"]):
        raise ValueError("Not an exact one-record interrupted startup checkpoint")
    if encrypted != _read_regular(root / "secrets.dpapi", 1024 * 1024):
        raise ValueError("Protected authority changed during inspection")
    material = b"\0".join((str(root).encode(), key_bytes, journal, encrypted, witness_bytes))
    digest = hashlib.sha256(material).hexdigest()
    report = {
        "eligible": True, "journal_records": len(records),
        "checkpoint_sequence": anchor["last_journal_sequence"],
        "pending_action": "startup honeypot activation", "review_token": digest,
        "host_actions_executed": 0,
    }
    return report, module, tail, (journal, encrypted, witness_bytes)


def recover_startup(root: Path, expected_token: str) -> dict:
    """Explicit maintenance only; retain the entire pre-repair encrypted state."""
    _require_stopped()
    report, module, _tail, _inputs = inspect_startup(root)
    if not hmac.compare_digest(report["review_token"], expected_token):
        raise ValueError("Recovery inputs changed; inspect and review again")
    with module._journal_writer_lease():
        report, module, tail, inputs = inspect_startup(root)
        if not hmac.compare_digest(report["review_token"], expected_token):
            raise ValueError("Recovery inputs changed before the writer lease")
        _require_stopped()
        backup = Path(root) / ("combat-startup-recovery-" + uuid.uuid4().hex)
        backup.mkdir(mode=0o700)
        _private_acl(backup)
        for filename, raw in zip(
            ("adversary_combat_actions.jsonl", "secrets.dpapi", "recovery_witness.json"),
            inputs,
        ):
            path = backup / filename
            with path.open("xb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            _private_acl(path)
            if _read_regular(path, 32 * 1024 * 1024) != raw:
                raise ValueError("Pre-recovery backup did not verify")
        # Recheck after backup I/O and keep journal identity pinned while
        # advancing the existing anchor/witness. No journal record is changed.
        current, _same, _tail, _inputs = inspect_startup(root)
        if not hmac.compare_digest(current["review_token"], expected_token):
            raise ValueError("Recovery inputs changed during backup")
        with module._pinned_journal_session(create=False):
            pinned, _same, _tail, _inputs = inspect_startup(root)
            if not hmac.compare_digest(pinned["review_token"], expected_token):
                raise ValueError("Recovery inputs changed while pinning the journal")
            module._assert_journal_session(module._active_journal_session())
            module._advance_recovery_anchor(tail)
            records, legacy = module._read_journal(strict=True)
            if legacy or len(records) != report["journal_records"]:
                raise JournalIntegrityError("Recovered journal verification failed")
        return {**report, "checkpoint_sequence": len(records), "recovered": True,
                "backup_directory": str(backup), "rearmed": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", required=True, type=Path)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--expected-token", default="")
    args = parser.parse_args()
    try:
        if args.apply:
            if not args.expected_token:
                raise ValueError("Apply requires the reviewed inspection token")
            report = recover_startup(args.data_root, args.expected_token)
        else:
            report = inspect_startup(args.data_root)[0]
        print(json.dumps(report, indent=2))
        return 0
    except Exception as exc:
        print(json.dumps({"eligible": False, "error": str(exc), "rearmed": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
