from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from angerona.core import ir_bundle


class _Bus:
    def __init__(self, events):
        self._events = events

    def recent(self, limit):
        return self._events[-limit:]


class IrBundlePrivacyTests(unittest.TestCase):
    def _collect(self, root: Path, *, events=()):
        logs = root / "shared_logs"
        logs.mkdir(exist_ok=True)
        output = root / "out"
        with (
            patch.object(ir_bundle, "_shared_logs", return_value=logs),
            patch.object(ir_bundle, "_process_list", return_value=[{
                "pid": 7, "ppid": 1, "name": "safe.exe", "mem_mb": 12.5,
            }]),
            patch.object(ir_bundle, "_connections", return_value=[{
                "pid": 7,
                "local": {"address_class": "private", "address_id": "<address:test>",
                          "port": 443},
                "remote": None,
                "status": "LISTEN",
                "type": "tcp",
            }]),
            patch.object(ir_bundle, "_system_info", return_value={
                "platform": "Windows", "collected_at": "2026-07-19T12:00:00-0400",
            }),
            patch("angerona.core.incident_timeline.build_timeline", return_value=[]),
        ):
            return ir_bundle.collect_triage_bundle(
                output, _Bus(list(events)), consent=True)

    def test_requires_explicit_consent_and_creates_nothing(self):
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / "out"
            with self.assertRaises(PermissionError):
                ir_bundle.collect_triage_bundle(dest)
            self.assertFalse(list(dest.glob("*.zip")) if dest.exists() else [])

    def test_redacts_secrets_identities_paths_and_addresses(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            logs = root / "shared_logs"
            logs.mkdir()
            username = os.environ.get("USERNAME") or os.environ.get("USER") or "local-user"
            secret = "fixture-secret-ThisMustNeverLeaveTheMachine-1234567890"
            dpapi = "AQAAANCMnd8BFdERjHoAwEAAAAAAAAAAAAAAAAAAAA"
            raw_path = f"C:\\Users\\{username}\\Documents\\case.txt"
            raw_ip = "203.0.113.44"
            (logs / "daily_briefing.json").write_text(json.dumps({
                "api_key": secret,
                "note": f"owner={username} path={raw_path} remote={raw_ip} blob={dpapi}",
            }), encoding="utf-8")
            event = SimpleNamespace(
                ts=1.0, module="test", severity=SimpleNamespace(name="HIGH"),
                message=(f"Authorization: Bearer short-secret-123456; token={secret}; "
                         f"from {raw_ip} at {raw_path}"),
                details={"password": secret, "nested": {"contact": "person@example.com"}},
            )
            path = self._collect(root, events=[event])
            with zipfile.ZipFile(path) as archive:
                payload = b"\n".join(archive.read(name) for name in archive.namelist())
                manifest = json.loads(archive.read("00_MANIFEST.json"))
            decoded = payload.decode("utf-8", errors="replace")
            for forbidden in (secret, "short-secret-123456", dpapi, raw_path, raw_ip,
                              "person@example.com"):
                self.assertNotIn(forbidden, decoded)
            self.assertNotIn(username, decoded)
            self.assertEqual(manifest["privacy"]["policy"], ir_bundle.POLICY_VERSION)
            self.assertGreater(manifest["privacy"]["redaction_counts"]["sensitive_fields"], 0)

    def test_excludes_arbitrary_and_protected_files(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            logs = root / "shared_logs"
            logs.mkdir()
            marker = "NEVER_EXPORT_THIS_MARKER"
            for name in ("secrets.dpapi", ".env", "flight-recorder.db", "random.log"):
                (logs / name).write_text(marker, encoding="utf-8")
            path = self._collect(root)
            with zipfile.ZipFile(path) as archive:
                self.assertFalse(any(
                    name.endswith(("secrets.dpapi", ".env", "flight-recorder.db", "random.log"))
                    for name in archive.namelist()
                ))
                content = b"".join(archive.read(name) for name in archive.namelist())
            self.assertNotIn(marker.encode(), content)

    def test_manifest_hashes_each_member_and_archive_is_bounded(self):
        with tempfile.TemporaryDirectory() as td:
            path = self._collect(Path(td))
            with zipfile.ZipFile(path) as archive:
                manifest = json.loads(archive.read("00_MANIFEST.json"))
                uncompressed = 0
                for name, record in manifest["members"].items():
                    content = archive.read(name)
                    uncompressed += len(content)
                    self.assertEqual(record["bytes"], len(content))
                    self.assertEqual(record["sha256"], hashlib.sha256(content).hexdigest())
            self.assertLessEqual(uncompressed, ir_bundle.MAX_ARCHIVE_BYTES)

    def test_oversized_curated_artifact_is_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            logs = root / "shared_logs"
            logs.mkdir()
            (logs / "daily_briefing.txt").write_bytes(
                b"x" * (ir_bundle.MAX_ARTIFACT_BYTES + 1))
            path = self._collect(root)
            with zipfile.ZipFile(path) as archive:
                manifest = json.loads(archive.read("00_MANIFEST.json"))
                self.assertNotIn("angerona/daily_briefing.txt", archive.namelist())
            self.assertEqual(manifest["skipped"]["daily_briefing.txt"], "size-limit")

    def test_symlinked_artifact_is_not_followed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            logs = root / "shared_logs"
            logs.mkdir()
            outside = root / "private.txt"
            outside.write_text("PRIVATE_OUTSIDE_DATA", encoding="utf-8")
            link = logs / "daily_briefing.txt"
            try:
                link.symlink_to(outside)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks are not available for this account")
            path = self._collect(root)
            with zipfile.ZipFile(path) as archive:
                manifest = json.loads(archive.read("00_MANIFEST.json"))
                content = b"".join(archive.read(name) for name in archive.namelist())
            self.assertNotIn(b"PRIVATE_OUTSIDE_DATA", content)
            self.assertEqual(manifest["skipped"]["daily_briefing.txt"], "unsafe-file-type")

    def test_symlink_file_type_is_rejected_even_without_os_symlink_support(self):
        with tempfile.TemporaryDirectory() as td:
            logs = Path(td)
            source = logs / "daily_briefing.txt"
            source.write_text("must not be read", encoding="utf-8")
            fake_stat = SimpleNamespace(st_mode=stat.S_IFLNK, st_size=16,
                                        st_dev=1, st_ino=1)
            with patch.object(Path, "lstat", return_value=fake_stat):
                content, reason = ir_bundle._safe_curated_artifact(
                    logs, "daily_briefing.txt", ir_bundle._PrivacyFilter())
            self.assertIsNone(content)
            self.assertEqual(reason, "unsafe-file-type")

    def test_recursive_telemetry_has_a_global_node_budget(self):
        redactor = ir_bundle._PrivacyFilter()
        hostile = [{str(i): [i, i + 1] for i in range(130)} for _ in range(40)]
        redacted = redactor.value(hostile)
        self.assertLessEqual(len(redacted), ir_bundle.MAX_CONTAINER_ITEMS)
        self.assertGreater(redactor.counts["node_budget_limited"], 0)

    def test_redaction_tokens_are_stable_inside_one_bundle(self):
        redactor = ir_bundle._PrivacyFilter()
        first = redactor.text("remote 198.51.100.3")
        second = redactor.text("again 198.51.100.3")
        self.assertEqual(first.split()[-1], second.split()[-1])
        self.assertNotIn("198.51.100.3", first + second)


if __name__ == "__main__":
    unittest.main()
