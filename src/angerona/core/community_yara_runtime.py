"""Optional reviewed user rules layered over the bundled YARA scanner.

Created and used by the module's worker thread. Includes/imports stay disabled,
rules are namespace-isolated, and matches grant no special response authority.
An optional pack failure preserves bundled matches and reports incomplete scan
coverage. This is a user-mode native scanner, not an OS execution sandbox.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import time
from types import SimpleNamespace

from angerona.core.rule_playbook_library import configured_library
from angerona.core.community_tool_probe_worker import source_namespace


class _CombinedScanner:
    def __init__(self, base, community, provenance, *, runtime=None):
        self.base, self.community, self.provenance = base, community, provenance
        self.runtime = runtime
        self.community_error = ""

    def scan(self, payload):
        self.community_error = ""
        if self.runtime is not None:
            current = self.runtime.compose(self.base)
            if current is not self:
                # Archives can contain many members; refresh the same bounded
                # cache at each payload, not only at the next outer traversal.
                status = self.runtime.snapshot()
                result = current.scan(payload)
                self.community_error = str(getattr(current, "community_error", ""))
                if status["state"] == "unavailable":
                    self.community_error = status["reason"] or "Community YARA coverage unavailable"
                return result
        original = self.base.scan(payload)
        matches = list(original.matching_rules)
        self.community_error = ""
        try:
            result = self.community.scan(payload)
            for match in result.matching_rules:
                namespace = str(getattr(match, "namespace", ""))
                matches.append(SimpleNamespace(identifier="Community_" + namespace + "_" + str(match.identifier)))
        except Exception:
            self.community_error = "Optional community YARA scan failed or timed out; bundled results are preserved"
        return SimpleNamespace(matching_rules=matches)


class CommunityYaraRuntime:
    def __init__(self, config, *, library=None, compiler=None, scanner=None, clock=time.monotonic):
        self.config = config
        self.library = library or configured_library(config)
        self.compiler_factory = compiler
        self.scanner_factory = scanner
        self.clock = clock
        self._next_read = self._last_read = 0.0
        self._digest = ""
        self._compiled = self._scanner = self._combined = self._base = None
        self._provenance = {}
        self._state, self._reason = "disabled", ""

    def _clear(self, state, reason=""):
        # Native scanner references are destroyed on this creator/owner thread.
        self._compiled = self._scanner = self._combined = self._base = None
        self._digest, self._provenance = "", {}
        self._state, self._reason = state, reason

    def compose(self, base):
        if getattr(self.config, "community_rules_enabled", False) is not True:
            self._clear("disabled")
            self._next_read = self._last_read = 0.0
            return base
        try:
            now = self.clock()
            valid_clock = type(now) in (int, float) and math.isfinite(now) and now >= self._last_read
        except Exception:
            valid_clock = False
        if not valid_clock:
            self._clear("unavailable", "Community YARA policy clock unavailable")
            self._next_read = 0.0
            return base
        self._last_read = now
        if now >= self._next_read:
            self._next_read = now + 5.0
            try:
                rows = self.library.active_data("yara")
                if len(rows) > 32 or sum(len(row["text"].encode()) for row in rows) > 64 * 1024:
                    raise ValueError("Active community rule set exceeds its 32-source/64 KiB budget")
                canonical = json.dumps([(row["id"], row["active_sha256"], row.get("compile_input_sha256", row["active_sha256"])) for row in rows], separators=(",", ":")).encode()
                digest = hashlib.sha256(canonical).hexdigest()
                if not rows:
                    self._clear("ready")
                elif digest != self._digest:
                    import yara_x
                    compiler = (self.compiler_factory or yara_x.Compiler)()
                    compiler.enable_includes(False)
                    compiler.max_warnings(32)
                    provenance = {}
                    for row in rows:
                        text = row["text"]
                        if not text or re.search(r"\b(?:include|import)\b", text):
                            raise ValueError("Community rule includes and imported modules are not supported")
                        if hashlib.sha256(text.encode("utf-8")).hexdigest() != row.get("compile_input_sha256", row["active_sha256"]):
                            raise ValueError("Community rule bytes changed before native compilation")
                        namespace = source_namespace(row["id"])
                        compiler.new_namespace(namespace)
                        compiler.add_source(text, origin=row["path"])
                        provenance[namespace] = {key: row[key] for key in ("id", "repository", "commit", "path", "license", "active_sha256")}
                        provenance[namespace]["compile_input_sha256"] = hashlib.sha256(text.encode("utf-8")).hexdigest()
                    compiled = compiler.build()
                    scanner = (self.scanner_factory or yara_x.Scanner)(compiled)
                    scanner.set_timeout(2)
                    scanner.max_matches_per_pattern(64)
                    scanner.fast_scan(True)
                    self._compiled, self._scanner = compiled, scanner
                    self._provenance, self._digest = provenance, digest
                    self._combined = self._base = None
                    self._state, self._reason = "ready", ""
            except Exception as exc:
                self._clear("unavailable", str(exc)[:240])
        if self._scanner is None:
            return base
        if self._combined is None or self._base is not base:
            self._base = base
            self._combined = _CombinedScanner(base, self._scanner, self._provenance, runtime=self)
        return self._combined

    def snapshot(self):
        return {"state": self._state, "reason": self._reason, "sources": len(self._provenance),
                "response_authorized": False}

    def close(self):
        self._clear("stopped")
