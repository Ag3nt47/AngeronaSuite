"""smart_deception.py — Hyper-contextual AI honeytokens (CODE: SDEC).

Upgrades the static canary approach in deception.py: instead of fixed decoy
names, it samples the *shape* of the user's Documents folder and asks the local
Ollama model to invent decoy filenames that blend in with the real ones, then
drops those honeytokens into high-value locations. Any process that touches one
triggers an immediate CRITICAL alert.

Privacy: only file/folder *names* are sampled and sent to the LOCAL Ollama
(loopback :11434, zero egress) — never file contents. If Ollama is unavailable,
a static fallback name list is used so honeytokens still deploy.

Detection uses the same proven mechanism as deception.py: each decoy carries an
anchor token; deletion, token loss (encryption/overwrite), or an exclusive lock
(active encryptor holding the handle) trips the trap. Tripped decoys are
re-staged immediately to prevent alert spam.

Standard library only (os, json, time, ctypes, random, urllib) — Windows hidden
attribute via ctypes, matching deception.py.
"""
from __future__ import annotations

import ctypes
import json
import os
import random
import time
import urllib.request
from pathlib import Path
from typing import Optional

from angerona.core.module_base import BaseModule, Severity


ANCHOR_TOKEN = "UDE_DECOY_TOKEN::CONFIDENTIAL_DATA_DO_NOT_MODIFY_OR_ENCRYPT"

DOCS_DIR = os.path.expandvars(r"%USERPROFILE%\Documents")
DEPLOY_TARGETS = [
    os.path.expandvars(r"%USERPROFILE%\Desktop"),
    os.path.expandvars(r"%USERPROFILE%\Documents"),
    os.path.expandvars(r"%APPDATA%"),
]

_OLLAMA_HOST  = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
_OLLAMA_MODEL = os.environ.get("ANGERONA_MODEL", "llama3")
_GEN_TIMEOUT_S = 20.0
_MAX_SAMPLE   = 60      # names sampled from Documents
_DECOYS_PER_TARGET = 3

_FALLBACK_NAMES = [
    "Tax_Return_2024_FINAL.xlsx", "Passwords_backup.docx", "Q4_Payroll.xlsx",
    "Bank_Statements_Q1.pdf", "Employee_SSN_master.csv", "Wallet_seed_phrase.txt",
    "VPN_credentials.docx", "Client_Contracts_signed.pdf", "Crypto_keys_cold.txt",
]

_GEN_SYSTEM_PROMPT = (
    "You generate decoy (honeytoken) filenames for a security deception system. "
    "Given a sample of real filenames from a user's Documents folder, invent "
    "convincing high-value decoy filenames that blend in (finance, credentials, "
    "personal records). Respond with ONLY a JSON array of filename strings, no "
    "prose, e.g. [\"Tax_2024.xlsx\", \"vault_keys.txt\"]. 8-12 names, each with a "
    "realistic extension."
)


class SmartDeception(BaseModule):
    name = "Smart Deception"
    CODE = "SDEC"
    description = "AI-generated contextual honeytokens; CRITICAL alert on tamper."
    category = "Deception"
    version = "1.0.0"

    MONITOR_S = 2.5          # decoy tamper-check cadence. 2.5s (was 1s) roughly
                             # halves idle wake-ups; a token-loss/lock is still
                             # caught within a couple seconds. The Adaptive Resource
                             # Governor can widen this further under load.
    REFRESH_S = 24 * 3600.0  # regenerate decoy set daily

    def __init__(self) -> None:
        super().__init__()
        self._decoys: list[str] = []      # deployed decoy file paths
        self._last_refresh = 0.0
        self._trips = 0

    # ── Generation ────────────────────────────────────────────────────────────
    def _sample_documents(self) -> list[str]:
        names: list[str] = []
        try:
            for root, dirs, files in os.walk(DOCS_DIR):
                for fn in files:
                    names.append(fn)
                    if len(names) >= _MAX_SAMPLE:
                        return names
        except Exception:
            pass
        return names

    def _generate_names(self) -> list[str]:
        """Ask Ollama for blended decoy names; fall back to a static list."""
        sample = self._sample_documents()
        if not sample:
            return list(_FALLBACK_NAMES)
        user = "Real filenames sample:\n" + json.dumps(sample)
        payload = json.dumps({
            "model": _OLLAMA_MODEL,
            "messages": [
                {"role": "system", "content": _GEN_SYSTEM_PROMPT},
                {"role": "user",   "content": user},
            ],
            "stream": False,
            "format": "json",
            "keep_alive": "30m",
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{_OLLAMA_HOST}/api/chat", data=payload,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=_GEN_TIMEOUT_S) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            content = (data.get("message", {}) or {}).get("content", "")
            names = json.loads(content)
            names = [self._safe_name(n) for n in names if isinstance(n, str)]
            names = [n for n in names if n]
            return names or list(_FALLBACK_NAMES)
        except Exception as exc:
            self.set_health(80, f"AI name-gen unavailable ({exc}); using fallback names.")
            return list(_FALLBACK_NAMES)

    @staticmethod
    def _safe_name(name: str) -> str:
        """Strip path separators / traversal so a model can't redirect the drop."""
        base = os.path.basename(name.strip().replace("\\", "/"))
        return "".join(c for c in base if c not in '<>:"|?*').strip()

    # ── Deployment ────────────────────────────────────────────────────────────
    def _deploy(self, names: list[str]) -> None:
        # Remove previously-deployed decoys first so the daily REFRESH_S
        # regeneration doesn't leave orphaned, unmonitored honeytokens piling up
        # in Documents/Desktop/APPDATA.
        for old in self._decoys:
            try:
                os.remove(old)
            except Exception:
                pass
        self._decoys.clear()
        for target in DEPLOY_TARGETS:
            if not os.path.isdir(target):
                continue
            for name in random.sample(names, min(_DECOYS_PER_TARGET, len(names))):
                path = os.path.join(target, name)
                if self._write_decoy(path):
                    self._decoys.append(path)
        self.emit(f"Deployed {len(self._decoys)} AI honeytokens across "
                  f"{len(DEPLOY_TARGETS)} locations.", Severity.INFO)

    def _write_decoy(self, path: str) -> bool:
        try:
            if os.path.exists(path):   # never clobber a real user file
                return False
            with open(path, "w", encoding="utf-8") as f:
                f.write(ANCHOR_TOKEN)
            try:
                # HIDDEN|SYSTEM (0x2|0x4): stays invisible even when the user has
                # "show hidden files" enabled, so decoys never clutter the desktop.
                ctypes.windll.kernel32.SetFileAttributesW(path, 0x2 | 0x4)
            except Exception:
                pass   # non-Windows or attribute failure — decoy still valid
            return True
        except Exception:
            return False

    # ── Monitoring ────────────────────────────────────────────────────────────
    def _check_decoy(self, path: str) -> Optional[str]:
        """Return a tamper reason if compromised, else None."""
        if not os.path.exists(path):
            return "deleted/wiped"
        try:
            with open(path, "r", encoding="utf-8") as f:
                if ANCHOR_TOKEN not in f.read():
                    return "anchor token missing (encrypted/overwritten)"
        except (IOError, PermissionError) as exc:
            return f"exclusive lock (active encryption): {exc}"
        return None

    def _trip(self, path: str, reason: str) -> None:
        self._trips += 1
        self.emit(f"HONEYTOKEN TRIPPED: {os.path.basename(path)} — {reason}",
                  Severity.CRITICAL, path=path, reason=reason)
        # Re-stage to keep the trap live without alert spam.
        self._write_decoy(path)

    # ── Loop ──────────────────────────────────────────────────────────────────
    def run(self) -> None:
        self._deploy(self._generate_names())
        self._last_refresh = time.time()

        while not self.stopping:
            for path in list(self._decoys):
                reason = self._check_decoy(path)
                if reason:
                    self._trip(path, reason)

            if time.time() - self._last_refresh >= self.REFRESH_S:
                self._deploy(self._generate_names())
                self._last_refresh = time.time()

            if self.health >= 90:
                self.set_health(100, f"{len(self._decoys)} decoys live; {self._trips} trips")
            self.sleep(self.MONITOR_S)

    def stop(self) -> None:
        # Best-effort cleanup so we don't leave decoys behind on shutdown.
        for path in self._decoys:
            try:
                os.remove(path)
            except Exception:
                pass
        super().stop()

    def self_test(self) -> tuple[bool, str]:
        return True, f"{len(self._decoys)} honeytokens deployed; {self._trips} trips"


def register() -> SmartDeception:
    return SmartDeception()
