"""ai_model_integrity.py — AI Model Integrity Guard (Code: AMIG).

Purpose
    Local LLM weights (e.g. Ollama blobs) are loaded into RAM and trusted by the
    triage engine. If an attacker tampers with or poisons a model file on disk,
    every downstream AI decision is compromised. AMIG computes cryptographic
    SHA-256 hashes of the local model blobs and compares them against a recorded
    baseline, raising a CRITICAL alert on any mismatch BEFORE the suite trusts a
    model for inference.

Trust-on-first-use baseline
    On first run (no baseline recorded) AMIG hashes the discovered model blobs
    and records them as the known-good baseline, then emits an INFO event naming
    what it pinned. On every subsequent pass it re-hashes and compares. This is
    TOFU: it detects post-baseline tampering. Re-pin deliberately by deleting the
    baseline file (or calling ``rebaseline()``) after an intentional model update.

Discovery
    Ollama blob directory, in priority order:
      1. ``ANGERONA_OLLAMA_MODELS`` (env)   2. ``OLLAMA_MODELS`` (env)
      3. ``%USERPROFILE%\\.ollama\\models`` (Windows) / ``~/.ollama/models``
    Hashes the ``blobs/sha256-*`` files. (An Ollama blob is content-addressed by
    its own sha256, so AMIG also flags a blob whose *content* no longer matches
    the sha256 embedded in its filename — a strong, self-describing check.)

Safety
    Read-only. Hashes files in 4 MB chunks (no whole-file load). Never modifies,
    deletes, or loads a model; on mismatch it only alerts — enforcement (refusing
    to load) is left to the AI triage layer / SOAR.

Drop-in contract: BaseModule subclass + CODE/NAME/state/health_pct/self_test +
module-level register().
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path

from angerona.core.module_base import BaseModule, Severity


def _repo_root() -> Path:
    from angerona.core.data_paths import data_dir
    return data_dir()


def _hash_file(filepath: str | os.PathLike, chunk: int = 4096 * 1024) -> str:
    """SHA-256 a (potentially multi-GB) file in chunks — no whole-file load."""
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for block in iter(lambda: f.read(chunk), b""):
                h.update(block)
        return h.hexdigest()
    except FileNotFoundError:
        return "FILE_NOT_FOUND"
    except Exception as exc:  # permission / IO
        return f"ERROR:{exc}"


class AIModelIntegrityGuardModule(BaseModule):
    CODE = "AMIG"
    NAME = "AI Model Integrity Guard"
    name = "AI Model Integrity Guard"
    description = ("Cryptographically attests local LLM weights (Ollama blobs) "
                   "against a pinned baseline; flags tampering/poisoning before load.")
    category = "AI Defense"
    version = "1.0.0"

    _INTERVAL = 30 * 60.0     # re-attest every 30 min

    def __init__(self) -> None:
        super().__init__()
        self.state_lock = threading.Lock()
        self._baseline_path = _repo_root() / "shared_logs" / "model_baselines.json"
        self._baseline: dict[str, str] = {}
        self._verified = 0
        self._mismatches = 0

    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    # ── discovery ────────────────────────────────────────────────────────────
    @staticmethod
    def _models_root() -> Path | None:
        for env in ("ANGERONA_OLLAMA_MODELS", "OLLAMA_MODELS"):
            v = os.environ.get(env)
            if v and Path(v).exists():
                return Path(v)
        home = Path(os.environ.get("USERPROFILE") or Path.home())
        cand = home / ".ollama" / "models"
        return cand if cand.exists() else None

    def _discover_blobs(self) -> dict[str, str]:
        """Return {blob_relpath: absolute_path} for every model blob found."""
        root = self._models_root()
        out: dict[str, str] = {}
        if not root:
            return out
        blobs = root / "blobs"
        search = blobs if blobs.exists() else root
        for p in search.rglob("sha256-*"):
            if p.is_file():
                out[p.name] = str(p)
        return out

    # ── baseline persistence ─────────────────────────────────────────────────
    def _load_baseline(self) -> None:
        try:
            if self._baseline_path.exists():
                self._baseline = json.loads(self._baseline_path.read_text("utf-8"))
        except Exception as exc:
            self.last_error = str(exc)
            self._baseline = {}

    def _save_baseline(self) -> None:
        try:
            self._baseline_path.parent.mkdir(parents=True, exist_ok=True)
            with self.state_lock:
                self._baseline_path.write_text(json.dumps(self._baseline, indent=2), "utf-8")
        except Exception as exc:
            self.last_error = str(exc)

    def rebaseline(self) -> int:
        """Re-pin the current on-disk blobs as the new known-good baseline.
        Call after an intentional model update. Returns number of blobs pinned."""
        blobs = self._discover_blobs()
        self._baseline = {name: _hash_file(path) for name, path in blobs.items()}
        self._save_baseline()
        return len(self._baseline)

    # ── verification ─────────────────────────────────────────────────────────
    def _verify_pass(self) -> tuple[int, list[str]]:
        """Hash every discovered blob; return (checked, mismatched_names)."""
        blobs = self._discover_blobs()
        mismatches: list[str] = []
        checked = 0
        for name, path in blobs.items():
            if self.stopping:
                break
            current = _hash_file(path)
            checked += 1

            # 1) Content-address self-check: Ollama names a blob sha256-<hex>.
            expected_self = name.split("sha256-", 1)[-1].lower() if "sha256-" in name else ""
            if expected_self and current and not current.startswith("ERROR") \
                    and current != "FILE_NOT_FOUND" and current.lower() != expected_self:
                mismatches.append(f"{name} (content≠self-address)")
                continue

            # 2) Baseline comparison (TOFU).
            base = self._baseline.get(name)
            if base is None:
                self._baseline[name] = current     # pin newly-seen blob
            elif base != current:
                mismatches.append(f"{name} (content≠baseline)")
        return checked, mismatches

    # ── lifecycle ────────────────────────────────────────────────────────────
    def run(self) -> None:
        self._load_baseline()
        first = not self._baseline
        if self._models_root() is None:
            self.set_health(60, "no Ollama model directory found — nothing to attest")
            self.emit("AMIG: no local model directory found; attestation idle. "
                      "Set ANGERONA_OLLAMA_MODELS if models live elsewhere.",
                      Severity.LOW, idle=True)
            while not self.stopping:
                self.sleep(self._INTERVAL)
            return

        if first:
            n = self.rebaseline()
            self.emit(f"AMIG: pinned baseline for {n} local model blob(s) (trust-on-first-use).",
                      Severity.INFO, pinned=n)

        self.emit("AMIG online — cryptographic model attestation active.", Severity.INFO)
        while not self.stopping:
            try:
                checked, mismatches = self._verify_pass()
                if mismatches:
                    self._mismatches += len(mismatches)
                    self.set_health(0, f"{len(mismatches)} model blob(s) failed attestation")
                    self.emit(
                        f"⚠ MODEL INTEGRITY FAILURE — {len(mismatches)} blob(s) do not match "
                        f"their known-good hash (possible poisoning/tampering): "
                        f"{', '.join(mismatches[:5])}. Do NOT trust affected model(s) until reviewed.",
                        Severity.CRITICAL, mismatches=mismatches[:20], checked=checked,
                        mitre="T1565.001 (Stored Data Manipulation)")
                else:
                    self._verified += checked
                    self._save_baseline()   # persist any newly-pinned blobs
                    self.set_health(100, f"{checked} model blob(s) attested clean")
            except Exception as exc:
                self.last_error = str(exc)
                self.set_health(50, f"attestation error: {exc}")
            self.sleep(self._INTERVAL)

    def self_test(self) -> tuple[bool, str]:
        """Offline: prove the hasher detects a single-byte change, and report
        whether any local models were discovered."""
        import tempfile
        ok = True
        detail_bits = []
        try:
            with tempfile.NamedTemporaryFile(delete=False) as tf:
                tf.write(b"angerona-model-attestation-selftest")
                tmp = tf.name
            h1 = _hash_file(tmp)
            with open(tmp, "ab") as f:
                f.write(b"X")            # tamper by one byte
            h2 = _hash_file(tmp)
            os.unlink(tmp)
            ok = (len(h1) == 64 and h1 != h2)
            detail_bits.append("chunked SHA-256 tamper-detect verified" if ok
                               else f"hash mismatch-detect FAILED (h1={h1[:12]} h2={h2[:12]})")
        except Exception as exc:
            ok = False
            detail_bits.append(f"hash self-test error: {exc}")

        root = self._models_root()
        detail_bits.append(f"model dir: {root}" if root else "no local model dir (attestation idle)")
        return ok, "; ".join(detail_bits)


def register() -> AIModelIntegrityGuardModule:
    return AIModelIntegrityGuardModule()
