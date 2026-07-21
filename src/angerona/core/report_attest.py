"""report_attest.py — HMAC attestation for self-hardening INPUT documents.

Angerona's self-hardening loop (``modules/posture_hardening.py``) learns from
After-Action Report JSON files on disk (``redteam_aar.json`` / ``shark_aar.json``
/ the legacy ``after_action_report.json``). The Judgment Gate already guards the
*output* — a staged remediation script is SHA-256-stamped and re-verified by
re-running the drill before it's trusted. But the *input* AAR was read straight
off disk with no authenticity check, so an attacker with filesystem write access
could plant a ``verdict/caught`` record to fabricate a weakness, steer the local
model's script generation, or (with ``ANGERONA_AUTO_REMEDIATE=1``) trigger real
host changes.

This module closes that gap the same way the EventBus closes the ledger-tamper
gap (``core/eventbus.BusAuthority``): every AAR that Angerona writes is stamped
with an HMAC-SHA256 over its canonical contents, using the **same per-install
secret** (``<data_dir>/bus.key``). The ingest side verifies that stamp before
trusting a report.

Threat model (identical framing to BusAuthority):
  • CLOSES — post-write tampering of a signed AAR, and forged/unsigned AARs
    dropped by an external process (they verify as ``bad`` / ``unsigned`` and
    are refused-or-flagged).
  • does NOT close — a compromised in-process Angerona module that has already
    loaded the key can forge a valid stamp. That is the in-process trust
    boundary handled by the supervisor / process-isolation layers, not here.

Policy (read side):
  • ``ok``       → verified, trust it.
  • ``bad``      → signature present but WRONG → active tampering. Always refused
                   and surfaced as a HIGH alert, regardless of mode.
  • ``unsigned`` / ``no_key`` → cannot prove authenticity. Default (lenient) is
    ingest-with-a-loud-warning so legacy/first-run reports keep working; set
    ``ANGERONA_REQUIRE_SIGNED_AAR=1`` for strict mode (refuse + alert).

Deliberately dependency-light and import-guarded so it's testable anywhere.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Optional, Tuple

# The signature field embedded in the AAR JSON. Chosen to be obviously
# Angerona-owned and unlikely to collide with a real report key.
SIG_FIELD = "_angerona_hmac"

_KEY_BYTES = 32


def _key_path() -> Path:
    """Same key the EventBus signs with — one per-install secret, not two."""
    from angerona.core.data_paths import data_dir
    return data_dir() / "bus.key"


def _load_key() -> Optional[bytes]:
    """Return the 32-byte install key, or None if it is absent/malformed.

    Absent key is treated as 'cannot verify' (not an error): a first run before
    the bus has generated its key still works in lenient mode. A malformed key is
    also treated as unverifiable rather than raising, so a corrupt key never
    takes the self-hardening loop down — the read-side policy decides what to do.
    """
    try:
        encoded = _key_path().read_text(encoding="ascii").strip()
        key = bytes.fromhex(encoded)
    except Exception:
        return None
    return key if len(key) == _KEY_BYTES else None


def _canonical(doc: dict) -> bytes:
    """Canonical bytes of the document EXCLUDING the signature field.

    Order-independent (sort_keys) so re-serialising a json.load'd dict reproduces
    exactly what was signed. Mirrors BusAuthority.sign's canonicalisation."""
    body = {k: v for k, v in doc.items() if k != SIG_FIELD}
    return json.dumps(body, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str).encode("utf-8")


def sign_doc(doc: dict, key: Optional[bytes] = None) -> Optional[str]:
    """Hex HMAC-SHA256 over the document's canonical body, or None with no key."""
    k = key if key is not None else _load_key()
    if not k:
        return None
    return hmac.new(k, _canonical(doc), hashlib.sha256).hexdigest()


def attest(doc: dict) -> dict:
    """Return a copy of ``doc`` with the signature embedded.

    Best-effort: if the key is unavailable the document is returned unchanged
    (unsigned) rather than raising — writing an AAR must never fail just because
    signing isn't possible. The read side flags unsigned reports."""
    sig = sign_doc(doc)
    if not sig:
        return dict(doc)
    out = dict(doc)
    out[SIG_FIELD] = sig
    return out


def verify(doc: dict) -> str:
    """Classify a loaded AAR document's authenticity.

    Returns one of: ``"ok"``, ``"bad"``, ``"unsigned"``, ``"no_key"``.
    """
    sig = doc.get(SIG_FIELD)
    if not sig:
        return "unsigned"
    key = _load_key()
    if not key:
        return "no_key"
    expected = hmac.new(key, _canonical(doc), hashlib.sha256).hexdigest()
    return "ok" if hmac.compare_digest(str(sig), expected) else "bad"


def strict_mode() -> bool:
    """True when unsigned/unverifiable AARs must be refused (not just flagged)."""
    return os.environ.get("ANGERONA_REQUIRE_SIGNED_AAR", "").strip().lower() in (
        "1", "true", "yes", "on")


def write_signed_json(path, doc: dict, *, indent: int = 2) -> None:
    """Attest ``doc`` and write it to ``path`` as JSON (best-effort signing)."""
    Path(path).write_text(json.dumps(attest(doc), indent=indent), encoding="utf-8")


def classify_for_ingest(doc: dict) -> Tuple[bool, str, str]:
    """Read-side decision helper. Returns ``(trust, severity, reason)``.

    ``trust`` — whether the caller should ingest the report.
    ``severity`` — "" (ok), "MEDIUM" (unverifiable, lenient), or "HIGH"
                   (tampered, or unverifiable under strict mode).
    ``reason`` — human string for the alert / log (empty when ok).
    """
    status = verify(doc)
    if status == "ok":
        return True, "", ""
    if status == "bad":
        return (False, "HIGH",
                "AAR HMAC signature is INVALID — the report was altered after it "
                "was written (possible self-hardening input poisoning). Refusing "
                "to ingest it.")
    # unsigned / no_key
    if strict_mode():
        return (False, "HIGH",
                f"AAR is not authenticated ({status}) and strict mode "
                "(ANGERONA_REQUIRE_SIGNED_AAR) is on — refusing to ingest.")
    return (True, "MEDIUM",
            f"AAR is not authenticated ({status}) — ingesting in lenient mode. "
            "Set ANGERONA_REQUIRE_SIGNED_AAR=1 to require signed reports.")


def self_test() -> "tuple[bool, str]":
    """Prove sign/verify round-trips, detects tampering, and survives no-key."""
    try:
        test_key = bytes(range(32))
        doc = {"run_id": "r1", "verdicts": [{"technique": "T1055", "caught": False}],
               "response_success_rate": 1.0 / 3.0}
        sig = sign_doc(doc, key=test_key)
        assert sig and len(sig) == 64, "signature should be 64 hex chars"

        signed = dict(doc); signed[SIG_FIELD] = sig
        # Re-serialise + reload (what really happens on disk) must still verify.
        reloaded = json.loads(json.dumps(signed, indent=2))
        # verify() reads the install key; emulate by recomputing with test_key.
        body = json.dumps({k: v for k, v in reloaded.items() if k != SIG_FIELD},
                          sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, default=str).encode("utf-8")
        expected = hmac.new(test_key, body, hashlib.sha256).hexdigest()
        assert hmac.compare_digest(reloaded[SIG_FIELD], expected), "round-trip verify"

        # Tamper: flip a caught flag → signature must no longer match.
        tampered = json.loads(json.dumps(signed))
        tampered["verdicts"][0]["caught"] = True
        body2 = json.dumps({k: v for k, v in tampered.items() if k != SIG_FIELD},
                           sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False, default=str).encode("utf-8")
        assert not hmac.compare_digest(
            tampered[SIG_FIELD], hmac.new(test_key, body2, hashlib.sha256).hexdigest()), \
            "tampered doc must fail verification"

        # Unsigned classification (no field) — lenient default trusts+flags.
        os.environ.pop("ANGERONA_REQUIRE_SIGNED_AAR", None)
        assert verify({"run_id": "x"}) == "unsigned"
        return True, ("OK — sign/verify round-trips through JSON, a one-flag tamper "
                      "breaks the HMAC, and unsigned reports are classified.")
    except AssertionError as exc:
        return False, f"FAIL — {exc}"
    except Exception as exc:  # pragma: no cover
        return False, f"ERROR — {type(exc).__name__}: {exc}"


if __name__ == "__main__":
    ok, detail = self_test()
    print(f"[report_attest] self_test: {'PASS' if ok else 'FAIL'} — {detail}")
    raise SystemExit(0 if ok else 1)
