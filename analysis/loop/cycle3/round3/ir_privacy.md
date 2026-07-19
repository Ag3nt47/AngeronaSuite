# Cycle 3 / Round 3 — Incident-bundle privacy remediation

Date: 2026-07-19

## C3-R3-IR-01 — One-click triage export could disclose excessive host data

Status: **FIXED**

Changed `src/angerona/core/ir_bundle.py` so incident/support bundles now:

- fail closed unless the caller records explicit operator consent;
- state that sanitized telemetry remains sensitive and must be reviewed before sharing;
- never collect process command lines, executable paths, usernames, logged-on users, or the host name;
- pseudonymize raw network addresses with an ephemeral per-bundle HMAC while preserving address class and port;
- recursively redact credential fields, bearer/provider tokens, JWTs, private keys, DPAPI-shaped blobs, long high-entropy values, email addresses, known local identities, and filesystem paths;
- include only four exact allow-listed diagnostic artifacts, read as regular files without following symlinks and sanitized before archival;
- exclude `.env`, `secrets.dpapi`, databases, key files, arbitrary files, and operator-selected paths by construction;
- enforce fixed process, connection, event, incident, nesting, node, artifact, member, and total uncompressed archive limits;
- emit stable JSON ordering plus a privacy manifest containing the policy version, limits, redaction counts, skip reasons, member sizes, and SHA-256 hashes;
- create a unique archive without overwriting an existing bundle and remove partial output on failure.

Caller contract: the GUI must show the warning and obtain affirmative consent before calling `collect_triage_bundle(..., consent=True)`. Calling without that keyword raises `PermissionError` and creates no archive.

## Gates

- `python -m py_compile src/angerona/core/ir_bundle.py tests/test_ir_bundle_privacy.py`: **PASS**
- `PYTHONPATH=src python -m unittest -v tests.test_ir_bundle_privacy`: **PASS** — 9 tests, 1 OS-level symlink-creation test skipped because the Windows account lacks symlink privilege; the platform-independent symlink file-type rejection test passed.
- `ir_bundle.self_test()`: **PASS** — consent denial and a bounded five-member bundle verified.

The focused tests cover no-consent behavior, secret/DPAPI/identity/path/address redaction, arbitrary/protected-file exclusion, manifest hashes, archive bounds, oversized artifacts, real and simulated symlinks, recursive node budgets, and stable within-bundle pseudonyms.

| Finding ID | Status | Gate result |
|---|---|---|
| C3-R3-IR-01 | FIXED | compile PASS; self-test PASS; 9 focused tests PASS (1 platform skip, simulated equivalent PASS) |
