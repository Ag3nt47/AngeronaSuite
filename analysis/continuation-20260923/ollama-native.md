# Native elevated Ollama startup acceptance — 2026-09-23

## Reproduced failure and narrow compatibility candidate

The first two real Windows acceptance runs reproduced a startup failure in the
committed `b9c7c97` implementation. An elevated, high-integrity parent obtained
its own linked token, but Windows returned a **limited, medium-integrity
impersonation token** (token type 2). Its user and interactive session matched
the parent; elevation and UIAccess were both false. The implementation required
a primary token immediately, so it failed before creating any process.

The candidate validates the direct linked token's complete authority before
converting an impersonation token into a primary token. `DuplicateTokenEx`
requests only `TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY`, with a
non-inheritable handle and no privilege changes. The resulting token must pass
the original strict primary-token check. The suspended child still receives an
independent token and executable check before its initial thread can resume.
Conversion, cancellation and verification failures close owned handles and do
not start an elevated fallback.

Microsoft documents [conversion with DuplicateTokenEx](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex)
and the [primary-token requirement for CreateProcessWithTokenW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw).

Subsequent **native, non-elevated, token-only** checks establish an important
limit. Starting with this process's own medium primary token and requesting
only query/duplicate access:

- A same-user/session medium impersonation token at `SecurityIdentification`
  (level 1) fails conversion through the actual candidate with Windows error
  **1346**, `ERROR_BAD_IMPERSONATION_LEVEL`. Both owned handles were closed.
- The corresponding control at `SecurityImpersonation` (level 2) converts
  successfully through the same candidate. The resulting token remains the
  same user/session, non-elevated, medium integrity, primary type 1 and limited
  elevation type 3. All four handles from this control were closed.

Neither check created a process, launched Ollama, requested UAC or changed
privileges. Microsoft's [token-duplication requirements](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwduplicatetoken)
require sufficient source impersonation authority for primary conversion.
The earlier elevated diagnostic recorded token type but **not impersonation
level**. Consequently, the candidate is demonstrated to support sufficient-level
tokens, but is not yet demonstrated to solve this host's elevated startup.
It cannot convert an identification-only linked token.

The next elevated diagnostic should record the direct linked token's
impersonation level. If that level is insufficient, the design must change
explicitly; token conversion cannot manufacture missing authority. A medium
startup phase before app elevation is preferable to silently introducing other
process-token sources. No alternate token source or privilege-enabling fallback
has been implemented.

## Acceptance boundary

The consenting user's normal UAC prompt starts an exact, separately reviewed
PowerShell bootstrap. It verifies the Program Files namespace, creates an
administrator-owned directory with a protected ACL, and copies a hash-pinned
test bundle before running it. Elevated Python never imports mutable repository
or user-installed packages. The bundle contains an official signed CPython
3.12.10 embedded runtime, hash-locked pywin32/psutil components, and a fixed
product snapshot. The candidate run changes only the reviewed token helper.

The probe uses `127.0.0.1:21437`, refuses an occupied endpoint, launches only the
signed registered Ollama executable with `serve`, and requests inventory and
resident-model status only. It verifies same-user/session, medium integrity,
non-elevation and listener ownership. It terminates only its own returned
process handle and confirms the pre-existing daemon on port 11434 is unchanged.
No prompt, model download or model loading is part of acceptance.

Protected result files remain under the per-run acceptance directory. The
bootstrap removes its own temporary protected Python runtime after completion.
The shared QEMU runtime was copied into its separate protected namespace;
QEMU was never executed elevated.

## Validation status

- Baseline native reproduction: failed before process creation; existing
  Ollama daemon unchanged.
- Instrumented baseline reproduction: confirmed the linked token type; existing
  Ollama daemon unchanged.
- Final focused Ollama regression suite: **146 passed** (7.36 seconds), including
  55 token-policy/binding tests and two actual Windows token-only regressions in
  `tests/test_ollama_windows_token_native.py`. Process creation remains mocked;
  the two new tests use real duplicates of their own process token and prove
  identification-level refusal and sufficient-level identity preservation.
  They skip only unavailable Windows/dependencies; real API failures fail the
  tests. Each owned token is closed even if an assertion fails.
- Ruff passed for the changed helper and test file. Normal-user embedded
  runtime import smoke test passed.
- The reviewed candidate acceptance request returned Windows error **1223**
  (UAC consent cancelled). The bootstrap did not run and was not retried. Native
  acceptance therefore remains pending; unit checks do not establish elevated
  process creation success.

The cancelled combined bootstrap had SHA-256
`c663d0b175f205c05e91145ee3f58d8374949349f7d7242d1e493bc53f6d0920`;
neither its optional QEMU ROM copy nor its Ollama probe ran. The adopted QEMU
profile v3 disables the unused virtual-APIC ROM with `-global apic.vapic=off`
and retains the installed 109-file profile. The missing ROM is therefore no
longer a current dependency or a reason to request elevation.

A fresh **Ollama-only** bootstrap is prepared, with no QEMU changes, and has
SHA-256 `d85dc9bcb805f354ff6a20b76f7d50cf7f26776630fedadc0ec070100f383900`.
It has not been launched; the user's retry choice is pending. This prepared
artifact is now **stale against the documented source** and must be rebuilt and
reviewed before any future launch. Its older candidate token-helper snapshot
has SHA-256
`4cce9dc2089435e2e61fc50bc47f7e07e7069e4682340a3b0eb161ac6019c2aa`.
The current helper, including the explicit identification-only limitation in
its docstring/comment, has SHA-256
`afc1a472db906fb10c77bb81158e76e2564a44d15a17f164baae02d7d5c0c05b`.
This documentation change does not change candidate behavior. No pending
bootstrap or payload was altered while adding the native regression tests.
The prepared bootstrap initializes its trusted PowerShell module path using
only .NET before invoking any module cmdlet; it does not use `Join-Path` before
the module search path is constrained.

## Limits

This native acceptance targets Windows x64 and the current user's split UAC
token. It does not establish native macOS/Linux startup behavior, other-account
elevation support, or service-account support. Missing or unsuitable linked
tokens remain an explicit failure, with no elevated Ollama fallback.
