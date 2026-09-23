# Ollama service startup and progress

Date: 2026-09-23. Scope: `src/angerona/core/ollama_lifecycle.py` and
`core/ollama_windows_token.py`, with dedicated startup/token tests. Application, module, self-test and GUI wiring
are maintained by the coordinating agent.

## Result

Added `ensure_ollama_service()`, `request_ollama_start()` and
`startup_snapshot()`. Explicit startup requests coalesce in the process; a
single launch lock serializes daemon discovery and start. Cached snapshots
perform no DNS, filesystem, socket or process inspection and are suitable for
GUI refreshes. The worker exits after the operation instead of polling during
idle. Startup records have a 16-endpoint bound.

`OllamaStartupStatus` distinguishes daemon readiness from model readiness.
Progress records completed checks: 10% address validation, 25% listener
inspection, 45% installation trust, 60% process launch, 80% listener ownership,
100% validated local model inventory. An already running service skips the
installation/launch stages. No model is pulled, loaded, warmed or approved by
this helper. Cancellation, invalid inventory and expired deadlines cannot
produce a successful 100% result. UI callback errors cannot erase the result.

## Defensive boundaries

- Only explicit localhost, IPv4 loopback or IPv6 loopback HTTP endpoints are
  eligible for automatic startup. No executable is discovered through PATH.
- Existing listeners must pass process/image attestation before inventory is
  requested. Occupied wildcard/unknown listeners do not authorize a launch or
  an API request.
- Windows starts only a recognized, vendor-signed installation with a fixed
  `serve` argument. The executable is held without write/delete sharing and
  its parent directories remain pinned during verification and launch.
- POSIX launch preserves the existing known-installation/root-owned image
  boundary and additionally rejects writable/non-root-owned parent chains.
  Links/reparse paths are not accepted for launch. Elevated/root processes
  can check an existing daemon but cannot start a model parser with inherited
  administrative privilege.
- The child receives a sanitized environment, fixed loopback binding,
  `OLLAMA_NO_CLOUD=1`, one loaded model and one parallel inference slot. An
  explicit absolute `OLLAMA_MODELS` directory is retained. Provider secrets,
  proxies, loading hooks and arbitrary Ollama overrides are not forwarded.
  Chill uses an immediate-unload default; service startup itself loads nothing.
- On macOS/Linux, denial of a system-wide socket table can fall back to a
  bounded scan of known, same-user Ollama processes. Their kernel-reported
  LISTEN sockets, executable and creation time are checked. Process names,
  successful HTTP responses and launched PIDs alone are insufficient. Access
  denial on a candidate or unknown ownership remains an availability failure.

The startup deadline is checked between bounded operations and after the
inventory request. An in-flight OS query or existing platform signature
verification cannot be interrupted by a Python event; the existing Windows
signature subprocess retains its own 15-second timeout. Cancellation does not
terminate an established shared daemon. There is no elevation attempt and no
change to Ollama's OS login-startup registration.

## Protected Windows launch

An elevated signed application cannot safely use ordinary process creation for
an AI parser. The final path obtains only the current user's linked limited
token, verifies the same user and interactive session, medium integrity, primary
token type and absence of UIAccess, then creates the fixed Ollama command
suspended. Child token and image identity are checked before resumption. Failed
checks terminate only the process handle created by this operation. Cancellation
and deadlines are checked before creation and resumption. No alternate account,
credential prompt, shell command or elevated fallback is available.

Protect startup sanitizes the parent environment. To preserve a user's custom
model drive, the helper reads only a validated absolute `OLLAMA_MODELS` setting
from the linked user's environment block; it never forwards the entire block.
The normal-user path is unchanged and POSIX root startup remains refused.

The first combined token/startup/discovery/transport gate passed **116 tests**.
The current-token identity adapter also passed a read-only Windows probe.
Actual elevated-to-medium child creation has **not** been accepted natively;
the current evidence is inert boundary and token-policy coverage. Final combined
gate counts are recorded in [QA round 3](bugs-round3.md).

Primary API contracts:
[linked token](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_linked_token),
[CreateProcessWithTokenW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw).

## Bugs found by real cold-start validation

1. A 200 ms socket probe could time out on an unused Windows port because
   refusal is delayed. After a successful OS listener enumeration, startup
   now uses that table for availability and retains mandatory later process
   attestation to handle bind races.
2. CPython 3.12 on this Windows host reports different `st_ctime_ns` meanings
   from named `stat()` and sealed-handle `fstat()` for rewritten files. An
   initial cross-API comparison wrongly rejected the genuine signed Ollama
   executable. Each API now retains its own complete baseline, while shared
   device/inode/size/mtime bind the two views. The no-write/delete seal remains
   in force. The behavior reproduced with 99 of 100 rewritten inert fixtures.

## Validation

- 76 focused tests passed across startup, registered-install discovery,
  process attestation and transport; Ruff passed for the changed Python files.
- Tests use inert executable fixtures and mocked launch/network APIs. Coverage
  includes concurrent requests, bounded cache/deadline, shutdown cancellation,
  invalid hosts and inventories, untrusted listeners, wildcard occupation,
  sanitized environment, root refusal, actual Windows file seal behavior,
  and POSIX listener ownership fallback.
- Coordinating-agent native Windows acceptance: cold start advanced
  10 → 25 → 45 → 60 → 80 → 100 in **16.44 seconds**, attested
  `D:/Ollama/ollama.exe` (PID 2836), and reported **zero loaded models** through
  `/api/ps`. Checking the already-running service also passed without launch.
- No native macOS/Linux acceptance was available. The POSIX ownership path
  has fixture coverage; it retains the documented installation/permission
  requirements instead of claiming universal model-service availability.

## Primary references

[Ollama's official FAQ](https://docs.ollama.com/faq) documents loopback binding,
the model storage override, cloud-disable variable, keep-alive controls and
parallel/model limits used here.

[psutil's official API reference](https://psutil.io/api/#psutil.net_connections)
documents the non-root macOS limitation of the system-wide connection table
and the per-process connection interface. The fallback still requires an
actual owned listening socket before the existing image attestation.
